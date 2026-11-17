#!/usr/bin/env bash
# redacto sweep of local Claude Code log sinks: a session's own files from its Stop/SessionEnd hooks, every sink only with --all — see README § How the plugin works.

DIR="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source-path=SCRIPTDIR
source "$DIR/redacto-sinks.sh"
HELPER="$DIR/redacto-session.py"

usage() {
  printf '%s\n' "usage: redacto-log-sweep.sh --all" \
    "  --all  sweep every sink (manual or scheduled; nothing runs this by default)" \
    "  The plugin's Stop and SessionEnd hooks call it with their JSON payload on stdin." >&2
}

MODE=hook
case "${1:-}" in
  "") ;;
  --all) MODE=all ;;
  --session-end-worker) MODE=worker ;;
  -h | --help) usage; exit 0 ;;
  *) usage; exit 64 ;;
esac

# REDACTO_BIN exists so tests/probe-log-sweep.py can substitute a stub; nothing in normal use sets it.
REDACTO="${REDACTO_BIN:-$HOME/.cargo/bin/redacto}"
[ -x "$REDACTO" ] || REDACTO="$(command -v redacto || true)"
if [ ! -x "$REDACTO" ]; then
  # A hook stays inert, since a plugin install alone must not start destroying data; a manual run asked for a sweep and is told.
  [ "$MODE" = all ] && { echo "redacto: the redacto binary was not found — nothing was swept." >&2; exit 127; }
  exit 0
fi

STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/redacto"
# Under $HOME, not XDG_STATE_HOME: launchd and a login shell can disagree on XDG, and two lock paths are no lock.
LOCK_FILE="$HOME/.local/state/redacto/sweep.lock"
EX_HELD=75

# Digits only, capped; anything else falls back, so a stray env value cannot break sleep or the CLI's argument parsing.
bounded_int() {
  case "$1" in
    '' | *[!0-9]*) printf '%s\n' "$2" ;;
    # The length check first: a long digit string overflows bash arithmetic and wraps negative before any comparison.
    *) if [ ${#1} -gt 6 ] || [ "$((10#$1))" -gt "$3" ]; then printf '%s\n' "$3"; else printf '%s\n' "$((10#$1))"; fi ;;
  esac
}

python_ok() {
  command -v python3 >/dev/null 2>&1 && python3 -c 'import fcntl, json' >/dev/null 2>&1
}

# 0 = held until this shell and its children exit (kernel flock, so a SIGKILL releases it too); 75 = busy, holder on stderr.
take_lock() {
  mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || return 1
  exec 9>>"$LOCK_FILE" || return 1
  python3 "$HELPER" lock --fd 9 --path "$LOCK_FILE" --wait "$1" --holder "$2"
}

lower_priority() {
  renice -n 19 -p $$ >/dev/null 2>&1
  # macOS background QoS throttles I/O as well as CPU, which nice alone does not.
  if command -v taskpolicy >/dev/null 2>&1; then taskpolicy -b -p $$ >/dev/null 2>&1; fi
  return 0
}

# The text half. Reads SINKS, EXCLUDES, TEXT_ARGS; sets SUMMARY, CTRL_FAILED, TEXT_TROUBLE.
run_text_sweep() {
  SUMMARY=""
  [ ${#SINKS[@]} -gt 0 ] || return 0
  local work="$WORK/text"
  if ! mkdir "$work"; then
    # Skipping silently would be the same failure-reads-as-clean shape this script exists to avoid.
    SUMMARY="redacto: could not create a temp dir — text sweep skipped, logs NOT redacted."
    TEXT_TROUBLE=1
    return 0
  fi
  local err_file="$work/stderr"
  # Same-invocation known-positive control, built by concatenation so no sweep ever rewrites a literal key in this file.
  local ctrl="$work/known-positive.txt"
  local ctrl_tail="abcdefgh01234567abcdefgh01234567abcdefgh01234567"
  {
    printf '%s\n' "sk-""admin-$ctrl_tail"
    printf '%s\n' "sk-""svcacct-$ctrl_tail"
    printf '%s\n' "sk-""proj-$ctrl_tail"
  } >"$ctrl"
  local ctrl_expected=3
  # Backdated past --live-window-secs, or the fixture is skipped as still being written.
  touch -t 202001010000 "$ctrl"
  # Streams kept apart: root errors and config warnings go to stderr carrying the same `redacto:` prefix as the summary line.
  local out rc
  out=$("$REDACTO" --write --patterns secrets "${TEXT_ARGS[@]}" "${EXCLUDES[@]}" "${SINKS[@]}" "$ctrl" 2>"$err_file")
  rc=$?
  # Fail closed when unreadable; grep -c exits 1 on zero matches, so never `|| echo 0`.
  local ctrl_left
  ctrl_left=$(grep -cE 'sk-(admin|svcacct|proj)-[A-Za-z0-9_-]{20,}' "$ctrl" 2>/dev/null)
  case "$ctrl_left" in '' | *[!0-9]*) ctrl_left=$ctrl_expected ;; esac
  local ctrl_fired=$((ctrl_expected - ctrl_left))
  local err err_lines
  err=$(head -5 "$err_file")
  # grep -c, not wc -l, which does not count a last line that lacks its newline.
  err_lines=$(grep -c '' "$err_file")
  # The count goes with the excerpt, so five failed sinks out of twenty does not read as five out of five.
  [ "$((err_lines))" -gt 5 ] && err=$(printf '%s\n… and %s more line(s)' "$err" "$((err_lines - 5))")
  SUMMARY=$(printf '%s\n' "$out" | grep '^redacto:')

  # head -1 on each: two summary lines would make these multi-valued and turn the comparisons below into an error.
  local total fails unsafe pem
  total=$(echo "$SUMMARY" | grep -oE '[0-9]+ total redaction' | grep -oE '^[0-9]+' | head -1)
  fails=$(echo "$SUMMARY" | grep -oE '[0-9]+ validation failure' | grep -oE '^[0-9]+' | head -1)
  unsafe=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unsafe lines' | grep -oE '^[0-9]+' | head -1)
  # The control's own redactions are not findings; report only what the sinks held.
  case "$total" in
    '' | *[!0-9]*) ;;
    *)
      # The summary shown gets the adjusted count too, or it reports redactions that were only the control.
      SUMMARY=$(printf '%s\n' "$SUMMARY" | sed "s/${total} total redaction/$((total - ctrl_fired)) total redaction/")
      total=$((total - ctrl_fired))
      [ "$total" -gt 0 ] && TEXT_FOUND=1
      ;;
  esac
  # PEM counts too: the CLI treats an unresolved orphan as not-clean (main.rs report()), so dropping it here contradicts that.
  pem=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unresolved PEM markers' | grep -oE '^[0-9]+' | head -1)
  [ "$rc" -eq 0 ] || TEXT_TROUBLE=1

  # Only an all-zero summary with exit 0 stays silent; every other branch below reports.
  if [ "$ctrl_fired" -ne "$ctrl_expected" ]; then
    # Louder than any finding: the sweep cannot be said to have checked anything.
    CTRL_FAILED=1
    SUMMARY=$(printf 'redacto: CONTROL FAILED (%s/%s synthetic keys redacted) — the secret rules did not fire on a known-positive file, so this run proves nothing and the sinks must be treated as UNSWEPT. The redacto binary may predate the OpenAI-style key rules.\n%s' \
      "$ctrl_fired" "$ctrl_expected" "$SUMMARY")
    printf '%s\n' "$SUMMARY" >&2
  elif [ -z "$SUMMARY" ]; then
    TEXT_TROUBLE=1
    # Whichever stream carried it: a wrapper on PATH may report its failure on stdout rather than stderr.
    local detail="$err"
    [ -n "$detail" ] || detail=$(printf '%s\n' "$out" | grep -v '^$' | tail -5)
    if [ "$rc" -eq 0 ]; then
      SUMMARY=$(printf 'redacto: exited 0 without a summary line — this does not look like the redacto CLI, and nothing was verified as redacted.\n%s' "$detail")
    else
      SUMMARY=$(printf 'redacto: no summary line (exit %s) — the sweep did not reach the end and sinks may be partially redacted.\n%s' \
        "$rc" "$detail")
    fi
  elif [ "${total:-0}" -eq 0 ] && [ "${fails:-0}" -eq 0 ] && [ "${unsafe:-0}" -eq 0 ] && [ "${pem:-0}" -eq 0 ]; then
    if [ "$rc" -ne 0 ]; then
      # An all-zero summary with a non-zero exit means the trouble is one the summary line does not count: a root it could not scan.
      SUMMARY=$(printf 'redacto: finished but could not scan every sink (exit %s):\n%s' "$rc" "$err")
    else
      SUMMARY=""
    fi
  elif [ -n "$err" ]; then
    SUMMARY=$(printf '%s\n%s' "$SUMMARY" "$err")
  fi
}

# The image half. Reads IMAGE_ARGS; sets IMAGE_SUMMARY, IMAGE_TROUBLE.
run_image_sweep() {
  IMAGE_SUMMARY=""
  if ! command -v python3 >/dev/null 2>&1; then
    # Unlike a missing binary, which means the plugin was never opted into, this is half a sweep the user believes is running.
    IMAGE_SUMMARY="image-carrier-sweep: python3 not found — image payloads were NOT swept."
    IMAGE_TROUBLE=1
    return 0
  fi
  local out rc
  out=$(python3 "$DIR/image-carrier-sweep.py" "${IMAGE_ARGS[@]}" 2>&1)
  rc=$?
  IMAGE_SUMMARY=$(printf '%s\n' "$out" | grep '^image-carrier-sweep')
  # A per-file error exits 0 by design (one bad file must not sink the rest), so it is read from its `!` line instead.
  printf '%s\n' "$IMAGE_SUMMARY" | grep -q '^image-carrier-sweep[^:]*: ! ' && IMAGE_TROUBLE=1
  # Exit status alone, unlike the redacto path: this script prints its summary line only when it has something to say.
  if [ "$rc" -ne 0 ]; then
    IMAGE_TROUBLE=1
    # tail, not head as on the redacto path: a traceback's informative line is its last, not its first.
    IMAGE_SUMMARY=$(printf 'image-carrier-sweep: did NOT complete (exit %s) — image payloads may remain in transcripts.\n%s' \
      "$rc" "$(printf '%s\n' "$out" | tail -5)")
  fi
}

emit_json() {
  # json.dumps, not sed — hand-rolled escaping leaves raw control characters, illegal in a JSON string.
  local encoded=""
  if command -v python3 >/dev/null 2>&1; then
    # Gated on the encoder's status, not its presence: a python3 that resolves but fails would drop the whole report.
    encoded=$(printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps({"systemMessage": sys.stdin.read()}))' 2>/dev/null) || encoded=""
  fi
  if [ -n "$encoded" ]; then
    printf '%s\n' "$encoded"
  else
    # Range strips every control character except \012, which awk below turns into an escaped \n.
    local escaped
    escaped=$(printf '%s' "$1" | tr -d '\000-\011\013-\037' |
      sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s%s", sep, $0; sep="\\n"}')
    printf '{"systemMessage": "%s"}\n' "$escaped"
  fi
}

# perl first: it starts in milliseconds, and the hook must have forked before SessionEnd's 1.5 s budget runs out.
start_end_worker() {
  if command -v perl >/dev/null 2>&1; then
    REDACTO_HOOK_INPUT="$INPUT" perl -MPOSIX -e 'defined(my $p = fork) or exit 1; exit 0 if $p; POSIX::setsid(); open STDIN, "<", "/dev/null"; open STDOUT, ">", "/dev/null"; open STDERR, ">", "/dev/null"; exec @ARGV or POSIX::_exit(127);' \
      "${BASH:-bash}" "${BASH_SOURCE[0]}" --session-end-worker && return 0
  fi
  REDACTO_HOOK_INPUT="$INPUT" python3 "$HELPER" detach -- "${BASH:-bash}" "${BASH_SOURCE[0]}" --session-end-worker
}

# SessionEnd output is discarded by Claude Code, so the detached run's only witness is this file.
log_report() {
  mkdir -p "$STATE_ROOT" 2>/dev/null || return 0
  local log="$STATE_ROOT/sweep.log"
  # One rotation at 1 MB keeps the witness bounded without losing the run before it.
  if [ -f "$log" ] && [ "$(wc -c <"$log")" -gt 1048576 ]; then mv -f "$log" "$log.1"; fi
  printf '%s %s\n%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >>"$log"
}

# Every outcome leaves through here, so each mode reports where someone will read it.
finish() {
  local report
  report=$(printf '%s\n%s' "$SUMMARY" "$IMAGE_SUMMARY" | grep -v '^$')
  case "$MODE" in
    all)
      [ -n "$report" ] && printf '%s\n' "$report"
      # Non-zero for anything short of a complete sweep, so a scheduler's exit status means something.
      if [ -n "${CTRL_FAILED:-}" ] || [ -n "${TEXT_TROUBLE:-}" ] || [ -n "${IMAGE_TROUBLE:-}" ]; then exit 1; fi
      exit 0
      ;;
    worker)
      [ -n "$report" ] && log_report "session ${SID:-unknown} SessionEnd" "$report"
      ;;
    *)
      [ -n "$report" ] && emit_json "$report"
      ;;
  esac
  # Non-zero only when the control failed, so a no-op sweep cannot pass as a clean one.
  [ -z "${CTRL_FAILED:-}" ] || exit 1
  exit 0
}

SUMMARY=""
IMAGE_SUMMARY=""
SINKS=()
EXCLUDES=()
TEXT_ARGS=()
IMAGE_ARGS=()

if ! WORK=$(mktemp -d); then
  SUMMARY="redacto: could not create a temp dir — nothing was swept, logs NOT redacted."
  TEXT_TROUBLE=1
  finish
fi
trap 'rm -rf "$WORK"' EXIT

if [ "$MODE" = all ]; then
  if ! python_ok; then
    SUMMARY="redacto: python3 is not usable, so the sweep lock cannot be taken — the full sweep did NOT run."
    TEXT_TROUBLE=1
    finish
  fi
  take_lock "$(bounded_int "${REDACTO_LOCK_WAIT_SECS:-}" 60 3600)" "pid=$$ mode=all since=$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>"$WORK/holder"
  case $? in
    0) ;;
    "$EX_HELD")
      echo "redacto: another sweep holds $LOCK_FILE ($(head -1 "$WORK/holder")) — this full sweep did not run." >&2
      exit "$EX_HELD"
      ;;
    *)
      SUMMARY="redacto: could not take the sweep lock ($(head -1 "$WORK/holder")) — the full sweep did NOT run."
      TEXT_TROUBLE=1
      finish
      ;;
  esac
  lower_priority
  while IFS= read -r p; do SINKS+=("$p"); done < <(redacto_sink_paths)
  while IFS= read -r g; do EXCLUDES+=(--exclude "$g"); done < <(redacto_sink_excludes)
  run_text_sweep
  while IFS= read -r p; do IMAGE_ARGS+=(--transcript "$p"); done < <(redacto_transcript_roots)
  while IFS= read -r p; do IMAGE_ARGS+=(--image-dir "$p"); done < <(redacto_image_cache_paths)
  while IFS= read -r g; do IMAGE_ARGS+=(--exclude "$g"); done < <(redacto_sink_excludes)
  run_image_sweep
  finish
fi

if [ "$MODE" = worker ]; then
  INPUT="${REDACTO_HOOK_INPUT:-}"
else
  # A terminal on stdin is a person who ran it bare; reading would hang, and a guess would sweep the wrong scope.
  [ -t 0 ] && { usage; exit 64; }
  INPUT=$(head -c 1048577)
  END_RE='(^|[^\\])"hook_event_name"[[:space:]]*:[[:space:]]*"SessionEnd"'
  # SessionEnd gets 1.5 s and discards output, so it only starts the detached final pass, which validates the payload itself.
  if [[ $INPUT =~ $END_RE ]]; then
    start_end_worker ||
      log_report "SessionEnd" "redacto: could not start the detached SessionEnd sweep — this session's last writes were NOT swept."
    exit 0
  fi
fi

if ! python_ok; then
  SUMMARY="redacto: python3 not found or not usable — this session's logs and image payloads were NOT swept."
  finish
fi

# Sets EVENT, SID and the root lists from the payload; on failure, input never widens the scope and the reason is reported.
load_paths() {
  if ! python3 "$HELPER" paths <<<"$INPUT" >"$WORK/paths" 2>"$WORK/paths.err"; then
    SUMMARY="redacto: $(head -3 "$WORK/paths.err") — nothing was swept."
    finish
  fi
  EVENT=""
  SID=""
  TEXT_ROOTS=()
  REAP_DIRS=()
  DISCOVERY_ROOTS=()
  IMAGE_ARGS=()
  local rec kind value
  while IFS= read -r -d '' rec; do
    kind=${rec%%$'\t'*}
    value=${rec#*$'\t'}
    case "$kind" in
      EVENT) EVENT=$value ;;
      SID) SID=$value ;;
      T) TEXT_ROOTS+=("$value") ;;
      J) IMAGE_ARGS+=(--transcript "$value") ;;
      C) IMAGE_ARGS+=(--image-dir "$value") ;;
      R) DISCOVERY_ROOTS+=("$value") ;;
      O) REAP_DIRS+=("$value") ;;
    esac
  done <"$WORK/paths"
}

load_paths

if [ "$MODE" = hook ] && [ "$EVENT" = SessionEnd ]; then
  # Reached only if the fast-path match above missed an oddly spaced payload; the result is the same detached pass.
  start_end_worker ||
    log_report "session $SID SessionEnd" "redacto: could not start the detached SessionEnd sweep — this session's last writes were NOT swept."
  exit 0
fi

SSTATE="$STATE_ROOT/sessions/$SID"
mkdir -p "$SSTATE" 2>/dev/null
TOKEN="$$-$(date +%s)-$RANDOM"
printf '%s\n' "$TOKEN" >"$SSTATE/latest.$$" 2>/dev/null && mv -f "$SSTATE/latest.$$" "$SSTATE/latest" 2>/dev/null

if [ "$MODE" = worker ]; then
  SETTLE=5
  LOCK_WAIT=900
else
  SETTLE=$(bounded_int "${REDACTO_SETTLE_SECS:-}" 30 600)
  LOCK_WAIT=$(bounded_int "${REDACTO_LOCK_WAIT_SECS:-}" 120 3600)
fi
# Before the lock, not under it: a session still mid-conversation should not hold every other session's sweep.
sleep "$SETTLE"

if ! take_lock "$LOCK_WAIT" "pid=$$ mode=$MODE session=$SID since=$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>"$WORK/holder"; then
  # A Stop run that loses the wait is covered by the next Stop or the SessionEnd pass; only the last pass has nobody after it.
  if [ "$MODE" = worker ]; then
    SUMMARY="redacto: the sweep lock stayed busy ($(head -1 "$WORK/holder")) — this session's last writes were NOT swept."
    finish
  fi
  exit 0
fi
# A newer run of this session started while this one settled or waited, and it covers everything this one would.
[ "$(cat "$SSTATE/latest" 2>/dev/null)" = "$TOKEN" ] || exit 0
# Checked again under the lock: a path that passed before the wait could have been swapped for a symlink during it.
load_paths

lower_priority
touch "$SSTATE"
# Per-session state is a cache; a session idle a week re-scans once if it resumes.
find "$STATE_ROOT/sessions" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} + 2>/dev/null
# A killed rewrite leaves a full copy beside the transcript, named after it, which no other run would ever reap.
for d in "${REAP_DIRS[@]}"; do
  find "$d" -maxdepth 1 -type f -name "$SID.redacto-tmp-*" -mmin +60 -exec rm -f {} + 2>/dev/null
done

SINKS=("${TEXT_ROOTS[@]}")
# The placeholder keeps an empty root list from falling back to every default discovery root.
[ ${#DISCOVERY_ROOTS[@]} -gt 0 ] || DISCOVERY_ROOTS=("$WORK/none")
while IFS= read -r g; do EXCLUDES+=(--exclude "$g"); done < <(redacto_sink_excludes "${DISCOVERY_ROOTS[@]}")
TEXT_ARGS=(--state-dir "$SSTATE" --live-window-secs "$SETTLE")
run_text_sweep

if [ ${#IMAGE_ARGS[@]} -gt 0 ]; then
  # The text rewrite just refreshed mtimes, and the final pass has no later run to pick up what the image stage would skip as live.
  [ "$MODE" = worker ] && [ -n "${TEXT_FOUND:-}" ] && sleep $((SETTLE + 1))
  IMAGE_ARGS+=(--scoped --state-file "$SSTATE/image-sweep.json" --live-window-secs "$SETTLE")
  for g in "${EXCLUDES[@]}"; do IMAGE_ARGS+=("$g"); done
  run_image_sweep
fi
finish
