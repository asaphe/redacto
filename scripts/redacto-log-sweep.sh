#!/usr/bin/env bash
# SessionStart hook: incremental redacto sweep over local Claude Code log sinks — see README § How the plugin works.

DIR="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source-path=SCRIPTDIR
source "$DIR/redacto-sinks.sh"

# REDACTO_BIN exists so tests/probe-log-sweep.py can substitute a stub; nothing in normal use sets it.
REDACTO="${REDACTO_BIN:-$HOME/.cargo/bin/redacto}"
[ -x "$REDACTO" ] || REDACTO="$(command -v redacto || true)"
# Both halves gate on the binary — a plugin install alone must not start destroying data.
[ -x "$REDACTO" ] || exit 0

SINKS=()
while IFS= read -r p; do SINKS+=("$p"); done < <(redacto_sink_paths)
EXCLUDES=()
while IFS= read -r g; do EXCLUDES+=(--exclude "$g"); done < <(redacto_sink_excludes)

SUMMARY=""
# Scoped to the text sweep, not the whole hook: the image sinks are a separate list and can exist on their own.
if [ ${#SINKS[@]} -gt 0 ]; then
  if ERR_FILE=$(mktemp); then
    trap 'rm -f "$ERR_FILE"' EXIT
    # Streams kept apart: root errors and config warnings go to stderr carrying the same `redacto:` prefix as the summary line.
    REDACTO_OUT=$("$REDACTO" --write --patterns secrets "${EXCLUDES[@]}" "${SINKS[@]}" 2>"$ERR_FILE")
    REDACTO_RC=$?
    REDACTO_ERR=$(head -5 "$ERR_FILE")
    # grep -c, not wc -l, which does not count a last line that lacks its newline.
    ERR_LINES=$(grep -c '' "$ERR_FILE")
    # The count goes with the excerpt, so five failed sinks out of twenty does not read as five out of five.
    [ "$((ERR_LINES))" -gt 5 ] && REDACTO_ERR=$(printf '%s\n… and %s more line(s)' "$REDACTO_ERR" "$((ERR_LINES - 5))")
    SUMMARY=$(printf '%s\n' "$REDACTO_OUT" | grep '^redacto:')

    # head -1 on each: two summary lines would make these multi-valued and turn the comparisons below into an error.
    TOTAL=$(echo "$SUMMARY" | grep -oE '[0-9]+ total redaction' | grep -oE '^[0-9]+' | head -1)
    FAILS=$(echo "$SUMMARY" | grep -oE '[0-9]+ validation failure' | grep -oE '^[0-9]+' | head -1)
    UNSAFE=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unsafe lines' | grep -oE '^[0-9]+' | head -1)
    # PEM counts too: the CLI treats an unresolved orphan as not-clean (main.rs report()), so dropping it here contradicts that.
    PEM=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unresolved PEM markers' | grep -oE '^[0-9]+' | head -1)

    # Four outcomes, only one of them silent — see README § How the plugin works.
    if [ -z "$SUMMARY" ]; then
      # Whichever stream carried it: a wrapper on PATH may report its failure on stdout rather than stderr.
      DETAIL="$REDACTO_ERR"
      [ -n "$DETAIL" ] || DETAIL=$(printf '%s\n' "$REDACTO_OUT" | grep -v '^$' | tail -5)
      if [ "$REDACTO_RC" -eq 0 ]; then
        SUMMARY=$(printf 'redacto: exited 0 without a summary line — this does not look like the redacto CLI, and nothing was verified as redacted.\n%s' "$DETAIL")
      else
        SUMMARY=$(printf 'redacto: no summary line (exit %s) — the sweep did not reach the end and sinks may be partially redacted.\n%s' \
          "$REDACTO_RC" "$DETAIL")
      fi
    elif [ "${TOTAL:-0}" -eq 0 ] && [ "${FAILS:-0}" -eq 0 ] && [ "${UNSAFE:-0}" -eq 0 ] && [ "${PEM:-0}" -eq 0 ]; then
      if [ "$REDACTO_RC" -ne 0 ]; then
        # An all-zero summary with a non-zero exit means the trouble is one the summary line does not count: a root it could not scan.
        SUMMARY=$(printf 'redacto: finished but could not scan every sink (exit %s):\n%s' "$REDACTO_RC" "$REDACTO_ERR")
      else
        SUMMARY=""
      fi
    elif [ -n "$REDACTO_ERR" ]; then
      SUMMARY=$(printf '%s\n%s' "$SUMMARY" "$REDACTO_ERR")
    fi
  else
    # Skipping silently would be the same failure-reads-as-clean shape this script exists to avoid.
    SUMMARY="redacto: could not create a temp file — text sweep skipped, logs NOT redacted."
  fi
fi

# Guarded because the report below needs it too, and a missing report reads as a clean sweep.
IMAGE_SUMMARY=""
if command -v python3 >/dev/null 2>&1; then
  IMAGE_ARGS=()
  while IFS= read -r p; do IMAGE_ARGS+=(--transcript "$p"); done < <(redacto_transcript_roots)
  while IFS= read -r p; do IMAGE_ARGS+=(--image-dir "$p"); done < <(redacto_image_cache_paths)
  while IFS= read -r g; do IMAGE_ARGS+=(--exclude "$g"); done < <(redacto_sink_excludes)
  IMAGE_OUT=$(python3 "$DIR/image-carrier-sweep.py" "${IMAGE_ARGS[@]}" 2>&1)
  IMAGE_RC=$?
  IMAGE_SUMMARY=$(printf '%s\n' "$IMAGE_OUT" | grep '^image-carrier-sweep')
  # Exit status alone, unlike the redacto path above: this script prints its summary line only when it has something to say.
  if [ "$IMAGE_RC" -ne 0 ]; then
    # tail, not head as on the redacto path: a traceback's informative line is its last, not its first.
    IMAGE_SUMMARY=$(printf 'image-carrier-sweep: did NOT complete (exit %s) — image payloads may remain in transcripts.\n%s' \
      "$IMAGE_RC" "$(printf '%s\n' "$IMAGE_OUT" | tail -5)")
  fi
else
  # Unlike a missing binary, which means the plugin was never opted into, this is half a sweep the user believes is running.
  IMAGE_SUMMARY="image-carrier-sweep: python3 not found — image payloads were NOT swept."
fi

REPORT=$(printf '%s\n%s' "$SUMMARY" "$IMAGE_SUMMARY" | grep -v '^$')
if [ -n "$REPORT" ]; then
  # json.dumps, not sed — hand-rolled escaping leaves raw control characters, illegal in a JSON string.
  ENCODED=""
  if command -v python3 >/dev/null 2>&1; then
    # Gated on the encoder's status, not its presence: a python3 that resolves but fails would drop the whole report.
    ENCODED=$(printf '%s' "$REPORT" | python3 -c 'import json,sys; print(json.dumps({"systemMessage": sys.stdin.read()}))' 2>/dev/null) || ENCODED=""
  fi
  if [ -n "$ENCODED" ]; then
    printf '%s\n' "$ENCODED"
  else
    # Range strips every control character except \012, which awk below turns into an escaped \n.
    ESCAPED=$(printf '%s' "$REPORT" | tr -d '\000-\011\013-\037' \
      | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s%s", sep, $0; sep="\\n"}')
    printf '{"systemMessage": "%s"}\n' "$ESCAPED"
  fi
fi

exit 0
