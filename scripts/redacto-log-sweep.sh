#!/usr/bin/env bash
# SessionStart hook: incremental redacto sweep over local Claude Code log sinks — see README § How the plugin works.

DIR="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source-path=SCRIPTDIR
source "$DIR/redacto-sinks.sh"

REDACTO="$HOME/.cargo/bin/redacto"
[ -x "$REDACTO" ] || REDACTO="$(command -v redacto || true)"
# Both halves gate on the binary — a plugin install alone must not start destroying data.
[ -x "$REDACTO" ] || exit 0

SINKS=()
while IFS= read -r p; do SINKS+=("$p"); done < <(redacto_sink_paths)
EXCLUDES=()
while IFS= read -r g; do EXCLUDES+=(--exclude "$g"); done < <(redacto_sink_excludes)
# No sinks is a clean outcome, not an error: calling the CLI with no paths would exit non-zero and read as a failed sweep.
[ ${#SINKS[@]} -eq 0 ] && exit 0

# Output and status captured separately: piping straight into grep discards the exit code, so a crash read as a clean sweep.
REDACTO_OUT=$("$REDACTO" --write --patterns secrets "${EXCLUDES[@]}" "${SINKS[@]}" 2>&1)
REDACTO_RC=$?
SUMMARY=$(printf '%s\n' "$REDACTO_OUT" | grep '^redacto:')
# Kept unblanked: a summary line is the proof the run reached the end, whatever it exited with.
RAW_SUMMARY="$SUMMARY"

TOTAL=$(echo "$SUMMARY" | grep -oE '[0-9]+ total redaction' | grep -oE '^[0-9]+')
FAILS=$(echo "$SUMMARY" | grep -oE '[0-9]+ validation failure' | grep -oE '^[0-9]+')
UNSAFE=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unsafe lines' | grep -oE '^[0-9]+')
# PEM counts too: the CLI treats an unresolved orphan as not-clean (main.rs report()), so dropping it here contradicts that.
PEM=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unresolved PEM markers' | grep -oE '^[0-9]+')
if [ "${TOTAL:-0}" -eq 0 ] && [ "${FAILS:-0}" -eq 0 ] && [ "${UNSAFE:-0}" -eq 0 ] && [ "${PEM:-0}" -eq 0 ]; then
  SUMMARY=""
fi

# exit 1 is how the CLI reports a completed-but-not-clean run, so non-zero alone does not mean failure.
if [ "$REDACTO_RC" -ne 0 ] && [ -n "$RAW_SUMMARY" ]; then
  SUMMARY="$RAW_SUMMARY"
elif [ "$REDACTO_RC" -ne 0 ]; then
  SUMMARY=$(printf 'redacto: sweep did NOT complete (exit %s) — sinks may be partially redacted.\n%s' \
    "$REDACTO_RC" "$(printf '%s\n' "$REDACTO_OUT" | head -5)")
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
  # Same trap as the binary above: main() has one exit path (return 0), so non-zero is a crash, and a traceback carries no prefix to survive the grep.
  if [ "$IMAGE_RC" -ne 0 ]; then
    IMAGE_SUMMARY=$(printf 'image-carrier-sweep: did NOT complete (exit %s) — image payloads may still be live.\n%s' \
      "$IMAGE_RC" "$(printf '%s\n' "$IMAGE_OUT" | tail -5)")
  fi
fi

REPORT=$(printf '%s\n%s' "$SUMMARY" "$IMAGE_SUMMARY" | grep -v '^$')
if [ -n "$REPORT" ]; then
  # json.dumps, not sed — hand-rolled escaping leaves raw control characters, illegal in a JSON string.
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$REPORT" | python3 -c 'import json,sys; print(json.dumps({"systemMessage": sys.stdin.read()}))'
  else
    # Every control character except LF (012), which awk still needs to split on: tab and CR left raw make the JSON invalid.
    ESCAPED=$(printf '%s' "$REPORT" | tr -d '\000-\011\013-\037' \
      | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s%s", sep, $0; sep="\\n"}')
    printf '{"systemMessage": "%s"}\n' "$ESCAPED"
  fi
fi

exit 0
