#!/usr/bin/env bash
# SessionStart hook: incremental redacto sweep over local Claude Code log sinks — see README § How the plugin works.

DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$DIR/redacto-sinks.sh"

REDACTO="$HOME/.cargo/bin/redacto"
[ -x "$REDACTO" ] || REDACTO="$(command -v redacto || true)"
# Both halves gate on the binary — a plugin install alone must not start destroying data.
[ -x "$REDACTO" ] || exit 0

SINKS=()
while IFS= read -r p; do SINKS+=("$p"); done < <(redacto_sink_paths)
EXCLUDES=()
while IFS= read -r g; do EXCLUDES+=(--exclude "$g"); done < <(redacto_sink_excludes)

SUMMARY=$("$REDACTO" --write --patterns secrets "${EXCLUDES[@]}" "${SINKS[@]}" 2>&1 | grep '^redacto:')

TOTAL=$(echo "$SUMMARY" | grep -oE '[0-9]+ total redaction' | grep -oE '^[0-9]+')
FAILS=$(echo "$SUMMARY" | grep -oE '[0-9]+ validation failure' | grep -oE '^[0-9]+')
UNSAFE=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unsafe lines' | grep -oE '^[0-9]+')
if [ "${TOTAL:-0}" -eq 0 ] && [ "${FAILS:-0}" -eq 0 ] && [ "${UNSAFE:-0}" -eq 0 ]; then
  SUMMARY=""
fi

# Guarded because the report below needs it too, and a missing report reads as a clean sweep.
IMAGE_SUMMARY=""
if command -v python3 >/dev/null 2>&1; then
  IMAGE_ARGS=()
  while IFS= read -r p; do IMAGE_ARGS+=(--transcript "$p"); done < <(redacto_transcript_roots)
  while IFS= read -r p; do IMAGE_ARGS+=(--image-dir "$p"); done < <(redacto_image_cache_paths)
  while IFS= read -r g; do IMAGE_ARGS+=(--exclude "$g"); done < <(redacto_sink_excludes)
  IMAGE_SUMMARY=$(python3 "$DIR/image-carrier-sweep.py" "${IMAGE_ARGS[@]}" 2>&1 | grep '^image-carrier-sweep')
fi

REPORT=$(printf '%s\n%s' "$SUMMARY" "$IMAGE_SUMMARY" | grep -v '^$')
if [ -n "$REPORT" ]; then
  # json.dumps, not sed — hand-rolled escaping leaves raw control characters, illegal in a JSON string.
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$REPORT" | python3 -c 'import json,sys; print(json.dumps({"systemMessage": sys.stdin.read()}))'
  else
    ESCAPED=$(printf '%s' "$REPORT" | tr -d '\000-\010\013\014\016-\037' \
      | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s%s", sep, $0; sep="\\n"}')
    printf '{"systemMessage": "%s"}\n' "$ESCAPED"
  fi
fi

exit 0
