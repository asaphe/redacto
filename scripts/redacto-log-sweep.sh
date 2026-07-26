#!/usr/bin/env bash
# SessionStart hook: incremental redacto sweep over local Claude Code log sinks — see README § How the plugin works.

REDACTO="$HOME/.cargo/bin/redacto"
[ -x "$REDACTO" ] || REDACTO="$(command -v redacto || true)"
[ -x "$REDACTO" ] || exit 0

source "$(dirname "${BASH_SOURCE[0]}")/redacto-sinks.sh"
SINKS=()
while IFS= read -r p; do SINKS+=("$p"); done < <(redacto_sink_paths)

SUMMARY=$("$REDACTO" --write --patterns secrets "${SINKS[@]}" 2>&1 | grep '^redacto:')

TOTAL=$(echo "$SUMMARY" | grep -oE '[0-9]+ total redaction' | grep -oE '^[0-9]+')
FAILS=$(echo "$SUMMARY" | grep -oE '[0-9]+ validation failure' | grep -oE '^[0-9]+')
UNSAFE=$(echo "$SUMMARY" | grep -oE '[0-9]+ file\(s\) with unsafe lines' | grep -oE '^[0-9]+')

if [ "${TOTAL:-0}" -gt 0 ] || [ "${FAILS:-0}" -gt 0 ] || [ "${UNSAFE:-0}" -gt 0 ]; then
  ESCAPED=$(echo "$SUMMARY" | sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '{"systemMessage": "%s"}\n' "$ESCAPED"
fi

exit 0
