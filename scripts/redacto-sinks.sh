#!/usr/bin/env bash
# Shared sink list for redacto-log-sweep.sh — single source of truth for which paths get swept.

redacto_sink_paths() {
  local paths=(
    "$HOME/.claude/projects"
    "$HOME/.claude/paste-cache"
    "$HOME/.claude/file-history"
    "$HOME/.claude/backups"
  )
  # RTK (github.com/rtk-ai/rtk) is optional; its tee mirror is only swept if present.
  [ -d "$HOME/Library/Application Support/rtk/tee" ] && paths+=("$HOME/Library/Application Support/rtk/tee")
  local f
  for f in "$HOME"/.claude/history.jsonl "$HOME"/.claude/history.jsonl.*; do
    [ -e "$f" ] && paths+=("$f")
  done
  printf '%s\n' "${paths[@]}"
}
