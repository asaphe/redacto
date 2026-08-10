#!/usr/bin/env bash
# Shared sink lists for redacto-log-sweep.sh — see README § How the plugin works.

redacto_sink_paths() {
  local paths=(
    "$HOME/.claude/projects"
    "$HOME/.claude/paste-cache"
    "$HOME/.claude/file-history"
    "$HOME/.claude/backups"
  )
  # RTK (github.com/rtk-ai/rtk) is optional; its tee mirror is only swept if present.
  [ -d "$HOME/Library/Application Support/rtk/tee" ] && paths+=("$HOME/Library/Application Support/rtk/tee")
  # Task-local notes and hook logs, which record verbatim command text.
  [ -d "$HOME/.claude/local" ] && paths+=("$HOME/.claude/local")
  # Session scratchpad — fetched values and raw command dumps land here as ordinary files.
  local scratch="/tmp/claude-$(id -u)"
  [ -d "$scratch" ] && paths+=("$scratch")
  local f
  for f in "$HOME"/.claude/history.jsonl "$HOME"/.claude/history.jsonl.*; do
    [ -e "$f" ] && paths+=("$f")
  done
  printf '%s\n' "${paths[@]}"
}

# Globs for redacto --exclude. Matched against the full path, so each needs a leading */.
redacto_sink_excludes() {
  local globs=(
    '*/.git/*'
    '*/target/*'
    '*/node_modules/*'
    '*/.venv/*'
    '*/site-packages/*'
    '*/__pycache__/*'
    '*/.ruff_cache/*'
  )
  # A .redacto-exempt file opts its subtree out — see README § Exempting a fixture directory.
  local root marker
  for root in "$HOME/.claude/local" "$HOME/.claude/projects" "$HOME/.claude/image-cache" "/tmp/claude-$(id -u)"; do
    [ -d "$root" ] || continue
    while IFS= read -r marker; do
      [ -n "$marker" ] && globs+=("$(dirname "$marker")/*")
    done < <(find "$root" -maxdepth 5 -name .redacto-exempt -type f 2>/dev/null)
  done
  printf '%s\n' "${globs[@]}"
}

# Roots holding .jsonl transcripts, which carry images inline as base64 no text redactor can see.
redacto_transcript_roots() {
  local paths=("$HOME/.claude/projects")
  local scratch="/tmp/claude-$(id -u)"
  [ -d "$scratch" ] && paths+=("$scratch")
  printf '%s\n' "${paths[@]}"
}

# Raster sinks — deletion only, since redacto cannot rewrite a PNG.
redacto_image_cache_paths() {
  printf '%s\n' "$HOME/.claude/image-cache"
}
