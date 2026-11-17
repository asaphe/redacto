#!/usr/bin/env bash
# Shared sink lists for redacto-log-sweep.sh — see README § How the plugin works.

redacto_sink_paths() {
  local paths=()
  local d
  # Guarded like every sink below: the CLI exits 1 on a missing root, which the hook then surfaces as an all-zero sweep.
  for d in "$HOME/.claude/projects" "$HOME/.claude/paste-cache" \
           "$HOME/.claude/file-history" "$HOME/.claude/backups"; do
    [ -d "$d" ] && paths+=("$d")
  done
  # RTK (github.com/rtk-ai/rtk) is optional; macOS keeps its tee mirror under Application Support, Linux under XDG_DATA_HOME.
  for d in "$HOME/Library/Application Support/rtk/tee" "${XDG_DATA_HOME:-$HOME/.local/share}/rtk/tee"; do
    [ -d "$d" ] && paths+=("$d")
  done
  # Task-local notes and hook logs, which record verbatim command text.
  [ -d "$HOME/.claude/local" ] && paths+=("$HOME/.claude/local")
  # Session scratchpad — fetched values and raw command dumps land here as ordinary files.
  local scratch
  scratch="/tmp/claude-$(id -u)"
  [ -d "$scratch" ] && paths+=("$scratch")
  local f
  for f in "$HOME"/.claude/history.jsonl "$HOME"/.claude/history.jsonl.*; do
    [ -e "$f" ] && paths+=("$f")
  done
  # Empty is a real outcome now that every root is guarded, and an empty array would expand to one blank argument.
  [ ${#paths[@]} -eq 0 ] && return 0
  printf '%s\n' "${paths[@]}"
}

# Globs for redacto --exclude, matched against the full path; arguments replace the default discovery roots.
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
  local roots=("$@")
  [ ${#roots[@]} -gt 0 ] || roots=("$HOME/.claude/local" "$HOME/.claude/projects" "$HOME/.claude/image-cache" "/tmp/claude-$(id -u)")
  # A .redacto-exempt file or a git work tree below a root opts its subtree out — see README § Exempting a fixture directory.
  local root found
  for root in "${roots[@]}"; do
    [ -d "$root" ] || continue
    while IFS= read -r found; do
      # One-character classes: a [ or * in a real directory name would otherwise change what the glob matches.
      [ -n "$found" ] && globs+=("$(dirname "$found" | sed 's/[][*?{}]/[&]/g')/*")
    done < <(
      find "$root" -maxdepth 8 -name .redacto-exempt -type f 2>/dev/null
      find "$root" -mindepth 2 -maxdepth 8 -name .git -prune 2>/dev/null
    )
  done
  printf '%s\n' "${globs[@]}"
}

# Roots holding .jsonl transcripts, which carry images inline as base64 no text redactor can see.
redacto_transcript_roots() {
  local paths=("$HOME/.claude/projects")
  local scratch
  scratch="/tmp/claude-$(id -u)"
  [ -d "$scratch" ] && paths+=("$scratch")
  printf '%s\n' "${paths[@]}"
}

# Raster sinks — deletion only, since redacto cannot rewrite a PNG.
redacto_image_cache_paths() {
  printf '%s\n' "$HOME/.claude/image-cache"
}
