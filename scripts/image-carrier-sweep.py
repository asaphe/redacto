#!/usr/bin/env python3
"""image-carrier-sweep.py — the non-text half of the local secret-leak sweep.

A secret pasted or screenshotted into a session lands in two places at once: the file in
`~/.claude/image-cache/`, and a byte-identical base64 copy inlined into the session
transcript. redacto sweeps the transcript corpus but is a text redactor, so it sees
neither — and it reports the corpus clean, which is worse than not scanning it. There is
no redaction for this carrier, only destruction: this sweep replaces every inlined image
payload past the age window with a 1x1 transparent PNG and deletes the cache files that
mirror it, in one pass, because removing either copy alone leaves the other live.

Blanket by age, deliberately. Without OCR nothing distinguishes an image holding a secret
from one holding a chart, and a sweep that silently misses one is the failure mode this
tool exists to remove. The cost is real — legitimate screenshots in old transcripts are
destroyed too — which is why the window is short rather than exempted.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone

# 1x1 transparent PNG — a valid image block keeps the record well-formed and the session resumable.
PLACEHOLDER = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
# Bumping this invalidates every cached stamp — a file skipped by a blinder detector must be re-read.
DETECTOR_VERSION = 1
MARKERS = ('"image/', '"image\\/')
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".avif", ".heic")
TEMP_PREFIX = ".image-sweep-"
ORPHAN_AGE_SECS = 3600
DEFAULT_STATE = os.path.expanduser("~/.local/state/redacto/image-sweep.json")
DEFAULT_TRANSCRIPTS = [os.path.expanduser("~/.claude/projects")]
DEFAULT_IMAGE_DIRS = [os.path.expanduser("~/.claude/image-cache")]


def has_marker(line):
    return any(marker in line for marker in MARKERS)


def iter_payloads(node):
    """Yield (container, key) for every base64 image payload in a decoded record."""
    if isinstance(node, dict):
        media = node.get("media_type")
        if (
            node.get("type") == "base64"
            and isinstance(node.get("data"), str)
            and isinstance(media, str)
            and media.startswith("image/")
        ):
            yield node, "data"
        kind = node.get("type")
        if isinstance(node.get("base64"), str) and isinstance(kind, str) and kind.startswith("image/"):
            yield node, "base64"
        for value in node.values():
            for found in iter_payloads(value):
                yield found
    elif isinstance(node, list):
        for value in node:
            for found in iter_payloads(value):
                yield found


def sentinel_view(line):
    """The record with every image payload blanked — everything a rewrite must not change."""
    rec = json.loads(line)
    for container, key in iter_payloads(rec):
        container[key] = "<DATA>"
    return rec


def record_epoch(rec, fallback):
    """A naive stamp is read as UTC; reading it as local time ages records early east of UTC."""
    ts = rec.get("timestamp") if isinstance(rec, dict) else None
    if isinstance(ts, str):
        try:
            when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return fallback
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when.timestamp()
    return fallback


def line_payloads(line, cutoff, fallback):
    """Return (distinct payloads past the age cutoff, how many fields they occupy, young count).

    A tool-result screenshot carries the same bytes in two fields of one record, so the
    distinct set is what gets replaced and the field count is what gets reported.
    """
    try:
        rec = json.loads(line)
    except ValueError:
        return [], (0, 0), 0
    when = record_epoch(rec, fallback)
    due, fields, freed, young = [], 0, 0, 0
    for container, key in iter_payloads(rec):
        value = container[key]
        if value == PLACEHOLDER or len(value) <= len(PLACEHOLDER):
            continue
        if when > cutoff:
            young += 1
            continue
        fields += 1
        freed += len(value) - len(PLACEHOLDER)
        if value not in due:
            due.append(value)
    return due, (fields, freed), young


def strip_line(line, payloads):
    before = sentinel_view(line)
    stripped, replaced = line, 0
    for payload in payloads:
        # base64 contains "/", so a record that escapes solidus carries the payload escaped too.
        for candidate in ('"%s"' % payload, '"%s"' % payload.replace("/", "\\/")):
            occurrences = stripped.count(candidate)
            if occurrences:
                stripped = stripped.replace(candidate, '"%s"' % PLACEHOLDER)
                replaced += occurrences
                break
        else:
            raise ValueError("payload not found verbatim in record")
    if sentinel_view(stripped) != before:
        raise ValueError("record changed beyond its image payloads")
    return stripped, replaced


def fsync_dir(dirpath):
    """Durability only — the rename already succeeded, so a failure here is not a failed sweep."""
    try:
        dir_fd = os.open(dirpath or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def sweep_transcript(path, cutoff, live_cutoff, dry_run):
    """Returns (stripped, bytes, young, error) — young > 0 means recheck this file next run."""
    try:
        st = os.stat(path)
    except OSError:
        return 0, 0, 0, None
    if st.st_mtime > live_cutoff:
        return 0, 0, 1, None

    due_total, freed_total, young_total, lines_in = 0, 0, 0, 0
    try:
        with open(path, "r", encoding="utf-8", errors="strict", newline="") as fh:
            for line in fh:
                lines_in += 1
                if not has_marker(line):
                    continue
                _due, (fields, freed), young = line_payloads(line, cutoff, st.st_mtime)
                due_total += fields
                freed_total += freed
                young_total += young
    except (OSError, UnicodeDecodeError) as exc:
        return 0, 0, 0, "%s: unreadable (%s)" % (path, exc)

    if not due_total or dry_run:
        return due_total, freed_total, young_total, None

    lines_out, stripped, tmp = 0, 0, None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=TEMP_PREFIX)
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
            with open(path, "r", encoding="utf-8", newline="") as fh:
                for line in fh:
                    if has_marker(line):
                        due, _counts, _young = line_payloads(line, cutoff, st.st_mtime)
                        if due:
                            line, replaced = strip_line(line, due)
                            stripped += replaced
                    out.write(line)
                    lines_out += 1
            out.flush()
            os.fsync(out.fileno())
        if lines_out != lines_in:
            raise ValueError("line count changed: %d -> %d" % (lines_in, lines_out))
        if stripped != due_total:
            raise ValueError("stripped %d payload(s), expected %d" % (stripped, due_total))
        # An append since the read would be truncated away by the swap, silently.
        now_st = os.stat(path)
        if (now_st.st_mtime_ns, now_st.st_size) != (st.st_mtime_ns, st.st_size):
            raise ValueError("file changed during the rewrite")
        os.replace(tmp, path)
    except Exception as exc:  # a partial rewrite is worse than a missed sweep
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
        return 0, 0, young_total, "%s: rewrite aborted (%s)" % (path, exc)
    fsync_dir(os.path.dirname(path))
    return stripped, freed_total, young_total, None


def normalise_glob(glob):
    """Candidates are absolutised, so a relative or ~ glob would silently match nothing."""
    if glob.startswith("~"):
        return os.path.expanduser(glob)
    if not os.path.isabs(glob) and not glob.startswith("*"):
        return os.path.abspath(glob)
    return glob


def excluded(path, globs):
    """Full-path match; a trailing /* is a literal prefix so a [bracket] in a real
    directory name cannot silently reinterpret the exclusion as a character class."""
    for glob in globs:
        if glob.endswith("/*") and (path.startswith(glob[:-1]) or path == glob[:-2]):
            return True
        if fnmatch.fnmatch(path, glob):
            return True
    return False


def sweep_image_dir(root, cutoff, live_cutoff, dry_run, globs):
    """Delete cache images past the age window — only images, and only dirs this walk emptied."""
    deleted, freed, emptied = 0, 0, []
    if not os.path.isdir(root):
        return deleted, freed
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        removed_here = 0
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not name.lower().endswith(IMAGE_SUFFIXES) or excluded(path, globs):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_mtime > cutoff or st.st_mtime > live_cutoff:
                continue
            deleted += 1
            freed += st.st_size
            removed_here += 1
            if not dry_run:
                try:
                    os.unlink(path)
                except OSError:
                    deleted -= 1
                    freed -= st.st_size
                    removed_here -= 1
        if removed_here and dirpath != root:
            candidate = dirpath
            while candidate != root and candidate.startswith(root + os.sep):
                if candidate not in emptied:
                    emptied.append(candidate)
                candidate = os.path.dirname(candidate)
    if not dry_run:
        for dirpath in emptied:
            try:
                if not os.listdir(dirpath):
                    os.rmdir(dirpath)
            except OSError:
                pass
    return deleted, freed


def sweep_orphans(dirpath, now, globs):
    """Reap temp files a killed run left behind — each holds a partial copy of a transcript."""
    reaped = 0
    try:
        names = os.listdir(dirpath)
    except OSError:
        return reaped
    for name in names:
        if not name.startswith(TEMP_PREFIX):
            continue
        path = os.path.join(dirpath, name)
        if excluded(path, globs):
            continue
        try:
            if now - os.stat(path).st_mtime > ORPHAN_AGE_SECS:
                os.unlink(path)
                reaped += 1
        except OSError:
            pass
    return reaped


def transcript_files(targets, globs, reap=None):
    for target in targets:
        target = os.path.abspath(os.path.expanduser(target))
        if os.path.isfile(target) and not os.path.islink(target):
            if not excluded(target, globs):
                yield target
        elif os.path.isdir(target):
            for dirpath, _dirnames, filenames in os.walk(target):
                if reap is not None:
                    reap[0] += sweep_orphans(dirpath, reap[1], globs)
                for name in filenames:
                    if not name.endswith(".jsonl"):
                        continue
                    path = os.path.join(dirpath, name)
                    # Rewriting a symlink replaces it, breaking the link and sparing the payload.
                    if os.path.islink(path) or excluded(path, globs):
                        continue
                    yield path


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if (
            isinstance(state, dict)
            and isinstance(state.get("files"), dict)
            and state.get("detector") == DETECTOR_VERSION
        ):
            return state
    except (OSError, ValueError):
        pass
    return {"version": 1, "detector": DETECTOR_VERSION, "files": {}}


def save_state(path, state):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".state-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--transcript", action="append", default=[], metavar="PATH")
    ap.add_argument("--image-dir", action="append", default=[], metavar="PATH")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    ap.add_argument("--max-age-hours", type=float, default=24.0)
    ap.add_argument("--live-window-secs", type=float, default=300.0)
    ap.add_argument("--state-file", default=DEFAULT_STATE)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    for name, value in (("--max-age-hours", args.max_age_hours), ("--live-window-secs", args.live_window_secs)):
        if not math.isfinite(value) or value < 0:
            ap.error("%s must be a finite value >= 0" % name)

    transcripts = args.transcript or DEFAULT_TRANSCRIPTS
    image_dirs = args.image_dir or DEFAULT_IMAGE_DIRS
    globs = [normalise_glob(g) for g in args.exclude]
    now = time.time()
    cutoff = now - args.max_age_hours * 3600.0
    live_cutoff = now - args.live_window_secs

    state = load_state(args.state_file) if not args.dry_run else {"files": {}}
    known = state["files"]
    seen = set()
    stripped, inline_freed, touched, errors = 0, 0, 0, []
    reap = None if args.dry_run else [0, now]

    for path in transcript_files(transcripts, globs, reap):
        seen.add(path)
        try:
            st = os.stat(path)
        except OSError:
            continue
        stamp = [st.st_mtime_ns, st.st_size]
        if known.get(path) == stamp:
            continue
        count, freed, young, error = sweep_transcript(path, cutoff, live_cutoff, args.dry_run)
        if error:
            errors.append(error)
            continue
        if count:
            stripped += count
            inline_freed += freed
            touched += 1
            if args.verbose or args.dry_run:
                print("%s: %d payload(s), %.1f MB" % (path, count, freed / 1048576.0))
        # Stamping the pre-read stat means a file that grew mid-run re-reads instead of being trusted.
        if young == 0 and not args.dry_run:
            known[path] = stamp

    deleted, freed = 0, 0
    for root in image_dirs:
        root = os.path.abspath(os.path.expanduser(root))
        count, bytes_freed = sweep_image_dir(root, cutoff, live_cutoff, args.dry_run, globs)
        deleted += count
        freed += bytes_freed

    if not args.dry_run:
        for path in list(known):
            if path not in seen:
                del known[path]
        save_state(args.state_file, state)

    reaped = reap[0] if reap else 0
    if stripped or deleted or errors or reaped or args.dry_run:
        prefix = "image-carrier-sweep%s:" % (" [dry-run]" if args.dry_run else "")
        print(
            "%s %d payload(s) in %d transcript(s) (%.1f MB), %d cache file(s) (%.1f MB)%s"
            % (
                prefix,
                stripped,
                touched,
                inline_freed / 1048576.0,
                deleted,
                freed / 1048576.0,
                ", %d orphan temp file(s) reaped" % reaped if reaped else "",
            )
        )
        # Errors share the prefix so the hook's grep keeps them; on stderr they read as clean.
        for error in errors:
            print("%s ! %s" % (prefix, error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
