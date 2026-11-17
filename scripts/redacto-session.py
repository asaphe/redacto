#!/usr/bin/env python3
"""redacto-session.py — the parts of redacto-log-sweep.sh that shell is bad at.

  paths   read a Stop/SessionEnd hook payload on stdin and print this session's own sweep
          roots, NUL-terminated "<kind>\\t<path>" records (see README § How the plugin works)
  lock    take the sweep lock on an fd the calling shell already holds open
  detach  start a command in its own session, so it outlives the hook that started it
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import glob
import json
import os
import re
import stat
import sys
import time

SID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z_-]{7,127}")
EVENTS = ("Stop", "SessionEnd")
MAX_INPUT = 1 << 20
EX_INPUT = 2
EX_HELD = 75


def lstat_kind(path):
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return None
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


def owned(path):
    try:
        return os.lstat(path).st_uid == os.getuid()
    except OSError:
        return False


def directly_under(path, parent):
    """Containment by resolved parent, so a symlinked ancestor cannot lead outside the sink."""
    return os.path.realpath(os.path.dirname(path)) == os.path.realpath(parent)


def exempt_by_ancestor(path, boundary):
    """Mirrors redacto_sink_excludes: a marker at or below the sink root, or a .git strictly below it."""
    d = path if lstat_kind(path) == "dir" else os.path.dirname(path)
    boundary = boundary.rstrip(os.sep)
    while True:
        if os.path.isfile(os.path.join(d, ".redacto-exempt")):
            return True
        if d != boundary and os.path.lexists(os.path.join(d, ".git")):
            return True
        parent = os.path.dirname(d)
        if d == boundary or parent == d or not d.startswith(boundary + os.sep):
            return False
        d = parent


def session_paths(payload, home, uid, tmp_root):
    """Returns (event, sid, records) or raises ValueError naming what was wrong with the payload."""
    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")
    event = payload.get("hook_event_name")
    if event not in EVENTS:
        raise ValueError("unsupported hook_event_name %r" % (event,))
    sid = payload.get("session_id")
    # fullmatch, not match: `$` would accept a trailing newline, which then lands in every derived path.
    if not isinstance(sid, str) or not SID_RE.fullmatch(sid):
        raise ValueError("session_id is missing or not a plain identifier")
    given = payload.get("transcript_path")

    claude = os.path.join(home, ".claude")
    projects = os.path.join(claude, "projects")
    records = []

    candidates = [given] if isinstance(given, str) and given else []
    candidates += sorted(glob.glob(os.path.join(glob.escape(projects), "*", sid + ".jsonl")))
    transcripts, seen = [], set()
    for cand in candidates:
        cand = os.path.abspath(cand)
        slug_dir = os.path.dirname(cand)
        if os.path.basename(cand) != sid + ".jsonl" or lstat_kind(cand) != "file":
            continue
        if lstat_kind(slug_dir) != "dir" or not directly_under(slug_dir, projects):
            continue
        key = os.path.realpath(cand)
        if key not in seen:
            seen.add(key)
            # Rebuilt under the lexical projects root, so the ancestor walk below stops at the sink boundary.
            transcripts.append(os.path.join(projects, os.path.basename(slug_dir), sid + ".jsonl"))

    for transcript in transcripts:
        if exempt_by_ancestor(transcript, projects):
            continue
        records += [("T", transcript), ("J", transcript), ("O", os.path.dirname(transcript))]
        sibling = transcript[: -len(".jsonl")]
        if lstat_kind(sibling) == "dir" and not exempt_by_ancestor(sibling, projects):
            records += [("T", sibling), ("J", sibling), ("R", sibling)]

    history = os.path.join(claude, "file-history")
    snapshot = os.path.join(history, sid)
    if lstat_kind(snapshot) == "dir" and directly_under(snapshot, history):
        records.append(("T", snapshot))

    # /tmp is shared: the scratch root and each level below it must be ours and not a symlink, or another user chose what gets rewritten.
    scratch = os.path.join(tmp_root, "claude-%d" % uid)
    if lstat_kind(scratch) == "dir" and owned(scratch):
        try:
            slugs = sorted(os.listdir(scratch))
        except OSError:
            slugs = []
        for slug in slugs:
            slug_dir = os.path.join(scratch, slug)
            mine = os.path.join(slug_dir, sid)
            if lstat_kind(slug_dir) != "dir" or not owned(slug_dir):
                continue
            if lstat_kind(mine) != "dir" or not owned(mine) or exempt_by_ancestor(mine, scratch):
                continue
            records += [("T", mine), ("J", mine), ("R", mine)]

    cache_root = os.path.join(claude, "image-cache")
    cache = os.path.join(cache_root, sid)
    if lstat_kind(cache) == "dir" and directly_under(cache, cache_root) and not exempt_by_ancestor(cache, cache_root):
        records += [("C", cache), ("R", cache)]

    return event, sid, records


def cmd_paths(_args):
    raw = sys.stdin.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        print("hook payload is over %d bytes" % MAX_INPUT, file=sys.stderr)
        return EX_INPUT
    try:
        payload = json.loads(raw)
        # REDACTO_SCRATCH_ROOT exists so the probe suite can stand in for /tmp; nothing in normal use sets it.
        tmp_root = os.environ.get("REDACTO_SCRATCH_ROOT") or "/tmp"
        event, sid, records = session_paths(payload, os.path.expanduser("~"), os.getuid(), tmp_root)
    except ValueError as exc:
        print("hook payload unusable: %s" % exc, file=sys.stderr)
        return EX_INPUT
    out = sys.stdout.buffer
    for kind, value in [("EVENT", event), ("SID", sid)] + records:
        out.write(("%s\t%s\0" % (kind, value)).encode("utf-8", "surrogateescape"))
    return 0


def cmd_lock(args):
    deadline = time.monotonic() + max(0.0, args.wait)
    while True:
        try:
            fcntl.flock(args.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as exc:
            if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                print("cannot lock %s: %s" % (args.path, exc), file=sys.stderr)
                return 1
            if time.monotonic() >= deadline:
                try:
                    with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
                        holder = fh.read(512).strip() or "unknown holder"
                except OSError:
                    holder = "unknown holder"
                print(holder, file=sys.stderr)
                return EX_HELD
            time.sleep(0.5)
    # Diagnostics only: the kernel lock, not this text, decides who holds it.
    os.ftruncate(args.fd, 0)
    os.write(args.fd, ("%s\n" % args.holder).encode("utf-8", "replace"))
    return 0


def cmd_detach(args):
    if not args.command:
        print("detach: no command given", file=sys.stderr)
        return 64
    if os.fork() > 0:
        return 0
    os.setsid()
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    os.closerange(3, 256)
    try:
        os.execvp(args.command[0], args.command)
    finally:
        os._exit(127)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("paths")
    lock = sub.add_parser("lock")
    lock.add_argument("--fd", type=int, required=True)
    lock.add_argument("--path", required=True)
    lock.add_argument("--wait", type=float, default=0.0)
    lock.add_argument("--holder", default="")
    detach = sub.add_parser("detach")
    detach.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    if args.cmd == "detach" and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    return {"paths": cmd_paths, "lock": cmd_lock, "detach": cmd_detach}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
