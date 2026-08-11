#!/usr/bin/env python3
"""Control suite for image-carrier-sweep.py.

The sweep destroys data by design, so every guard that stops it destroying the wrong
data needs a control that fails loudly when it regresses. Each case below names both
what must be removed and what must survive.

Usage: probe-image-carrier-sweep.py   (exit 0 = all controls pass)
"""

import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWEEP = next(
    p for p in (
        os.path.join(ROOT, "scripts", "image-carrier-sweep.py"),
        os.path.join(ROOT, "image-carrier-sweep.py"),
    ) if os.path.exists(p)
)
PLACEHOLDER = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
NOW = datetime.datetime.now(datetime.timezone.utc)
FAILURES = []


def check(name, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, ("  — " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def ts(hours_ago):
    return (NOW - datetime.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
    stamp = NOW.timestamp() - 7200
    os.utime(path, (stamp, stamp))


def run(root, *extra):
    cmd = [sys.executable, SWEEP, "--state-file", os.path.join(root, "state.json")] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def payload_bytes(nbytes):
    return base64.b64encode(os.urandom(nbytes)).decode()


def case_transcript(root):
    big, young_bytes = payload_bytes(3000), payload_bytes(2000)
    proj = os.path.join(root, "proj")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    tail = 'tail: café ✓ quote " inside'
    write_jsonl(path, [
        {"type": "user", "timestamp": ts(100),
         "message": {"role": "user", "content": [{"type": "text", "text": "plain record"}]}},
        {"type": "user", "timestamp": ts(72),
         "message": {"role": "user", "content": [
             {"type": "image", "source": {"type": "base64", "data": big, "media_type": "image/png"}}]}},
        {"type": "user", "timestamp": ts(48),
         "message": {"role": "user", "content": [{"type": "tool_result", "content": [
             {"type": "image", "source": {"type": "base64", "data": big, "media_type": "image/png"}}]}]},
         "toolUseResult": {"type": "image", "file": {"base64": big, "type": "image/png", "originalSize": 3000}}},
        {"type": "user", "timestamp": ts(1),
         "message": {"role": "user", "content": [
             {"type": "image", "source": {"type": "base64", "data": young_bytes, "media_type": "image/png"}}]}},
        {"type": "assistant", "timestamp": ts(0.5),
         "message": {"role": "assistant", "content": [{"type": "text", "text": tail}]}},
    ])

    before = open(path, "rb").read()
    rc, out, _err = run(root, "--dry-run", "--transcript", proj)
    check("dry run reports the three due payload fields", "3 payload(s)" in out, out)
    check("dry run writes nothing", open(path, "rb").read() == before)

    rc, out, err = run(root, "--transcript", proj, "--verbose")
    check("live run exits 0", rc == 0, err)
    recs = [json.loads(line) for line in open(path, encoding="utf-8")]
    check("line count unchanged", len(recs) == 5, str(len(recs)))
    check("old pasted image stripped",
          recs[1]["message"]["content"][0]["source"]["data"] == PLACEHOLDER)
    check("tool-result image stripped in message content",
          recs[2]["message"]["content"][0]["content"][0]["source"]["data"] == PLACEHOLDER)
    check("tool-result image stripped in toolUseResult.file.base64",
          recs[2]["toolUseResult"]["file"]["base64"] == PLACEHOLDER)
    check("young image survives (negative control)",
          recs[3]["message"]["content"][0]["source"]["data"] == young_bytes)
    check("sibling metadata survives", recs[2]["toolUseResult"]["file"]["originalSize"] == 3000)
    check("unicode and quotes survive", recs[4]["message"]["content"][0]["text"] == tail)

    stamped = json.load(open(os.path.join(root, "state.json")))["files"]
    check("file with a young payload is not stamped", os.path.abspath(path) not in stamped)

    digest = open(path, "rb").read()
    rc, out, _err = run(root, "--transcript", proj)
    check("second run is idempotent", open(path, "rb").read() == digest and out == "", out)


def case_live_window(root):
    proj = os.path.join(root, "live")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    write_jsonl(path, [{"type": "user", "timestamp": ts(72), "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": payload_bytes(3000), "media_type": "image/png"}}]}}])
    os.utime(path, None)
    before = open(path, "rb").read()
    run(root, "--transcript", proj)
    check("file inside the live window is left alone", open(path, "rb").read() == before)
    run(root, "--transcript", proj, "--live-window-secs", "0")
    check("same file is swept once the live window is waived",
          open(path, "rb").read() != before)
    stamped = json.load(open(os.path.join(root, "state.json")))["files"]
    check("fully-clean file is stamped", os.path.abspath(path) in stamped)


def case_structural_guard(root):
    """A payload echoed into a non-image field must abort the rewrite, not corrupt it."""
    proj = os.path.join(root, "guard")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    big = payload_bytes(3000)
    write_jsonl(path, [{"type": "user", "timestamp": ts(72), "note": big,
                        "message": {"role": "user", "content": [
                            {"type": "image",
                             "source": {"type": "base64", "data": big, "media_type": "image/png"}}]}}])
    before = open(path, "rb").read()
    rc, out, err = run(root, "--transcript", proj)
    check("collateral rewrite aborts", "rewrite aborted" in out, out or err)
    check("aborted file is byte-identical", open(path, "rb").read() == before)


def case_exempt(root):
    """A .redacto-exempt subtree must be as invisible to this sweep as it is to redacto."""
    proj = os.path.join(root, "exempt")
    fixtures = os.path.join(proj, "fixtures")
    os.makedirs(fixtures)
    open(os.path.join(fixtures, ".redacto-exempt"), "w").close()
    kept = os.path.join(fixtures, "corpus.jsonl")
    swept = os.path.join(proj, "ordinary.jsonl")
    payload = payload_bytes(3000)
    for path in (kept, swept):
        write_jsonl(path, [{"type": "user", "timestamp": ts(72), "message": {"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "data": payload, "media_type": "image/png"}}]}}])
    cache = os.path.join(root, "exempt-cache", "held")
    os.makedirs(cache)
    open(os.path.join(os.path.dirname(cache), ".redacto-exempt"), "w").close()
    img = os.path.join(cache, "5.png")
    with open(img, "wb") as fh:
        fh.write(os.urandom(2048))
    stamp = NOW.timestamp() - 72 * 3600
    os.utime(img, (stamp, stamp))

    run(root, "--transcript", proj, "--image-dir", os.path.dirname(cache),
        "--exclude", os.path.join(fixtures, "*"),
        "--exclude", os.path.join(os.path.dirname(cache), "*"))
    kept_data = json.loads(open(kept, encoding="utf-8").read())["message"]["content"][0]["source"]["data"]
    swept_data = json.loads(open(swept, encoding="utf-8").read())["message"]["content"][0]["source"]["data"]
    check("excluded transcript keeps its payload", kept_data == payload)
    check("non-excluded sibling is still swept (control)", swept_data == PLACEHOLDER)
    check("excluded cache image survives", os.path.exists(img))


def case_cache_is_images_only(root):
    """The cache sweep deletes images, not whatever else happens to share the directory."""
    cache = os.path.join(root, "typed-cache")
    os.makedirs(os.path.join(cache, "sess"))
    os.makedirs(os.path.join(cache, "pre-existing-empty"))
    img = os.path.join(cache, "sess", "5.png")
    notes = os.path.join(cache, "sess", "NOTES.txt")
    index = os.path.join(cache, "index.sqlite")
    for path in (img, notes, index):
        with open(path, "wb") as fh:
            fh.write(os.urandom(512))
        stamp = NOW.timestamp() - 72 * 3600
        os.utime(path, (stamp, stamp))
    run(root, "--image-dir", cache)
    check("stale cache image deleted", not os.path.exists(img))
    check("non-image in the cache survives", os.path.exists(notes))
    check("cache index file survives", os.path.exists(index))
    check("directory this run did not empty is left alone",
          os.path.isdir(os.path.join(cache, "pre-existing-empty")))


def case_unrecognised_payload_is_not_stamped(root):
    """A shape the detector misses must not whitelist the file forever."""
    proj = os.path.join(root, "unknown")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    known = payload_bytes(3000)
    write_jsonl(path, [{"type": "user", "timestamp": ts(72), "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": known, "media_type": "image/png"}}]}}])
    run(root, "--transcript", proj)
    state_path = os.path.join(root, "state.json")
    state = json.load(open(state_path))
    check("state records the detector version", state.get("detector") is not None)
    state["detector"] = "stale-detector"
    json.dump(state, open(state_path, "w"))
    reloaded = run(root, "--transcript", proj)
    check("a bumped detector version invalidates the cache",
          json.load(open(state_path)).get("detector") != "stale-detector", str(reloaded))


def case_symlink_untouched(root):
    proj = os.path.join(root, "symlink")
    real_dir = os.path.join(root, "symlink-target")
    os.makedirs(proj)
    os.makedirs(real_dir)
    real = os.path.join(real_dir, "real.jsonl")
    payload = payload_bytes(3000)
    write_jsonl(real, [{"type": "user", "timestamp": ts(72), "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": payload, "media_type": "image/png"}}]}}])
    link = os.path.join(proj, "link.jsonl")
    os.symlink(real, link)
    run(root, "--transcript", proj)
    check("symlinked transcript is still a symlink", os.path.islink(link))
    kept = json.loads(open(real, encoding="utf-8").read())["message"]["content"][0]["source"]["data"]
    check("symlink target is not silently rewritten", kept == payload)


def case_naive_timestamp_is_utc(root):
    """A naive stamp read as local time destroys records early east of UTC."""
    proj = os.path.join(root, "naive")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    naive = (NOW - datetime.timedelta(hours=23)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    payload = payload_bytes(3000)
    write_jsonl(path, [{"type": "user", "timestamp": naive, "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": payload, "media_type": "image/png"}}]}}])
    env = dict(os.environ, TZ="Asia/Jerusalem")
    cmd = [sys.executable, SWEEP, "--state-file", os.path.join(root, "naive-state.json"),
           "--transcript", proj]
    subprocess.run(cmd, capture_output=True, text=True, env=env)
    kept = json.loads(open(path, encoding="utf-8").read())["message"]["content"][0]["source"]["data"]
    check("naive 23h-old record survives a 24h window east of UTC", kept == payload)


def case_argument_hygiene(root):
    proj = os.path.join(root, "args")
    os.makedirs(proj)
    rc, _out, err = run(root, "--transcript", proj, "--max-age-hours", "-100")
    check("negative age window is rejected", rc != 0 and ">= 0" in err, err)
    cwd_state = subprocess.run(
        [sys.executable, SWEEP, "--state-file", "bare-state.json", "--transcript", proj],
        capture_output=True, text=True, cwd=root)
    check("a bare --state-file filename does not crash", cwd_state.returncode == 0, cwd_state.stderr)


def case_errors_reach_stdout(root):
    """An abort must survive the hook's grep, or a failing file reads as a clean report."""
    proj = os.path.join(root, "errout")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    big = payload_bytes(3000)
    write_jsonl(path, [{"type": "user", "timestamp": ts(72), "note": big,
                        "message": {"role": "user", "content": [
                            {"type": "image",
                             "source": {"type": "base64", "data": big, "media_type": "image/png"}}]}}])
    _rc, out, _err = run(root, "--transcript", proj)
    kept = [ln for ln in out.splitlines() if ln.startswith("image-carrier-sweep")]
    check("abort is reported on the line the hook keeps",
          any("rewrite aborted" in ln for ln in kept), out)


def case_escaped_solidus(root):
    """A record that escapes / carries the payload escaped too — detect AND strip, not detect and error."""
    proj = os.path.join(root, "escaped")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    payload = payload_bytes(3000)
    rec = {"type": "user", "timestamp": ts(72), "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": payload, "media_type": "image/png"}}]}}
    raw = json.dumps(rec, separators=(",", ":")).replace("/", "\\/")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw + "\n")
    stamp = NOW.timestamp() - 7200
    os.utime(path, (stamp, stamp))
    check("escaped record still decodes identically",
          json.loads(raw)["message"]["content"][0]["source"]["data"] == payload)
    _rc, out, _err = run(root, "--transcript", proj)
    after = json.loads(open(path, encoding="utf-8").read())
    check("escaped payload is stripped, not aborted",
          after["message"]["content"][0]["source"]["data"] == PLACEHOLDER, out)


def case_nan_window(root):
    """Every comparison against NaN is False, which would disable the age guard entirely."""
    proj = os.path.join(root, "nan")
    os.makedirs(proj)
    path = os.path.join(proj, "fixture.jsonl")
    payload = payload_bytes(3000)
    write_jsonl(path, [{"type": "user", "timestamp": ts(0), "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": payload, "media_type": "image/png"}}]}}])
    rc, _out, err = run(root, "--transcript", proj, "--max-age-hours", "nan")
    check("NaN age window is rejected", rc != 0 and "finite" in err, err)
    kept = json.loads(open(path, encoding="utf-8").read())["message"]["content"][0]["source"]["data"]
    check("brand-new payload survives a NaN window", kept == payload)


def case_orphan_reaping_respects_excludes(root):
    proj = os.path.join(root, "orphans")
    fixtures = os.path.join(proj, "fixtures")
    os.makedirs(fixtures)
    protected = os.path.join(fixtures, ".image-sweep-fixture")
    ordinary = os.path.join(proj, ".image-sweep-leftover")
    for path in (protected, ordinary):
        open(path, "w").close()
        stamp = NOW.timestamp() - 7200
        os.utime(path, (stamp, stamp))
    run(root, "--transcript", proj, "--exclude", os.path.join(fixtures, "*"))
    check("excluded temp-named file is not reaped", os.path.exists(protected))
    check("genuine orphan is reaped (control)", not os.path.exists(ordinary))


def case_nested_cache_dirs(root):
    """A parent emptied only by its child's removal must still go."""
    cache = os.path.join(root, "nested-cache")
    deep = os.path.join(cache, "2026-08", "session-abc")
    os.makedirs(deep)
    img = os.path.join(deep, "5.png")
    with open(img, "wb") as fh:
        fh.write(os.urandom(512))
    stamp = NOW.timestamp() - 72 * 3600
    os.utime(img, (stamp, stamp))
    run(root, "--image-dir", cache)
    check("nested session directory removed", not os.path.isdir(deep))
    check("its emptied parent removed too", not os.path.isdir(os.path.join(cache, "2026-08")))
    check("cache root itself survives", os.path.isdir(cache))


def case_unwritable_dir_does_not_sink_the_run(root):
    """One unwritable directory must not abort the whole sweep and report clean."""
    proj = os.path.join(root, "locked")
    a_locked = os.path.join(proj, "a-locked")
    b_open = os.path.join(proj, "b-open")
    os.makedirs(a_locked)
    os.makedirs(b_open)
    payload = payload_bytes(3000)
    rec = [{"type": "user", "timestamp": ts(72), "message": {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "data": payload, "media_type": "image/png"}}]}}]
    write_jsonl(os.path.join(a_locked, "f.jsonl"), rec)
    write_jsonl(os.path.join(b_open, "f.jsonl"), rec)
    os.chmod(a_locked, 0o500)
    try:
        _rc, out, _err = run(root, "--transcript", proj)
        sibling = json.loads(open(os.path.join(b_open, "f.jsonl"), encoding="utf-8").read())
        check("writable sibling is still swept",
              sibling["message"]["content"][0]["source"]["data"] == PLACEHOLDER, out)
        check("the failure is reported on the line the hook keeps",
              any(ln.startswith("image-carrier-sweep") and "aborted" in ln for ln in out.splitlines()), out)
    finally:
        os.chmod(a_locked, 0o700)


def case_marker_search_covers_sweep_roots(root):
    """redacto_sink_excludes must emit globs for the roots the sweep actually walks."""
    sinks = os.path.join(os.path.dirname(HERE), "scripts", "redacto-sinks.sh")
    found = os.path.exists(sinks)
    # Fails rather than returns: a silent skip reports a full pass with this control never run.
    check("redacto-sinks.sh is where this control looks for it", found, sinks)
    if not found:
        return
    text = open(sinks, encoding="utf-8").read()
    for needed in ("$HOME/.claude/projects", "$HOME/.claude/image-cache"):
        check("marker search covers %s" % needed, needed in text.split("redacto_sink_excludes")[1])


def case_image_cache(root):
    cache = os.path.join(root, "cache")
    os.makedirs(os.path.join(cache, "old-session"))
    os.makedirs(os.path.join(cache, "new-session"))
    old = os.path.join(cache, "old-session", "5.png")
    new = os.path.join(cache, "new-session", "1.png")
    for path in (old, new):
        with open(path, "wb") as fh:
            fh.write(os.urandom(2048))
    stamp = NOW.timestamp() - 72 * 3600
    os.utime(old, (stamp, stamp))
    run(root, "--image-dir", cache)
    check("stale cache image deleted", not os.path.exists(old))
    check("stale session directory removed", not os.path.isdir(os.path.dirname(old)))
    check("recent cache image survives (negative control)", os.path.exists(new))


def main():
    raw = base64.b64decode(PLACEHOLDER)
    check("placeholder is a 96-char valid PNG", len(PLACEHOLDER) == 96 and raw[:8] == b"\x89PNG\r\n\x1a\n")
    root = tempfile.mkdtemp(prefix="image-sweep-probe-")
    try:
        case_transcript(root)
        case_live_window(root)
        case_structural_guard(root)
        case_exempt(root)
        case_escaped_solidus(root)
        case_nan_window(root)
        case_orphan_reaping_respects_excludes(root)
        case_nested_cache_dirs(root)
        case_unwritable_dir_does_not_sink_the_run(root)
        case_marker_search_covers_sweep_roots(root)
        case_cache_is_images_only(root)
        case_unrecognised_payload_is_not_stamped(root)
        case_symlink_untouched(root)
        case_naive_timestamp_is_utc(root)
        case_argument_hygiene(root)
        case_errors_reach_stdout(root)
        case_image_cache(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("\n%d control(s) failed" % len(FAILURES) if FAILURES else "\nall controls passed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
