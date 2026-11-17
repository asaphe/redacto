#!/usr/bin/env python3
"""Control suite for redacto-log-sweep.sh.

The hook's only job is to distinguish three outcomes — clean, findings, and a sweep that
did not finish — and it has collapsed them into "silent" three separate times. Each case
below pins one outcome and fails loudly when it collapses again. The scope cases pin the
other contract: a session's hook touches that session's files only, a full sweep needs
--all, and one lock keeps any two sweeps from running at once.

Usage: probe-log-sweep.py   (exit 0 = all controls pass; the scope cases need `cargo build`)
"""

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASH = shutil.which("bash") or "/bin/bash"
SWEEP = os.path.join(ROOT, "scripts", "redacto-log-sweep.sh")
SINKS = os.path.join(ROOT, "scripts", "redacto-sinks.sh")
HELPER = os.path.join(ROOT, "scripts", "redacto-session.py")
IMAGE = os.path.join(ROOT, "scripts", "image-carrier-sweep.py")
REAL_BIN = os.path.join(ROOT, "target", "debug", "redacto")
CLEAN_SUMMARY = (
    "redacto: 0 file(s) with matches, 0 total redaction(s), 0 validation failure(s), "
    "0 file(s) with unsafe lines, 0 file(s) with unresolved PEM markers, write_mode=true"
)
FOUND_SUMMARY = (
    "redacto: 2 file(s) with matches, 7 total redaction(s), 0 validation failure(s), "
    "0 file(s) with unsafe lines, 0 file(s) with unresolved PEM markers, write_mode=true"
)
SID = "aaaaaaaa-1111-2222-3333-444444444444"
OTHER = "bbbbbbbb-1111-2222-3333-444444444444"
# Built at runtime, never literal: a literal key in this file would be rewritten by the first sweep that reads it.
KEY = "sk-" + "proj-" + "abcdefgh01234567" * 3
FAILURES = []


def check(name, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, ("  — " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def write_exec(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_old(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    # Backdated past every live window the hook applies.
    os.utime(path, (1577836800, 1577836800))


def make_session(root, sid=SID, slug="-slug", body='{"type":"user"}\n'):
    path = os.path.join(root, ".claude", "projects", slug, sid + ".jsonl")
    write_old(path, body)
    os.makedirs(path[: -len(".jsonl")], exist_ok=True)
    return path


def stage(root, stdout="", stderr="", rc=0, image_body=None, sink_paths=("/sink-a",), stderr_newline=True,
          session_files=None):
    """Copy the real hook and helper next to stubs. `--all` reads the stubbed sink lists; a Stop run
    reads this session's own files, created under the fixture HOME whenever there are sinks."""
    sd = os.path.join(root, "scripts")
    os.makedirs(sd, exist_ok=True)
    shutil.copy(SWEEP, os.path.join(sd, "redacto-log-sweep.sh"))
    shutil.copy(HELPER, os.path.join(sd, "redacto-session.py"))
    with open(os.path.join(sd, "redacto-sinks.sh"), "w", encoding="utf-8") as fh:
        fh.write(
            "redacto_sink_paths() { %s; }\n"
            "redacto_sink_excludes() { printf '%%s\\n' '*/.git/*'; }\n"
            "redacto_transcript_roots() { printf '%%s\\n' '/t'; }\n"
            "redacto_image_cache_paths() { printf '%%s\\n' '/i'; }\n"
            % (
                "printf '%s\\n' " + " ".join("'%s'" % p for p in sink_paths)
                if sink_paths
                else "return 0"
            )
        )
    write_exec(
        os.path.join(root, "stub-redacto"),
        "#!/usr/bin/env bash\necho x >> %s\nprintf '%%s\\n' \"$@\" -- >> %s\n"
        # An engine that stays busy, and records whether another one was busy at the same moment.
        "if [ -n \"$STUB_SLEEP\" ]; then mkdir \"$STUB_BUSY\" 2>/dev/null || echo OVERLAP >> \"$STUB_BUSY.overlap\"; "
        "sleep \"$STUB_SLEEP\"; rmdir \"$STUB_BUSY\" 2>/dev/null; fi\n"
        "BUMP=0\n"
        "[ -n \"$STUB_SKIP_CONTROL\" ] || for a in \"$@\"; do case \"$a\" in */known-positive.txt) printf '[REDACTED]\\n' > \"$a\"; BUMP=3 ;; esac; done\n"
        "OUT=%s\n"
        # A real run counts the control's three redactions in its total, which the hook subtracts again.
        "if [[ $OUT =~ ([0-9]+)\\ total ]]; then N=${BASH_REMATCH[1]}; OUT=${OUT/$N total/$((N + BUMP)) total}; fi\n"
        "printf '%%s' \"$OUT\"\nprintf '%%s' %s >&2\nexit %d\n"
        % (
            _q(os.path.join(root, "invoked")),
            _q(os.path.join(root, "argv")),
            _q(stdout + "\n" if stdout else ""),
            _q((stderr + "\n" if stderr_newline else stderr) if stderr else ""),
            rc,
        ),
    )
    write_exec(
        os.path.join(sd, "image-carrier-sweep.py"),
        image_body if image_body is not None else "#!/usr/bin/env python3\nimport sys; sys.exit(0)\n",
    )
    if session_files if session_files is not None else bool(sink_paths):
        make_session(root)
    return sd


def _q(text):
    return "'" + text.replace("'", "'\\''") + "'"


def invocations(root):
    try:
        with open(os.path.join(root, "invoked"), encoding="utf-8") as fh:
            return len(fh.read().splitlines())
    except OSError:
        return 0


def argv_of(root):
    try:
        with open(os.path.join(root, "argv"), encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def payload(root, event="Stop", sid=SID, transcript=None):
    if transcript is None:
        transcript = os.path.join(root, ".claude", "projects", "-slug", sid + ".jsonl")
    return json.dumps({"hook_event_name": event, "session_id": sid, "transcript_path": transcript, "cwd": root})


TOOLS = ["bash", "env", "grep", "sed", "awk", "tr", "head", "tail", "wc", "mktemp", "rm", "dirname", "touch", "cat",
         "id", "date", "mkdir", "rmdir", "mv", "find", "sleep", "renice", "perl", "taskpolicy"]
# A fixture PATH missing a tool fails to empty output, which reads as correct silence, so every run is screened for it.
MISSING_TOOL = []


def make_bin(root, name, with_python=True, without=()):
    """A PATH with no `redacto` on it: the hook falls back to `command -v redacto`, and this
    suite runs it in --write mode, so a reachable real binary would sweep the real machine."""
    bindir = os.path.join(root, name)
    os.makedirs(bindir, exist_ok=True)
    for tool in TOOLS:
        found = shutil.which(tool)
        if found and tool not in without and not os.path.exists(os.path.join(bindir, tool)):
            os.symlink(found, os.path.join(bindir, tool))
    # sys.executable, not which("python3"): a version-manager shim needs helpers this PATH lacks.
    link = os.path.join(bindir, "python3")
    if with_python and not os.path.exists(link):
        os.symlink(os.path.realpath(sys.executable), link)
    return bindir


def hook_env(root, env_extra=None):
    env = dict(os.environ)
    env.pop("XDG_STATE_HOME", None)
    env["HOME"] = root
    env["REDACTO_BIN"] = os.path.join(root, "stub-redacto")
    env["PATH"] = make_bin(root, "bin")
    env["REDACTO_SETTLE_SECS"] = "0"
    env["REDACTO_SCRATCH_ROOT"] = os.path.join(root, "scratch")
    env.update(env_extra or {})
    return env


def run(root, sd, env_extra=None, args=None, stdin=None, event="Stop"):
    """A Stop run by default; args=["--all"] for a full sweep. stdin defaults to this session's payload."""
    args = list(args or [])
    if stdin is None:
        stdin = "" if args else payload(root, event=event)
    # Absolute: every case runs with a PATH holding only the tools the hook needs.
    proc = subprocess.run(
        [BASH, os.path.join(sd, "redacto-log-sweep.sh")] + args,
        input=stdin, capture_output=True, text=True, env=hook_env(root, env_extra), timeout=180,
    )
    for line in proc.stderr.splitlines():
        if "command not found" in line or "No such file or directory" in line:
            MISSING_TOOL.append(line.strip())
    return proc.returncode, proc.stdout, proc.stderr


def sink_env(home, **extra):
    """XDG_DATA_HOME is inherited from the caller otherwise, and it moves the very path the
    RTK case asserts on — a green or red result would then depend on the developer's shell."""
    env = dict(os.environ)
    env["HOME"] = home
    env.pop("XDG_DATA_HOME", None)
    env.update(extra)
    return env


def message(stdout):
    """The systemMessage a Stop run hands Claude, or None when the hook stayed silent."""
    if not stdout.strip():
        return None
    return json.loads(stdout)["systemMessage"]


def hold_lock(root, holder="pid=4242 mode=probe-holder"):
    """A separate process holding the sweep lock, as another session's run or a scheduled sweep would."""
    lock = os.path.join(root, ".local", "state", "redacto", "sweep.lock")
    os.makedirs(os.path.dirname(lock), exist_ok=True)
    code = (
        "import fcntl,os,sys,time\n"
        "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o644)\n"
        "fcntl.flock(fd,fcntl.LOCK_EX)\n"
        "os.ftruncate(fd,0); os.write(fd,(sys.argv[2]+'\\n').encode())\n"
        "print('ready',flush=True)\n"
        "time.sleep(120)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code, lock, holder], stdout=subprocess.PIPE, text=True)
    ready = proc.stdout.readline().strip() == "ready"
    return proc, lock, ready


# ---- reporting contract (a Stop run unless the case says otherwise) ----

def case_broken_python3_still_reports(root):
    """`command -v python3` proves presence, never that it runs. A broken interpreter cannot parse
    the payload or take the lock, and that must reach Claude rather than dropping the report."""
    sd = stage(root, stderr="thread 'main' panicked at src/main.rs:1:1", rc=101)
    bindir = make_bin(root, "brokenpy")
    os.remove(os.path.join(bindir, "python3"))
    write_exec(os.path.join(bindir, "python3"), "#!/usr/bin/env bash\nprintf 'python3: broken install\\n' >&2\nexit 1\n")
    check("control: python3 is still found on this fixture PATH",
          shutil.which("python3", path=bindir) is not None)
    _rc, out, _err = run(root, sd, env_extra={"PATH": bindir})
    check("a broken python3 does not swallow the report", out.strip() != "", repr(_err))
    try:
        msg = json.loads(out)["systemMessage"]
        ok = True
    except (ValueError, KeyError):
        msg, ok = "", False
    check("the fallback encoder produced parseable JSON", ok, repr(out))
    check("the report names python3 as the reason nothing was swept",
          ok and "python3" in msg and "NOT swept" in msg, repr(msg))
    check("nothing was swept without the lock", invocations(root) == 0)


def case_error_count_includes_an_unterminated_last_line(root):
    """wc -l counts terminators, so a final line without its newline is dropped from the excerpt
    and from the remainder count — the excerpt then understates the failure it is summarising."""
    lines = ["/sink-%d: path does not exist" % i for i in range(12)]
    sd = stage(root, stdout=CLEAN_SUMMARY, stderr="\n".join(lines), rc=1, stderr_newline=False)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("an unterminated last stderr line is still counted",
          msg is not None and "7 more line(s)" in msg, repr(msg))


def case_absent_python3_is_reported(root):
    """With no python3 nothing can run: the payload is unparsed and the lock untaken. A missing
    binary stays silent because the plugin was never opted into; this is a sweep the user
    believes is running."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    bindir = make_bin(root, "nopy2", with_python=False)
    check("control: the fixture really has no python3", shutil.which("python3", path=bindir) is None)
    _rc, out, _err = run(root, sd, env_extra={"PATH": bindir})
    msg = message(out)
    check("a missing python3 is reported rather than passing as clean",
          msg is not None and "python3 not found" in msg, repr(out))
    check("the message says nothing was swept", msg is not None and "NOT swept" in msg, repr(msg))


def case_clean_run_is_silent(root):
    """The positive control comes first: `out == ""` also passes when the fixture is too broken
    to execute anything, which is exactly how a silence assertion rots into a rubber stamp."""
    loud = stage(os.path.join(root, "loud"), stdout=FOUND_SUMMARY, rc=0)
    _rc, out, err = run(os.path.join(root, "loud"), loud)
    check("control: this fixture can emit output at all", out.strip() != "", repr(err))
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    _rc, out, _err = run(root, sd)
    check("a clean sweep prints nothing at all", out == "", repr(out))
    check("control: the clean sweep did invoke the binary", invocations(root) == 1)


def case_findings_are_reported(root):
    """rc=0, because `total_redactions` is not in report()'s trouble predicate: a completed run
    that redacted cleanly exits 0. Pairing this summary with rc=1 pins a state the CLI cannot produce."""
    sd = stage(root, stdout=FOUND_SUMMARY, rc=0)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("a run with redactions reports its summary", msg is not None and "7 total redaction(s)" in msg, repr(out))


def case_validation_failure_is_reported(root):
    """The reachable exit-1-with-findings shape: a trouble counter, not a redaction count."""
    summary = CLEAN_SUMMARY.replace("0 validation failure(s)", "2 validation failure(s)")
    sd = stage(root, stdout=summary, rc=1)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("a validation failure is reported", msg is not None and "2 validation failure(s)" in msg, repr(out))


def case_exit_zero_without_a_summary_is_not_called_a_crash(root):
    """Reachable when `command -v redacto` finds a wrapper: reporting is right, but calling a
    clean exit "did not reach the end" is a message that contradicts itself."""
    sd = stage(root, stdout="some wrapper banner", rc=0)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("exit 0 with no summary is still reported", msg is not None, repr(out))
    check("it is not described as an unfinished sweep",
          msg is not None and "did not reach the end" not in msg, repr(msg))
    check("the stdout diagnostic survives when stderr is empty",
          msg is not None and "wrapper banner" in msg, repr(msg))


def case_root_error_names_the_path(root):
    """An all-zero summary with exit 1 is a root the CLI could not scan — reporting it as
    all-zero reads as a clean no-op, and the path is on stderr the summary filter drops."""
    sd = stage(root, stdout=CLEAN_SUMMARY, stderr="/absent-sink: path does not exist", rc=1)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("a failed sink is reported at all", msg is not None, repr(out))
    check("the failing path is named", msg is not None and "/absent-sink" in msg, repr(msg))
    check("it does not read as a clean no-op", msg is not None and msg.strip() != CLEAN_SUMMARY, repr(msg))


def case_unredacted_control_fails_loudly(root):
    """A stub that leaves the control file alone stands for a binary whose rules never fired."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    rc, out, err = run(root, sd, env_extra={"STUB_SKIP_CONTROL": "1"})
    msg = message(out)
    check("an unredacted control is reported, not silent", msg is not None and "CONTROL FAILED" in msg, repr(out))
    check("an unredacted control exits non-zero", rc != 0, repr(rc))
    check("an unredacted control also writes stderr", "CONTROL FAILED" in err, repr(err))


def case_crash_is_loud(root):
    sd = stage(root, stderr="thread 'main' panicked at src/main.rs:1:1", rc=101)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("a crash before report() is reported", msg is not None, repr(out))
    check("the crash carries its stderr", msg is not None and "panicked" in msg, repr(msg))


def case_stderr_warning_cannot_pass_as_a_summary(root):
    """config.rs writes `redacto:`-prefixed warnings to stderr, so a merged stream let a
    warning stand in for the summary line and hide a crash."""
    sd = stage(root, stderr="redacto: failed to parse config file, ignoring", rc=101)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("a stderr warning does not count as reaching the end",
          msg is not None and "did not reach the end" in msg, repr(msg))


def case_findings_and_root_error_both_survive(root):
    sd = stage(root, stdout=FOUND_SUMMARY, stderr="/absent-sink: path does not exist", rc=1)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("findings survive alongside a root error", msg is not None and "7 total redaction(s)" in msg, repr(msg))
    check("the root error survives alongside findings", msg is not None and "/absent-sink" in msg, repr(msg))


def case_truncated_error_list_states_its_scale(root):
    sd = stage(root, stdout=CLEAN_SUMMARY,
               stderr="\n".join("/sink-%d: path does not exist" % i for i in range(12)), rc=1)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("a truncated error list says how many it dropped", msg is not None and "7 more line(s)" in msg, repr(msg))


def case_image_sweep_crash_is_loud(root):
    """A real traceback runs deeper than five lines and its informative line is the LAST one, so
    a head-style excerpt reports that it failed while dropping why."""
    deep = ("#!/usr/bin/env python3\n"
            "def d(): raise PermissionError('cannot write state file')\n"
            "def c(): d()\n"
            "def b(): c()\n"
            "def a(): b()\n"
            "a()\n")
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0, image_body=deep)
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("an image-sweep crash is reported", msg is not None and "image-carrier-sweep" in msg, repr(out))
    check("the image-sweep crash is not silent-clean", msg is not None and "did NOT complete" in msg, repr(msg))
    check("the exception itself survives the excerpt",
          msg is not None and "cannot write state file" in msg, repr(msg))


def case_image_sweep_silence_is_not_an_error(root):
    """The python sweep prints its summary line only when it has something to say, so an
    empty line is a clean run — the opposite of the redacto path's contract."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    _rc, out, _err = run(root, sd)
    check("a silent image sweep with a clean redacto stays silent", out == "", repr(out))


def case_no_sinks_never_invokes_the_binary(root):
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0, sink_paths=())
    _rc, out, _err = run(root, sd)
    check("a session with no files of its own stays silent", out == "", repr(out))
    check("a session with no files of its own does not invoke the binary", invocations(root) == 0)


def case_no_sinks_still_runs_the_image_sweep(root):
    """The image sinks are a separate list, so an empty text-sink list must not gate them —
    a session with only an image cache would otherwise leave screenshot payloads in place."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0, sink_paths=(),
               image_body="#!/usr/bin/env python3\nprint('image-carrier-sweep: 3 payload(s) in 1 transcript(s)')\n")
    os.makedirs(os.path.join(root, ".claude", "image-cache", SID))
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("the image sweep runs even with no text sinks",
          msg is not None and "3 payload(s)" in msg, repr(out))
    check("the text sweep is still skipped", invocations(root) == 0)


def case_image_sweep_gets_only_this_sessions_paths(root):
    """Without --scoped an empty list means every transcript, so the flag and the paths are the contract."""
    record = os.path.join(root, "image-argv")
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0,
               image_body="#!/usr/bin/env python3\nimport sys\nopen(%r, 'w').write('\\n'.join(sys.argv[1:]))\n" % record)
    make_session(root, sid=OTHER)
    os.makedirs(os.path.join(root, ".claude", "image-cache", SID))
    run(root, sd)
    args = read_or_none(record) or ""
    lines = args.splitlines()
    check("the image sweep runs scoped", "--scoped" in lines, repr(args))
    check("the image sweep gets this session's transcript",
          os.path.join(root, ".claude", "projects", "-slug", SID + ".jsonl") in lines, repr(args))
    check("the image sweep gets this session's image cache",
          os.path.join(root, ".claude", "image-cache", SID) in lines, repr(args))
    check("the image sweep never gets another session's paths", OTHER not in args, repr(args))
    check("the image sweep keeps per-session state", "--state-file" in lines and SID in args, repr(args))


def case_missing_binary_is_inert(root):
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    check("the fixture PATH cannot reach a real redacto",
          shutil.which("redacto", path=make_bin(root, "bin")) is None)
    _rc, out, _err = run(root, sd, env_extra={"REDACTO_BIN": os.path.join(root, "nope")})
    check("no binary means no output from a hook", out == "", repr(out))
    rc, _out, err = run(root, sd, env_extra={"REDACTO_BIN": os.path.join(root, "nope")}, args=["--all"])
    check("a manual --all without the binary says so", rc != 0 and "not found" in err, repr((rc, err)))


def case_fallback_json_survives_control_characters(root):
    """The hand-rolled encoder runs when python3 works for the sweep but fails to encode; a raw
    tab or CR there is illegal inside a JSON string and silently breaks the hook's output."""
    bindir = make_bin(root, "encfail", with_python=False)
    write_exec(os.path.join(bindir, "python3"),
               "#!/usr/bin/env bash\ncase \"$2\" in *json.dumps*) exit 1 ;; esac\nexec %s \"$@\"\n"
               % _q(os.path.realpath(sys.executable)))
    sd = stage(root, stdout=FOUND_SUMMARY + "\tafter-tab\rafter-cr", rc=1)
    _rc, out, _err = run(root, sd, env_extra={"PATH": bindir})
    check("the fallback branch produced output", out.strip() != "", repr(_err))
    try:
        msg = json.loads(out)["systemMessage"]
        ok = True
    except (ValueError, KeyError):
        msg, ok = "", False
    check("the fallback emits parseable JSON despite a tab and a CR", ok, repr(out))
    check("the text either side of the stripped controls survives",
          ok and "after-tab" in msg and "after-cr" in msg, repr(msg))


# ---- modes and the lock ----

def case_full_sweep_needs_the_flag(root):
    sd = stage(root, stdout=FOUND_SUMMARY, rc=0)
    _rc, out, _err = run(root, sd, args=[], stdin="")
    msg = message(out)
    check("a bare run with no payload sweeps nothing", invocations(root) == 0, repr(out))
    check("a bare run with no payload says why", msg is not None and "nothing was swept" in msg, repr(msg))
    rc, _out, _err = run(root, sd, args=["--everything"])
    check("an unknown flag is a usage error", rc == 64 and invocations(root) == 0, repr(rc))
    rc, out, _err = run(root, sd, args=["--all"])
    check("--all sweeps the full sink list", "/sink-a" in argv_of(root), repr(argv_of(root)))
    check("--all reports in plain text", "7 total redaction(s)" in out and not out.startswith("{"), repr(out))
    check("--all with findings redacted exits 0", rc == 0, repr(rc))


def case_full_sweep_exit_status_means_something(root):
    for name, kwargs, extra, want in (
        ("clean", {"stdout": CLEAN_SUMMARY}, {}, 0),
        ("root error", {"stdout": CLEAN_SUMMARY, "stderr": "/sink-a: path does not exist", "rc": 1}, {}, 1),
        ("control failure", {"stdout": CLEAN_SUMMARY}, {"STUB_SKIP_CONTROL": "1"}, 1),
        ("crash", {"stderr": "thread 'main' panicked", "rc": 101}, {}, 1),
    ):
        sub = os.path.join(root, name.replace(" ", "-"))
        sd = stage(sub, **kwargs)
        rc, out, _err = run(sub, sd, env_extra=extra, args=["--all"])
        check("--all exits %d on a %s run" % (want, name), rc == want, repr((rc, out)))


def case_a_held_lock_refuses_or_defers(root):
    sd = stage(root, stdout=FOUND_SUMMARY, rc=0)
    holder, _lock, ready = hold_lock(root)
    try:
        check("control: the holder took the lock", ready)
        rc, out, err = run(root, sd, args=["--all"], env_extra={"REDACTO_LOCK_WAIT_SECS": "0"})
        check("--all refuses while another sweep holds the lock", rc == 75, repr((rc, err)))
        check("the refusal names the holder", "probe-holder" in err, repr(err))
        rc, out, _err = run(root, sd, env_extra={"REDACTO_LOCK_WAIT_SECS": "0"})
        check("a Stop run defers silently while the lock is held", rc == 0 and out == "", repr((rc, out)))
        check("neither run swept anything", invocations(root) == 0)
    finally:
        holder.send_signal(signal.SIGKILL)
        holder.wait()
    rc, out, _err = run(root, sd, args=["--all"], env_extra={"REDACTO_LOCK_WAIT_SECS": "5"})
    check("a holder killed with SIGKILL releases the lock", rc == 0 and invocations(root) == 1, repr((rc, out)))


def spawn(root, sd, env_extra, stdin_text, args=()):
    proc = subprocess.Popen([BASH, os.path.join(sd, "redacto-log-sweep.sh")] + list(args), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=hook_env(root, env_extra))
    proc.stdin.write(stdin_text)
    proc.stdin.close()
    return proc


def case_two_sweeps_never_run_their_engines_at_once(root):
    """The lock is only real if it is held while the engine rewrites files, not just around a check."""
    busy = os.path.join(root, "busy")
    control = os.path.join(root, "control")
    sd_control = stage(control, stdout=CLEAN_SUMMARY, rc=0)
    stub = os.path.join(control, "stub-redacto")
    env = dict(os.environ, STUB_SLEEP="2", STUB_BUSY=os.path.join(control, "busy"))
    pair = [subprocess.Popen([stub], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(2)]
    for p in pair:
        p.wait()
    check("control: two unlocked engines started together are seen overlapping",
          os.path.exists(os.path.join(control, "busy.overlap")), sd_control)

    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    make_session(root, sid=OTHER)
    extra = {"STUB_SLEEP": "2", "STUB_BUSY": busy, "REDACTO_LOCK_WAIT_SECS": "30"}
    runs = [spawn(root, sd, extra, payload(root, sid=sid)) for sid in (SID, OTHER)]
    for p in runs:
        p.wait(timeout=120)
    check("both sessions' sweeps ran", invocations(root) == 2, str(invocations(root)))
    check("control: the busy marker clears after each engine", not os.path.isdir(busy))
    check("two sessions' engines never ran at once", not os.path.exists(busy + ".overlap"))

    held = spawn(root, sd, {"STUB_SLEEP": "4", "STUB_BUSY": busy}, payload(root))
    ok = wait_for(lambda: os.path.isdir(busy), 30)
    rc, _out, err = run(root, sd, args=["--all"], env_extra={"REDACTO_LOCK_WAIT_SECS": "0"})
    held.wait(timeout=120)
    check("control: the session engine was mid-run", ok)
    check("--all refuses while a session's engine is mid-run", rc == 75 and "mode=hook" in err, repr((rc, err)))


def case_paths_are_checked_again_under_the_lock(root):
    """A session directory swapped for a symlink while the run settled must not become a sweep root."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    sibling = os.path.join(root, ".claude", "projects", "-slug", SID)
    elsewhere = os.path.join(root, "elsewhere")
    os.makedirs(elsewhere)
    proc = spawn(root, sd, {"REDACTO_SETTLE_SECS": "3"}, payload(root))
    time.sleep(1)
    os.rmdir(sibling)
    os.symlink(elsewhere, sibling)
    proc.wait(timeout=60)
    args = argv_of(root)
    check("control: the run still swept the transcript",
          os.path.join(root, ".claude", "projects", "-slug", SID + ".jsonl") in args, repr(args))
    check("a directory swapped for a symlink during the settle is not swept", sibling not in args, repr(args))


def case_timing_values_are_bounded(root):
    """A long digit string overflowed bash arithmetic into a negative sleep; the function is exercised directly."""
    script = 'source <(sed -n "/^bounded_int() {/,/^}/p" "$1"); shift; for v in "$@"; do bounded_int "$v" 30 600; done'
    values = ["99999999999999999999", "9223372036854775808", "601", "0042", "abc", "", "5"]
    out = subprocess.run([BASH, "-c", script, "_", SWEEP] + values, capture_output=True, text=True).stdout.split()
    check("control: the function was extracted and ran once per value", len(out) == len(values), repr(out))
    check("an overflowing value is capped, not wrapped", out[:2] == ["600", "600"], repr(out))
    check("a value over the cap is capped", out[2:3] == ["600"], repr(out))
    check("leading zeros are decimal, not octal", out[3:4] == ["42"], repr(out))
    check("a non-number or empty value takes the default", out[4:6] == ["30", "30"], repr(out))
    check("control: an ordinary value passes through", out[6:7] == ["5"], repr(out))


def case_an_image_sweep_error_fails_a_full_sweep(root):
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0,
               image_body="#!/usr/bin/env python3\nprint('image-carrier-sweep: 0 payload(s) in 0 transcript(s) (0.0 MB), 0 cache file(s) (0.0 MB)')\n"
                          "print('image-carrier-sweep: ! /x.jsonl: rewrite aborted (file changed during the rewrite)')\n")
    rc, out, _err = run(root, sd, args=["--all"])
    check("an image-sweep file error is reported", "rewrite aborted" in out, repr(out))
    check("an image-sweep file error makes --all exit 1", rc == 1, repr(rc))


def case_a_stale_lock_file_does_not_block(root):
    """There is no stale state to recover: the kernel drops a flock when its holder dies, and the
    text left in the file by a dead run is diagnostics only."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    lock = os.path.join(root, ".local", "state", "redacto", "sweep.lock")
    os.makedirs(os.path.dirname(lock))
    with open(lock, "w", encoding="utf-8") as fh:
        fh.write("pid=999999 mode=all since=2020-01-01T00:00:00Z\n")
    rc, _out, err = run(root, sd, args=["--all"], env_extra={"REDACTO_LOCK_WAIT_SECS": "0"})
    check("a lock file left by a dead run does not block the next one", rc == 0 and invocations(root) == 1, err)
    with open(lock, encoding="utf-8") as fh:
        text = fh.read()
    check("the new holder replaced the dead run's text", "mode=all" in text and "999999" not in text, repr(text))


def case_a_newer_run_supersedes_a_settling_one(root):
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    older = subprocess.Popen(
        [BASH, os.path.join(sd, "redacto-log-sweep.sh")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=hook_env(root, {"REDACTO_SETTLE_SECS": "3"}),
    )
    older.stdin.write(payload(root))
    older.stdin.close()
    time.sleep(1)
    run(root, sd)
    older.wait(timeout=60)
    check("control: the newer run swept", invocations(root) >= 1)
    check("the older run of the same session stood down", invocations(root) == 1, str(invocations(root)))


# ---- scope ----

def scope_fixture(root):
    """Real files for this session and a neighbour, each holding a key, under a fixture HOME and /tmp."""
    uid = os.getuid()
    claude = os.path.join(root, ".claude")
    scratch = os.path.join(root, "scratch", "claude-%d" % uid)
    mine = {
        "transcript": os.path.join(claude, "projects", "-slug", SID + ".jsonl"),
        "tool result": os.path.join(claude, "projects", "-slug", SID, "tool-results", "r.txt"),
        "subagent": os.path.join(claude, "projects", "-slug", SID, "subagents", "agent-1.jsonl"),
        "file history": os.path.join(claude, "file-history", SID, "f@v1"),
        "scratchpad": os.path.join(scratch, "-launch-slug", SID, "scratchpad", "dump.txt"),
    }
    theirs = {
        "neighbour transcript": os.path.join(claude, "projects", "-slug", OTHER + ".jsonl"),
        "neighbour tool result": os.path.join(claude, "projects", "-slug", OTHER, "tool-results", "r.txt"),
        "neighbour file history": os.path.join(claude, "file-history", OTHER, "f@v1"),
        "neighbour scratchpad": os.path.join(scratch, "-launch-slug", OTHER, "scratchpad", "dump.txt"),
        "history.jsonl": os.path.join(claude, "history.jsonl"),
        "paste cache": os.path.join(claude, "paste-cache", "abc.txt"),
    }
    for path in list(mine.values()) + list(theirs.values()):
        write_old(path, json.dumps({"type": "user", "message": KEY}) + "\n")
    return mine, theirs


def has_key(path):
    with open(path, encoding="utf-8") as fh:
        return KEY in fh.read()


def case_a_session_run_touches_only_its_own_files(root):
    """End to end with the real binary and the real image sweep: a neighbour's known-positive files
    are the control that the scope held, and the session's own must come back redacted."""
    check("the real binary is built (cargo build) for the scope cases", os.access(REAL_BIN, os.X_OK), REAL_BIN)
    if not os.access(REAL_BIN, os.X_OK):
        return
    with open(IMAGE, encoding="utf-8") as fh:
        sd = stage(root, session_files=False, image_body=fh.read())
    mine, theirs = scope_fixture(root)
    rc, out, err = run(root, sd, env_extra={"REDACTO_BIN": REAL_BIN})
    msg = message(out)
    check("the session run exits 0", rc == 0, repr((rc, err)))
    for name, path in mine.items():
        check("this session's %s is redacted" % name, not has_key(path), path)
    for name, path in theirs.items():
        check("the %s is untouched" % name, has_key(path), path)
    check("the report counts only this session's files",
          msg is not None and "%d total redaction(s)" % len(mine) in msg, repr(msg))
    state = os.path.join(root, ".local", "state", "redacto")
    check("the global watermark is not touched", not os.path.exists(os.path.join(state, "watermark.json")))
    check("the session keeps its own watermark", os.path.exists(os.path.join(state, "sessions", SID, "watermark.json")))
    rc, out, _err = run(root, sd, env_extra={"REDACTO_BIN": REAL_BIN})
    check("a second run over unchanged files is silent", rc == 0 and out == "", repr(out))


def case_a_bad_payload_never_widens_the_scope(root):
    sd = stage(root, stdout=FOUND_SUMMARY, rc=0)
    outside = os.path.join(root, "outside", SID + ".jsonl")
    write_old(outside, "x\n")
    bad = {
        "a trailing newline in the id": payload(root, sid=SID + "\n"),
        "a path in the id": payload(root, sid="../" + SID),
        "a non-hook event": payload(root, event="PreToolUse"),
        "not JSON": "{",
        "an id that is not a string": json.dumps({"hook_event_name": "Stop", "session_id": 7}),
    }
    for name, text in bad.items():
        before = invocations(root)
        _rc, out, _err = run(root, sd, stdin=text)
        msg = message(out)
        check("%s sweeps nothing" % name, invocations(root) == before, repr(argv_of(root)[-6:]))
        check("%s is reported" % name, msg is not None and "nothing was swept" in msg, repr(msg))
    os.remove(os.path.join(root, ".claude", "projects", "-slug", SID + ".jsonl"))
    run(root, sd, stdin=payload(root, transcript=outside))
    check("a transcript_path outside the projects root is never swept", outside not in argv_of(root))


def case_a_symlinked_session_dir_is_not_followed(root):
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    elsewhere = os.path.join(root, "elsewhere")
    os.makedirs(elsewhere)
    sibling = os.path.join(root, ".claude", "projects", "-slug", SID)
    os.rmdir(sibling)
    os.symlink(elsewhere, sibling)
    run(root, sd)
    args = argv_of(root)
    check("control: the transcript itself was swept",
          os.path.join(root, ".claude", "projects", "-slug", SID + ".jsonl") in args, repr(args))
    check("a symlinked session directory is not a sweep root", sibling not in args and elsewhere not in args, repr(args))


def case_an_exempt_ancestor_drops_the_session_path(root):
    marked = os.path.join(root, "marked")
    sd = stage(marked, stdout=CLEAN_SUMMARY, rc=0)
    open(os.path.join(marked, ".claude", "projects", "-slug", ".redacto-exempt"), "w").close()
    scratch_dir = os.path.join(marked, "scratch", "claude-%d" % os.getuid(), "-launch", SID)
    os.makedirs(scratch_dir)
    os.makedirs(os.path.join(marked, "scratch", "claude-%d" % os.getuid(), "-launch", ".git"))
    run(marked, sd)
    args = argv_of(marked)
    check("a .redacto-exempt beside the transcript exempts it",
          os.path.join(marked, ".claude", "projects", "-slug", SID + ".jsonl") not in args, repr(args))
    check("a .git above the scratch session dir exempts it", scratch_dir not in args, repr(args))

    plain = os.path.join(root, "plain")
    sd = stage(plain, stdout=CLEAN_SUMMARY, rc=0)
    plain_scratch = os.path.join(plain, "scratch", "claude-%d" % os.getuid(), "-launch", SID)
    os.makedirs(plain_scratch)
    run(plain, sd)
    args = argv_of(plain)
    check("control: without markers the transcript is swept",
          os.path.join(plain, ".claude", "projects", "-slug", SID + ".jsonl") in args, repr(args))
    check("control: without markers the scratch dir is swept", plain_scratch in args, repr(args))


def wait_for(predicate, secs):
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.25)
    return predicate()


def read_or_none(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def case_session_end_hands_off_to_a_detached_pass(root):
    """SessionEnd gets 1.5 s from Claude Code and its output is discarded, so the hook must return
    at once and the pass it starts must report somewhere a person can read."""
    for name, without in (("perl", ()), ("python fallback", ("perl",))):
        sub = os.path.join(root, name.replace(" ", "-"))
        sd = stage(sub, stdout=FOUND_SUMMARY, rc=0)
        env = hook_env(sub, {"PATH": make_bin(sub, "bin-end", without=without)})
        start = time.monotonic()
        proc = subprocess.run([BASH, os.path.join(sd, "redacto-log-sweep.sh")], input=payload(sub, event="SessionEnd"),
                              capture_output=True, text=True, env=env, timeout=60)
        elapsed = time.monotonic() - start
        check("the SessionEnd hook exits 0 with no output (%s)" % name, proc.returncode == 0 and proc.stdout == "",
              repr((proc.returncode, proc.stdout, proc.stderr)))
        if name == "perl":
            check("the SessionEnd hook returns inside the 1.5 s budget", elapsed < 1.5, "%.2fs" % elapsed)
        log = os.path.join(sub, ".local", "state", "redacto", "sweep.log")
        found = wait_for(lambda: "7 total redaction(s)" in (read_or_none(log) or ""), 40)
        check("the detached pass swept and logged its findings (%s)" % name, found and invocations(sub) == 1,
              repr(read_or_none(log)))


# ---- the real sink lists ----

def case_real_sink_list_omits_absent_directories(root):
    """redacto_sink_paths must not name a directory Claude Code has not created yet: the
    CLI counts an absent root as trouble and exits 1 with an all-zero summary."""
    home = os.path.join(root, "home")
    os.makedirs(os.path.join(home, ".claude", "projects"))
    out = subprocess.run(
        [BASH, "-c", 'source "$1"; redacto_sink_paths', "_", SINKS],
        capture_output=True, text=True, env=sink_env(home),
    ).stdout
    lines = out.splitlines()
    check("an existing sink is listed", os.path.join(home, ".claude", "projects") in lines, out)
    for absent in ("paste-cache", "file-history", "backups", "local"):
        check("absent %s is omitted" % absent,
              os.path.join(home, ".claude", absent) not in lines, out)


def case_real_sink_list_finds_rtk_on_both_platforms(root):
    home = os.path.join(root, "home2")
    mac = os.path.join(home, "Library", "Application Support", "rtk", "tee")
    xdg = os.path.join(home, ".local", "share", "rtk", "tee")
    custom = os.path.join(root, "xdg-elsewhere", "rtk", "tee")
    for d in (mac, xdg, custom):
        os.makedirs(d)
    out = subprocess.run(
        [BASH, "-c", 'source "$1"; redacto_sink_paths', "_", SINKS],
        capture_output=True, text=True, env=sink_env(home),
    ).stdout
    check("the macOS rtk tee mirror is swept", mac in out.splitlines(), out)
    check("the XDG default rtk tee mirror is swept", xdg in out.splitlines(), out)
    out2 = subprocess.run(
        [BASH, "-c", 'source "$1"; redacto_sink_paths', "_", SINKS],
        capture_output=True, text=True,
        env=sink_env(home, XDG_DATA_HOME=os.path.dirname(os.path.dirname(custom))),
    ).stdout
    check("XDG_DATA_HOME redirects the probe rather than being ignored", custom in out2.splitlines(), out2)
    check("the default location is not also swept once XDG_DATA_HOME points elsewhere",
          xdg not in out2.splitlines(), out2)


def case_real_sink_list_emits_no_phantom_empty_path(root):
    """printf with an empty array prints one blank line, which the caller reads as a sink named
    "" and redacto then counts as a root that does not exist. Branching on whether the real
    scratchpad happens to exist would skip this on every machine that has run Claude Code, so
    `id` is stubbed to an unused uid and the empty case is forced."""
    home = os.path.join(root, "home3")
    os.makedirs(home)
    bindir = make_bin(root, "fakeid")
    unused = 999_997
    while os.path.isdir("/tmp/claude-%d" % unused):
        unused -= 1
    os.remove(os.path.join(bindir, "id"))
    write_exec(os.path.join(bindir, "id"), "#!/usr/bin/env bash\nprintf '%s' " + str(unused) + "\n")
    env = sink_env(home, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
    proc = subprocess.run([BASH, "-c", 'source "$1"; redacto_sink_paths', "_", SINKS],
                          capture_output=True, text=True, env=env)
    check("control: the forced-empty fixture really has no scratchpad",
          not os.path.isdir("/tmp/claude-%d" % unused))
    check("with no sinks at all the output is empty, not a blank line", proc.stdout == "", repr(proc.stdout))
    check("no blank line is emitted as a sink path", "" not in proc.stdout.splitlines(), repr(proc.stdout))


def _real_excludes(home, *roots):
    return subprocess.run(
        [BASH, "-c", 'source "$1"; shift; redacto_sink_excludes "$@"', "_", SINKS] + list(roots),
        capture_output=True, text=True, env=sink_env(home),
    ).stdout.splitlines()


def case_real_excludes_skip_git_work_trees(root):
    """A checkout under a sink is not a log: rewriting it corrupted a scanner's own test
    fixtures in a clone under the session scratchpad. A clone's .git is a directory and a
    worktree's is a file, and the scratchpad's own prefix already spends three levels."""
    home = os.path.join(root, "home")
    local = os.path.join(home, ".claude", "local")
    clone = os.path.join(local, "clone")
    worktree = os.path.join(local, "wt")
    deep = os.path.join(local, "slug", "session", "scratchpad", "repos", "deep")
    notes = os.path.join(local, "notes")
    for d in (os.path.join(clone, ".git"), worktree, os.path.join(deep, ".git"), notes):
        os.makedirs(d)
    with open(os.path.join(worktree, ".git"), "w", encoding="utf-8") as fh:
        fh.write("gitdir: /elsewhere/.git/worktrees/wt\n")
    globs = _real_excludes(home)
    check("a clone below a root is excluded", clone + "/*" in globs, "\n".join(globs))
    check("a worktree (.git file) below a root is excluded", worktree + "/*" in globs, "\n".join(globs))
    check("a work tree at scratchpad depth is found", deep + "/*" in globs, "\n".join(globs))
    check("control: a plain directory is still swept", notes + "/*" not in globs, "\n".join(globs))


def case_real_excludes_still_sweep_a_root_that_is_a_work_tree(root):
    """mindepth 2: a root that is itself a repository holds local-only content, so only
    checkouts below it are skipped — never the root."""
    home = os.path.join(root, "home")
    local = os.path.join(home, ".claude", "local")
    os.makedirs(os.path.join(local, ".git"))
    globs = _real_excludes(home)
    check("a root with its own .git is not excluded", local + "/*" not in globs, "\n".join(globs))


def case_real_excludes_find_a_marker_at_scratchpad_depth(root):
    home = os.path.join(root, "home")
    fixtures = os.path.join(home, ".claude", "local", "slug", "session", "scratchpad", "a", "fixtures")
    os.makedirs(fixtures)
    open(os.path.join(fixtures, ".redacto-exempt"), "w").close()
    globs = _real_excludes(home)
    check("a .redacto-exempt marker six levels down is honored", fixtures + "/*" in globs, "\n".join(globs))


def case_real_excludes_escape_glob_characters(root):
    """A [ or * in a directory name is glob syntax to both matchers, so an unescaped exemption
    either missed its own directory or excluded others."""
    home = os.path.join(root, "home")
    odd = os.path.join(home, ".claude", "local", "fix[1]*")
    os.makedirs(odd)
    open(os.path.join(odd, ".redacto-exempt"), "w").close()
    globs = _real_excludes(home)
    check("glob characters in an exempt directory's name are escaped",
          os.path.join(home, ".claude", "local", "fix[[]1[]][*]") + "/*" in globs, "\n".join(globs))


def case_real_excludes_take_explicit_roots(root):
    home = os.path.join(root, "home")
    inside = os.path.join(root, "session", "scratchpad", "fixtures")
    outside = os.path.join(home, ".claude", "local", "fixtures")
    for d in (inside, outside):
        os.makedirs(d)
        open(os.path.join(d, ".redacto-exempt"), "w").close()
    globs = _real_excludes(home, os.path.join(root, "session"))
    check("explicit roots are searched", inside + "/*" in globs, "\n".join(globs))
    check("explicit roots replace the default ones", outside + "/*" not in globs, "\n".join(globs))


def main():
    cases = [v for k, v in sorted(globals().items()) if k.startswith("case_")]
    for case in cases:
        root = tempfile.mkdtemp(prefix="probe-log-sweep-")
        try:
            case(root)
        finally:
            shutil.rmtree(root, ignore_errors=True)
    check("no case hit a tool missing from the fixture PATH",
          not MISSING_TOOL, "; ".join(sorted(set(MISSING_TOOL))[:3]))
    print("\n%d control(s) failed" % len(FAILURES) if FAILURES else "\nall controls pass")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
