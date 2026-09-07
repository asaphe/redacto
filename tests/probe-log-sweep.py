#!/usr/bin/env python3
"""Control suite for redacto-log-sweep.sh.

The hook's only job is to distinguish three outcomes — clean, findings, and a sweep that
did not finish — and it has collapsed them into "silent" three separate times. Each case
below pins one outcome and fails loudly when it collapses again.

Usage: probe-log-sweep.py   (exit 0 = all controls pass)
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASH = shutil.which("bash") or "/bin/bash"
SWEEP = os.path.join(ROOT, "scripts", "redacto-log-sweep.sh")
SINKS = os.path.join(ROOT, "scripts", "redacto-sinks.sh")
CLEAN_SUMMARY = (
    "redacto: 0 file(s) with matches, 0 total redaction(s), 0 validation failure(s), "
    "0 file(s) with unsafe lines, 0 file(s) with unresolved PEM markers, write_mode=true"
)
FOUND_SUMMARY = (
    "redacto: 2 file(s) with matches, 7 total redaction(s), 0 validation failure(s), "
    "0 file(s) with unsafe lines, 0 file(s) with unresolved PEM markers, write_mode=true"
)
FAILURES = []


def check(name, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, ("  — " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def write_exec(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def stage(root, stdout="", stderr="", rc=0, image_body=None, sink_paths=("/sink-a",), stderr_newline=True):
    """Copy the real hook next to stubs for the three files it resolves through $DIR."""
    sd = os.path.join(root, "scripts")
    os.makedirs(sd, exist_ok=True)
    shutil.copy(SWEEP, os.path.join(sd, "redacto-log-sweep.sh"))
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
        "#!/usr/bin/env bash\ntouch %s\nprintf '%%s' %s\nprintf '%%s' %s >&2\nexit %d\n"
        % (
            _q(os.path.join(root, "invoked")),
            _q(stdout + "\n" if stdout else ""),
            _q((stderr + "\n" if stderr_newline else stderr) if stderr else ""),
            rc,
        ),
    )
    write_exec(
        os.path.join(sd, "image-carrier-sweep.py"),
        image_body if image_body is not None else "#!/usr/bin/env python3\nimport sys; sys.exit(0)\n",
    )
    return sd


def _q(text):
    return "'" + text.replace("'", "'\\''") + "'"


TOOLS = ["bash", "env", "grep", "sed", "awk", "tr", "head", "tail", "wc", "mktemp", "rm", "dirname", "touch", "cat", "id"]
# Any case whose fixture PATH lacks a tool the hook calls fails to empty output, which several
# assertions read as correct silence — so every run is screened for it instead.
MISSING_TOOL = []


def make_bin(root, name, with_python=True):
    """A PATH with no `redacto` on it: the hook falls back to `command -v redacto`, and this
    suite runs it in --write mode, so a reachable real binary would sweep the real machine."""
    bindir = os.path.join(root, name)
    os.makedirs(bindir, exist_ok=True)
    for tool in TOOLS:
        found = shutil.which(tool)
        if found and not os.path.exists(os.path.join(bindir, tool)):
            os.symlink(found, os.path.join(bindir, tool))
    # sys.executable, not which("python3"): a version-manager shim needs helpers this PATH lacks,
    # which made the suite pass or fail according to how it was launched.
    link = os.path.join(bindir, "python3")
    if with_python and not os.path.exists(link):
        os.symlink(os.path.realpath(sys.executable), link)
    return bindir


def run(root, sd, env_extra=None):
    env = dict(os.environ)
    env["HOME"] = root
    env["REDACTO_BIN"] = os.path.join(root, "stub-redacto")
    env["PATH"] = make_bin(root, "bin")
    env.update(env_extra or {})
    # Absolute: every case runs with a PATH holding only the tools the hook needs.
    proc = subprocess.run(
        [BASH, os.path.join(sd, "redacto-log-sweep.sh")],
        capture_output=True, text=True, env=env,
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
    """The systemMessage the user sees, or None when the hook stayed silent."""
    if not stdout.strip():
        return None
    return json.loads(stdout)["systemMessage"]


def case_broken_python3_still_reports(root):
    """`command -v python3` proves presence, never that it runs. A shim invoked with a stripped
    PATH, a broken install or a poisoned sitecustomize exits non-zero, and gating the encoder on
    presence dropped the entire report — the failure this hook exists to make impossible."""
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
    check("the crash still reaches the user", ok and "panicked" in msg, repr(msg))


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
    """The mirror of the crash path: with no python3 the image half never runs at all, and a
    clean text sweep then made the hook silent — indistinguishable from a full sweep that found
    nothing. A missing binary stays silent because the plugin was never opted into; this is half
    a sweep the user believes is running."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    bindir = make_bin(root, "nopy2", with_python=False)
    check("control: the fixture really has no python3", shutil.which("python3", path=bindir) is None)
    _rc, out, _err = run(root, sd, env_extra={"PATH": bindir})
    msg = message(out)
    check("a missing python3 is reported rather than passing as clean",
          msg is not None and "python3 not found" in msg, repr(out))
    check("the message says the images were not swept",
          msg is not None and "NOT swept" in msg, repr(msg))


def case_clean_run_is_silent(root):
    """The positive control comes first: `out == ""` also passes when the fixture is too broken
    to execute anything, which is exactly how a silence assertion rots into a rubber stamp."""
    loud = stage(os.path.join(root, "loud"), stdout=FOUND_SUMMARY, rc=0)
    _rc, out, err = run(os.path.join(root, "loud"), loud)
    check("control: this fixture can emit output at all", out.strip() != "", repr(err))
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    _rc, out, _err = run(root, sd)
    check("a clean sweep prints nothing at all", out == "", repr(out))


def case_findings_are_reported(root):
    """rc=0, because `total_redactions` is not in report()'s trouble predicate (main.rs:168-171):
    a completed run that redacted cleanly exits 0. Pairing this summary with rc=1 pins a state
    the CLI cannot produce."""
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
    check("an empty sink list stays silent", out == "", repr(out))
    check("an empty sink list does not invoke the binary",
          not os.path.exists(os.path.join(root, "invoked")))


def case_no_sinks_still_runs_the_image_sweep(root):
    """The image sinks are a separate list, so an empty text-sink list must not gate them —
    a machine with only an image cache would otherwise leave screenshot payloads in place."""
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0, sink_paths=(),
               image_body="#!/usr/bin/env python3\nprint('image-carrier-sweep: 3 payload(s) in 1 transcript(s)')\n")
    _rc, out, _err = run(root, sd)
    msg = message(out)
    check("the image sweep runs even with no text sinks",
          msg is not None and "3 payload(s)" in msg, repr(out))
    check("the text sweep is still skipped", not os.path.exists(os.path.join(root, "invoked")))


def case_missing_binary_is_inert(root):
    sd = stage(root, stdout=CLEAN_SUMMARY, rc=0)
    check("the fixture PATH cannot reach a real redacto",
          shutil.which("redacto", path=make_bin(root, "bin")) is None)
    _rc, out, _err = run(root, sd, env_extra={"REDACTO_BIN": os.path.join(root, "nope")})
    check("no binary means no output", out == "", repr(out))


def case_fallback_json_survives_control_characters(root):
    """The python3-less branch hand-rolls its escaping; a raw tab or CR there is illegal
    inside a JSON string and silently breaks the hook's output."""
    bindir = make_bin(root, "nopy", with_python=False)
    check("the no-python3 fixture really has no python3", shutil.which("python3", path=bindir) is None)
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
