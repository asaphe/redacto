# redacto

Redacts secrets and sanitizes infrastructure identifiers from files **in
place** — safely, repeatedly, with validity-gated writes.

## Why this exists

Most secret scanners (detect-secrets, truffleHog, git-secrets, gitleaks,
ggshield) are one-shot CI/pre-commit tools: they detect and report, they
don't rewrite the file in place, and several explicitly document multi-line
secrets as out of scope. The one tool found doing in-place redaction
(`msantos/redact`) is a small, single-author project with no incremental
scanning and no write-validity gating.

**redacto's actual value isn't the pattern list** (that part is adapted from
gitleaks' MIT-licensed default ruleset plus infra-identifier rules) — it's
the combination that doesn't exist elsewhere:

1. **Repeatable/incremental** — safe to invoke on a schedule (cron/launchd)
   against files that grow over time; a watermark skips files that haven't
   changed since the last successful scan.
2. **Validity-gated writes** — a redaction is only ever written if the
   result is still structurally valid (every line of a `.jsonl` file still
   parses as JSON, a whole `.json` file still parses). A redaction that
   would corrupt the file is reported and left untouched, not forced.
3. **Structurally safe on multi-line secrets** — PEM private-key blocks are
   handled with a LIFO stack-match: adjacent and nested blocks in the same
   record are redacted correctly (proper nesting collapses safely to the
   outer span), and a redaction can never cross a physical-line boundary —
   the one guarantee that rules out the "jumped past the real END marker"
   failure mode a naive multi-line regex is prone to.

One explicit design position: continuous log sanitization is usually best
solved at the pipeline layer (redact in-stream before the file is ever
written). **redacto is for when the writer isn't yours to change** — a
third-party tool's own log format, a vendor CLI's output cache, anything you
can't intercept at the source.

## Usage

```sh
redacto <path>... [--write] [--patterns secrets|infra|all] [--config redacto.toml] [--exclude <glob>]...
```

Without `--write`, redacto reports what it would redact and changes
nothing. Files modified within the last 5 minutes (`--live-window-secs`) are
skipped as possibly still being written.

### Three ways a scan reports clean when it did not run

Each of these produces a clean-looking summary rather than an error, so
nothing prompts you to look twice. They matter most when the scan is the gate
before publishing something.

**A file that once scanned clean is skipped, even under wider patterns.** The
watermark records a path when the scan found nothing (or when `--write`
finished redacting it), keyed on mtime and size. A later scan of that file,
unmodified, is skipped as unchanged — including a scan you widened. Scanning
with `--patterns secrets`, then re-scanning the same file with `--patterns
all`, reports clean: the second run never opened it, and the infra IDs a fresh
state dir finds are invisible. The same applies after upgrading to a release
that adds a pattern.

A file that *matched* in report-only mode is not recorded, so re-scanning it
does re-scan. The trap is one-directional and lands on exactly the files you
have most reason to believe are fine.

Pass `--state-dir "$(mktemp -d)"` whenever the pattern set changed, or whenever
the answer needs to come from the file rather than from a previous verdict.

**`--live-window-secs 0` is required when scanning a file you just wrote.**
The default 300-second window skips recently-modified files, so scanning
something you created seconds ago reports zero findings because it never
opened it. A pre-commit or pre-publish check must pass `--live-window-secs 0`,
or it silently approves the file it was written to inspect.

**A known-benign value is subtracted before the report.** `KNOWN_BENIGN_VALUES`
removes the canonical AWS documentation key and similar published examples. A
control probe built from one of those values therefore returns "clean" whether
or not the scanner works — the probe proves nothing, and the null reads as a
pass. Build controls from a freshly generated value instead.

`--patterns` defaults to `secrets` — real-world testing against a large
personal log corpus confirmed the infra-identifier patterns are
appropriate for sanitizing content *before sharing it* (their original
purpose), but destructive to a log's own usefulness if applied by default:
every file path and session/message ID in normal operational logs matches
them, at a scale (millions of redactions) that makes the log unsearchable
afterward. Pass `--patterns all` explicitly when you actually want infra-ID
sanitization too (e.g. preparing something to post publicly), or `--patterns
infra` for infra-IDs only.

```sh
# Report only, secrets patterns (the safe default for your own logs)
redacto /var/log/app/*.jsonl

# Actually redact secrets, with custom patterns
redacto --write --config redacto.toml /var/log/app/

# Sanitizing something before sharing externally — secrets + infra IDs
redacto --write --patterns all ./report-to-share.md
```

`redacto.toml`:

```toml
[patterns]
custom = [
  "my-internal-hostname-pattern",
]
```

## Built-in patterns (v0.1)

**Secret values** (mostly adapted from gitleaks' MIT default ruleset):
AWS access keys, JWTs, private-key/PEM blocks (structural handler, not a
single regex), Slack tokens (bot, legacy bot, user, app, legacy and legacy
workspace), GitLab PATs (classic and routable), GitHub OAuth, personal,
app/refresh and fine-grained tokens, Google API keys, Anthropic API keys, npm
access tokens, Docker Hub PATs, Stripe access tokens, Slack webhook URLs, plus
one project-specific ClickHouse Cloud API key rule.

Every prefixed rule is left-anchored. That is stricter than gitleaks,
deliberately: gitleaks reports findings for a human to triage, whereas this
tool rewrites the file, so a loose bound is a silent unrecoverable edit rather
than a false positive someone dismisses.

Bounds are per-rule, and the exceptions are deliberate rather than oversights.
Most prefixed rules are pinned to the vendor's exact body length, or to a range
where that length genuinely varies. Two end in an open quantifier —
`stripe-access-token` and `jwt` — because a cap would leave the tail of a live
credential sitting in the file. Rules whose charset admits `-`, `_` or `.`
(`gitlab-pat`, `gitlab-pat-routable`, `google-api-key`, `anthropic-api-key`,
`docker-pat`, `github-fine-grained-pat`, `slack-user-token`) rely on an exact
or ranged length instead, since for them an open quantifier would run into
adjacent prose rather than into more of the same character class.

Two known gaps, both measured and both with a test pinning the current
behaviour. `jwt` is open-ended *and* delimiter-permissive — its body admits
`/`, `-` and `_` — so a JWT appearing as a URL or filesystem path segment takes
the following segment with it; it is the one rule where the two properties
combine. And within the secrets set, `aws-access-token` and
`clickhouse-cloud-api-secret-key` are the only rules ending in `\b`: butted
directly against an alphanumeric they match nothing at all, so that credential
survives the pass. Five infrastructure-identifier rules (`aws-resource-id`,
`aws-instance-id`, `route53-zone-id`, `aws-account-id`, `uuid`) end in `\b`
too and share that blind spot — worth knowing before relying on
`--patterns all` to sanitize something for publication.

**Infrastructure identifiers**: AWS resource IDs (vpc/sg/subnet/etc.), EC2
instance IDs, Route53 zone IDs, AWS account IDs, absolute home paths,
GitHub org/repo names, UUIDs, `--repo` CLI flags.

**Known-benign values are never flagged**: vendor-published example
credentials (currently: AWS's own `AKIAIOSFODNN7EXAMPLE`) are excluded —
confirmed via real-world testing to appear constantly in code/docs
discussing secret detection, never as an actual leaked credential.

**Deliberately deferred** (documented, not hidden): `curl-auth-header` and
`linkedin-client-id` (gitleaks' real rules are complex multi-branch
parsers — not yet safely translated), a `generic-api-key` keyword-context
heuristic rule, a built-in daemon/watch mode (use an external
cron/launchd invocation instead — that's what the watermark is for), and
Homebrew/crates.io publishing automation.

Two gitleaks behaviours are deferred specifically because they lean on an
entropy gate this crate doesn't have. Its looser `xox[ar]-` workspace-token
variant matches an 8-char alphanumeric run after the prefix, which without
entropy scoring would rewrite ordinary text — only the documented five-segment
shape is matched here. And its 16-entry allowlist of published Google API keys
is not copied: adding it would commit sixteen real-shaped credential strings to
a public repository — the exact thing this tool exists to prevent — in exchange
for not redacting a vendor doc quoted in a log. `KNOWN_BENIGN_VALUES` stays
AWS-only until that trade looks better.

## How it's different from just running gitleaks

gitleaks' own `--redact` flag only masks values in its **findings report**,
not the scanned file itself — and the project's own README states it's
feature-frozen (security patches only). redacto reuses gitleaks' pattern
definitions as a starting point but owns the parts gitleaks doesn't do:
in-place rewriting, incremental scanning, and safe multi-line handling.

## Claude Code plugin

This repo doubles as a Claude Code plugin (`.claude-plugin/`) that sweeps the
local Claude Code log sinks on `SessionStart`.

Install:

```sh
claude plugin marketplace add asaphe/redacto
claude plugin install redacto@redacto
```

The plugin only wires the hook — it calls the `redacto` binary on `PATH`, so
`cargo install --locked --path .` (or however you install the CLI) is still
required. `--locked` matters here: `cargo install` ignores a packaged
`Cargo.lock` by default and every dependency is specified at major-version
granularity, so without it all 61 packages re-resolve from crates.io at install
time, build scripts included — for a binary a `SessionStart` hook then runs
unattended over the files most likely to hold a pasted secret.
The whole hook, image sweep included, is a no-op if `redacto` isn't found:
installing the plugin on its own must never start deleting anything.

For a tighter sweep interval than "once per session start," pair this with
your own cron/launchd invocation of `scripts/redacto-log-sweep.sh` (see
[Built-in patterns](#built-in-patterns-v01) above on why this isn't a
built-in daemon mode).

### How the plugin works

`scripts/redacto-sinks.sh` is the single source of truth for what gets swept,
and it declares four lists rather than one, because a sink's carrier decides
its policy:

| List | Paths | Policy |
|---|---|---|
| `redacto_sink_paths` | `~/.claude/projects`, `paste-cache/`, `file-history/`, `backups/`, `local/`, `history.jsonl` (+ dated rotations), the session scratchpad at `/tmp/claude-$(id -u)`, RTK's `tee/` mirror if present | redact in place |
| `redacto_sink_excludes` | `--exclude` globs: VCS, build output, vendored dependency trees, plus any `.redacto-exempt` subtree | never scanned |
| `redacto_transcript_roots` | `~/.claude/projects` and the scratchpad | additionally image-swept |
| `redacto_image_cache_paths` | `~/.claude/image-cache` | delete only |

Read the file rather than trusting a list quoted elsewhere — it grows, and a
stale count reads as a coverage claim. Note the third list is narrower than the
first: `history.jsonl` is a `.jsonl` file but is not image-swept, because images
are inlined into session transcripts and nothing else.

### The image carrier

A secret pasted or screenshotted into a session is invisible to a text
redactor, and the sweep does not merely miss it — it reports the corpus
clean. The carrier also lands in **two** sinks at once: the file in
`~/.claude/image-cache/`, and a byte-identical base64 copy inlined into the
transcript under `~/.claude/projects/`. Removing either alone leaves a live
copy.

`scripts/image-carrier-sweep.py` (Python 3.9+, no dependencies) handles both
in one pass. For this carrier there is no redaction, only destruction: every
inlined image payload older than the age window is replaced with a 96-char
1×1 transparent PNG — valid base64, so the record stays well-formed and the
session remains resumable — and the cache files past the same window are
deleted.

It is blanket by age on purpose. Without OCR nothing distinguishes an image
holding a secret from one holding a chart, and a sweep that silently misses
one is the failure mode this tool exists to remove. The cost is real:
legitimate screenshots in old transcripts are destroyed too. The window is
therefore short rather than exempted — `--max-age-hours` (default 24) is the
knob.

Guards, all covered by `tests/probe-image-carrier-sweep.py`:

- Files modified inside `--live-window-secs` (default 300) are skipped, and
  the file is re-`stat`ed immediately before the swap — an append that lands
  while the rewrite is in flight throws the rewrite away rather than
  truncating those records. The mtime check alone would not catch that: it is
  taken before the read, and a large transcript takes a moment to rewrite.
  A residual window remains between that final `stat` and the rename itself,
  and a same-size in-place edit with a restored mtime is not detected — both
  are narrow, and neither is the append case the guard targets.
- Both payload fields are covered — a tool-result screenshot duplicates its
  bytes into `source.data` *and* `toolUseResult.file.base64`, and stripping
  only the first leaves the image fully recoverable while looking scrubbed.
- Each rewritten record is compared against the original with every image
  payload blanked; if anything outside a payload would change, the whole file
  is left untouched. A partial rewrite is worse than a missed sweep.
- Line count is asserted; the replacement is `fsync`'d, atomically renamed,
  and the containing directory `fsync`'d, so a crash cannot leave a truncated
  transcript behind. A temp file from a killed run is reaped on the next
  sweep — it holds a partial copy of the transcript it came from.
- Symlinked transcripts are skipped. Rewriting one replaces the link with a
  regular file and leaves the real target — and its payload — untouched.
- Re-runs are no-ops via an incremental state cache, keyed on mtime and size
  *and* on a detector version. A file the sweep just rewrote is re-read once
  more on the following run before it stamps clean. Bumping that version re-opens every file: a
  payload shape the sweep could not recognise must not stay whitelisted by
  the run that failed to see it.
- Only image files are deleted from a cache directory, and only directories
  the run itself emptied are removed. Anything else sharing that directory
  survives.

Run it standalone with `--dry-run` to see what a window would remove before
committing to it:

```sh
python3 scripts/image-carrier-sweep.py --dry-run --max-age-hours 24
```

### Exempting a fixture directory

Some directories hold secret-shaped literals *as their content* — a
detector's own pattern definitions, its test corpora, a known-positive
control fixture used to prove a scanner works. Redacting those disarms the
scanner that exists to catch real leaks, which is strictly worse than the
leak.

Drop an empty `.redacto-exempt` file in such a directory and
`redacto_sink_excludes` turns it into an exclude glob for that whole subtree:

```sh
touch /path/to/fixtures/.redacto-exempt
```

The marker binds **both** stages — the hook passes the same globs to `redacto`
and to `image-carrier-sweep.py`, so an exempt directory holding a `.jsonl`
fixture with a deliberate inline image keeps that payload too. A marker that
covered only the text stage would quietly destroy exactly the fixtures it
appeared to protect.

Markers are searched up to 5 levels below each of `~/.claude/projects`,
`~/.claude/image-cache`, `~/.claude/local` and the session scratchpad — every
root either stage walks.
`image-carrier-sweep.py` also takes `--exclude GLOB` directly (repeatable,
full-path match) when run standalone.

## License

Apache-2.0.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — sign off your commits
(`git commit -s`), no CLA required.
