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
single regex), Slack bot/user/app tokens, GitLab PATs, GitHub OAuth, personal,
app/refresh and fine-grained tokens, Google API keys, Anthropic API keys, npm
access tokens, Docker Hub PATs, Stripe access tokens, Slack webhook URLs, plus
one project-specific ClickHouse Cloud API key rule.

The GitHub, Google, Anthropic, npm, Docker and ClickHouse rules are
left-anchored and pinned to the vendor's exact body length. That is stricter
than gitleaks, deliberately: gitleaks reports findings for a human to triage,
whereas this tool rewrites the file, so a loose bound is a silent unrecoverable
edit rather than a false positive someone dismisses.

The older `gho_`, `glpat-`, `xoxb-` and Stripe rules still carry open-ended
quantifiers and, for the first three, no left anchor — so they can consume
adjacent text (a `glpat-` token followed by kebab-case prose takes the whole
run). Tightening them to the same standard is outstanding.

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

## How it's different from just running gitleaks

gitleaks' own `--redact` flag only masks values in its **findings report**,
not the scanned file itself — and the project's own README states it's
feature-frozen (security patches only). redacto reuses gitleaks' pattern
definitions as a starting point but owns the parts gitleaks doesn't do:
in-place rewriting, incremental scanning, and safe multi-line handling.

## Claude Code plugin

This repo doubles as a Claude Code plugin (`.claude-plugin/`) that runs an
incremental `redacto` sweep as a `SessionStart` hook, over the local Claude
Code log sinks that tend to accumulate secrets during normal work: session
transcripts (`~/.claude/projects`), `paste-cache/`, `file-history/`,
`backups/`, `history.jsonl` (+ dated rotations), and RTK's `tee/` mirror if
present.

Install:

```sh
claude plugin marketplace add asaphe/redacto
claude plugin install redacto@redacto
```

The plugin only wires the hook — it still calls the `redacto` binary on
`PATH`, so `cargo install --path .` (or however you install the CLI) is
still required. The hook is a no-op if `redacto` isn't found.

For a tighter sweep interval than "once per session start," pair this with
your own cron/launchd invocation of `redacto` against the same paths (see
[Built-in patterns](#built-in-patterns-v01) above on why this isn't a
built-in daemon mode).

## License

Apache-2.0.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — sign off your commits
(`git commit -s`), no CLA required.
