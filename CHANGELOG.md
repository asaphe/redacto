# Changelog

## [Unreleased]

Found via real-world testing against a large personal Claude Code log
corpus (2.86GB, 3400+ files) — first genuine end-to-end validation beyond
synthetic fixtures:

- **`--patterns secrets|infra|all` flag, default `secrets`.** Infra-ID
  patterns produced 3.84 million redactions when applied by default against
  real operational logs (every file path and session/message ID matches
  them) — appropriate for their original purpose (sanitizing content before
  sharing), destructive to a log's own searchability otherwise. PEM
  structural handling now only runs when the selection includes secrets.
- **Fixed**: `FileKind` detection trusted the file extension unconditionally;
  a real `.json`-extension file held JSONL-shaped content (multiple
  newline-delimited records) and failed whole-file JSON validation forever,
  silently blocking its redactions at exit code 0. Detection now sniffs
  actual content shape when the extension-implied parse fails, falling back
  to JSONL or plain-text handling as the content actually warrants.
- **Added**: a known-benign-value filter (currently: AWS's own published
  `AKIAIOSFODNN7EXAMPLE`) — confirmed via the same real-world test to appear
  constantly in code/docs discussing secret detection, never as a real leak.
- Confirmed via the same real-world pass: zero validation failures, zero
  unsafe JSONL lines, zero PEM structural-ambiguity aborts, and the one
  genuine pre-existing finding (real AWS temporary credentials in a file the
  original manual secret-scrub effort had explicitly deferred) still
  surfaces correctly — the noise-reduction fixes don't hide real findings.

## v0.1.0

Initial implementation:
- Secret-value pattern engine (aws-access-token, jwt, private-key,
  slack-bot-token, gitlab-pat, github-oauth, slack-webhook-url,
  clickhouse-cloud-api-secret-key), adapted from gitleaks' MIT default
  ruleset.
- Infrastructure-identifier pattern engine (AWS resource/instance IDs,
  Route53 zone IDs, AWS account IDs, home paths, GitHub org/repo, UUIDs,
  `--repo` flags).
- PEM structural handler: LIFO BEGIN/END stack-match with containment-merge,
  never crosses a physical-line boundary.
- Per-filetype validity gate (JSON/JSONL) before any write.
- Watermark-based incremental scanning, with a live-file exclusion window.
- CLI: `redacto <path>... [--write] [--config] [--exclude]`.
- Custom pattern support via `redacto.toml`.
