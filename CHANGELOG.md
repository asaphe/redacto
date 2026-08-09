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
- **Added**: nine prefixed vendor token patterns — `github-pat` (`ghp_`),
  `github-app-token` (`ghu_`/`ghs_`/`ghr_`), `github-fine-grained-pat`,
  `slack-user-token`, `slack-app-token`, `google-api-key`, `anthropic-api-key`,
  `npm-access-token` and `docker-pat`. The set covered `gho_` but not `ghp_`,
  so the GitHub token a developer actually pastes went undetected; a scan of a
  real log corpus confirmed live tokens of several of these types that every
  prior run had reported clean. Provenance is not uniform and the differences
  matter: the GitHub, Google, npm and Slack rules follow gitleaks' shapes;
  `anthropic-api-key` follows gitleaks' `api03`/`admin01` form including its
  required infix and `AA` terminator; `docker-pat` has **no** gitleaks
  equivalent and is pinned to Docker Hub's fixed 27-character body.
- **Every one of the nine is left-anchored and pinned to the vendor's exact
  body length.** Detection tooling can afford loose bounds because a human
  triages every hit; an in-place rewriter cannot, so the same looseness is a
  silent unrecoverable edit. Two concrete failures caught in review before
  release: an unanchored fixed-length window over a base64 alphabet collides
  inside ordinary base64 — brute-forcing 427MB of random base64 produced 10
  natural collisions, one of which truncated a PNG payload inside a transcript
  record, and the JSON validity gate cannot catch that because the damaged
  result is still valid JSON — and a `-` in a body charset with no left anchor
  matches ordinary kebab-case prose after any word ending in `sk`. Where
  gitleaks wraps a rule in its `\b(...)` boundary helper, that anchor is
  reproduced here rather than dropped.
- **`--version` now reports the git revision the binary was built from**, e.g.
  `redacto 0.1.0 (21af8f70fdfc)`, with a `-dirty` suffix when the working tree
  had uncommitted changes. A bare `0.1.0` is identical across every build, so an
  install predating a fix could not be told apart from a current one — an install
  built before the PEM-orphan fix stayed live and undetected, and the only way to
  check was grepping the binary for a symbol. A build with no git metadata
  (crates.io, tarball) reports `unknown` rather than a fabricated revision.
- **Fixed**: the README's built-in pattern list named only the original eight
  secret rules, omitting the nine added since.
- A standalone AWS secret-access-key rule stays deferred: a bare 40-char
  base64 string has no self-delimiting shape and needs the keyword-context
  `generic-api-key` rule rather than a pattern that would over-match under
  `--write`.

- **Fixed**: `--version` could report a revision the binary was not built from.
  A copy vendored into an unrelated repository was stamped with *that*
  repository's HEAD — `git ls-files` only rules out an *untracked* copy, and a
  committed `vendor/` subdirectory is tracked — so the repo root must now also
  be this crate's own manifest directory, and such a build reports `unknown`.
  A crate packaged from a modified tree was stamped with a clean-looking sha;
  cargo records `"dirty": true` in `.cargo_vcs_info.json` and that now surfaces
  as a `-dirty` suffix rather than asserting a provenance the artifact lacks.
- **Fixed**: `.cargo_vcs_info.json` is parsed as JSON instead of split on the
  `"sha1"` key. Splitting took the first occurrence anywhere in the document,
  so a sibling object yielded a sha from the wrong one and a half-written file
  still answered confidently; the short form is also truncated by character
  rather than by byte, which panicked mid-character and aborted the build.

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
