# Changelog

## [Unreleased]

- **Fixed**: a redacting write no longer drops the file's mode. `write_atomically`
  created the temp file with `std::fs::write` — born with the umask default — and
  renamed it over the original, so a `0600` log came back `0644`. Measured on a
  real install: `~/.claude/history.jsonl` and every transcript under
  `~/.claude/projects` are `0600`, umask is `022`, and a write-temp-then-rename
  cycle turns `600` into `644`. The sweep was therefore making exactly the files
  that had held pasted secrets group- and world-readable, every run. The image
  sweep already preserved mode via `os.fchmod`; nothing in the crate did.
  Regression test asserts `0o600` as a literal rather than against the mode read
  back, and fails `left: 420, right: 384` with the fix removed.
- **Fixed**: the `SessionStart` hook discarded PEM-only findings. Its
  clear-if-nothing-happened check tested redactions, validation failures and
  unsafe lines, but not the unresolved-PEM-marker count carried on the same
  summary line — contradicting `report()`, which counts an unresolved orphan as
  not-clean and exits 1 for it.
- **Fixed**: a crashing binary was indistinguishable from a clean sweep. The
  summary was captured by piping into `grep`, which discards the exit status, and
  a panic carries no `redacto:` prefix to survive the filter, so every count
  defaulted to zero and the hook exited 0 with no output. Output and status are
  captured separately now. Note the subtlety: a non-zero exit is *not* proof of
  failure, since `report()` exits 1 on a completed-but-not-clean run — the
  presence of a summary line is what distinguishes the two, and it is captured
  before the zero-count blanking so a real finding is never overwritten by a
  false failure message.
- **Fixed**: the same crash-reads-as-clean trap on the image half of the hook.
  `image-carrier-sweep.py`'s output was piped straight into `grep`, and an
  uncaught exception carries no `image-carrier-sweep` prefix, so a traceback was
  filtered away and the sweep reported nothing — for the pass that handles
  screenshot-borne secrets, which no text scan can see. `main()` has a single
  exit path (`return 0`), so any non-zero status is a crash; output and status
  are captured separately and the failure is reported with the traceback's last
  lines. `shellcheck -o all` flags this line as SC2312, the same masked-status
  family as the SC2155 findings below.
- **Fixed**: `shellcheck -x` findings in the hook scripts — SC1091 in
  `redacto-log-sweep.sh` (sourcing a sibling by `$DIR`, resolved with
  `source-path=SCRIPTDIR` rather than a literal path, so the directive survives
  being vendored elsewhere) and SC2155 twice in `redacto-sinks.sh`, where
  `local scratch="/tmp/claude-$(id -u)"` masked the command substitution's exit
  status. Behaviour-neutral: all four sink functions emit byte-identical output
  before and after. `shellcheck -x` now runs in CI beside `bash -n`, which
  catches syntax only and passed on all three of these.
- **Fixed**: the plugin install note recommended `cargo install --path .`
  without `--locked`, so the packaged `Cargo.lock` was ignored and all 61
  dependencies re-resolved from crates.io at install time, build scripts
  included — for a binary a `SessionStart` hook then runs unattended over the
  local log sinks.

- **Added**: `scripts/image-carrier-sweep.py`, wired into the plugin's
  `SessionStart` hook. A secret pasted as a screenshot was invisible to the
  text sweep, and the run reported the corpus clean — the strongest form of
  the failure this tool exists to prevent. The carrier also lands in two
  sinks at once (`~/.claude/image-cache/` and a byte-identical base64 copy
  inlined in the transcript), so removing either alone leaves a live copy.
  The new pass handles both together: image payloads older than
  `--max-age-hours` (default 24) become a 1×1 transparent PNG, and cache
  files past the same window are deleted. Blanket by age deliberately —
  without OCR nothing distinguishes an image holding a secret from one
  holding a chart, and the alternative fails silently. Covers both
  `source.data` and `toolUseResult.file.base64`; stripping only the first
  leaves the image fully recoverable while looking scrubbed. Guarded by a
  live-window skip, a per-record structural-equality check that aborts the
  whole rewrite rather than writing a partial one, a line-count assertion,
  and atomic replace. 49 controls in `tests/probe-image-carrier-sweep.py`,
  now run in CI alongside `bash -n` on the hook scripts.
- **Added**: `redacto_sink_excludes` and a `.redacto-exempt` opt-out marker.
  A directory whose secret-shaped literals *are* its content — a detector's
  patterns, its test corpora, a control fixture — can now exclude its own
  subtree. Without it, sweeping a working checkout silently rewrites the
  fixtures that prove a scanner works. Also excludes VCS, build output, and
  vendored dependency trees by default. The marker binds both stages: the
  same globs reach `image-carrier-sweep.py` via `--exclude`, so an exempt
  fixture holding a deliberate inline image keeps it. An exclusion honoured
  by only one stage would destroy precisely what it appeared to protect.
- **Added**: `~/.claude/local` and the session scratchpad
  (`/tmp/claude-$(id -u)`) to the swept sinks. Both accumulate fetched
  values and raw command dumps as ordinary files; neither was covered.

- **Fixed**: four rules could consume adjacent text under `--write`.
  `gitlab-pat` (`glpat-[\w-]{20,}`), `slack-bot-token` (trailing
  `[a-zA-Z0-9-]*`) and `github-oauth` (`{36,}`) were open-ended, and
  `slack-webhook-url` matched a single `[A-Za-z0-9+/]{43,56}` span with the
  path separator *inside* the charset. Measured before the fix: a
  `GITLAB_TOKEN:` line lost `-prod-runner-shared-config`, and a real
  `services/` webhook URL lost the following `/archive/2026` path. Each rule
  is now left-anchored and bounded to the vendor's real token length, with
  the webhook path bounded per segment.
- **Fixed**: a routable GitLab PAT was half-redacted. The classic rule
  consumed the body greedily up to the `.` and left `.<9 chars>` behind; a
  `gitlab-pat-routable` rule now runs ahead of it and redacts the token whole.
  Its body is alphanumeric-only and its checksum `\b`-terminated: upstream
  relies on an entropy gate this crate does not have, and with `-`/`_`
  admitted the greedy body spanned ordinary kebab-case prose as far as any
  dotted nine-letter word and deleted all of it.
- **Added**: token shapes that were passing through in cleartext —
  `slack-legacy-bot-token` (two-segment `xoxb-`), `slack-legacy-token`
  (`xoxs-`/`xoxo-`) and `slack-legacy-workspace-token` (`xoxa-`/`xoxr-`,
  documented five-segment form only, since gitleaks' looser variant relies
  on an entropy gate this crate does not have).
- **Behaviour change**: `slack-bot-token` now requires a secret segment of
  at least 16 chars. `xoxb-<digits>-<digits>` with a shorter or absent third
  segment was redacted by the previous release and is not a usable
  credential, but the narrowing is real and is recorded here rather than
  discovered later.
- **Known, unchanged**: with no lookahead, a ranged body cannot both always
  match and never over-consume, so every ranged rule can run past a real token
  into adjacent *in-charset* text by up to the width of its range —
  `slack-user-token` by 2 chars past a real 32-char tail, `slack-bot-token` by
  up to 8, `slack-legacy-bot-token` by up to 2. Narrowing a charset instead
  drops any real token containing that character — measured in both directions
  for `slack-user-token`. Tests pin the current behaviour rather than implying
  it is absent.
- **Testing**: the five registered-but-untested rules (`slack-bot-token`,
  `gitlab-pat`, `github-oauth`, `slack-webhook-url`,
  `clickhouse-cloud-api-secret-key`) now have coverage, and the five ranged
  Slack rules assert both ends of their tail bound by exact output — asserting
  only that the match *stops by* the cap is satisfied by any shorter match too,
  which would let a cap be lowered silently and truncate a live credential.
  Still unasserted, and listed so the next change knows: the numeric-segment
  ceilings, `gitlab-pat-routable`'s 300-char body cap, `slack-webhook-url`'s
  six path-segment quantifiers, and left-anchor
  or alternation coverage for `aws-access-token` (including its `ASIA`
  temporary-credential branch), `stripe-access-token` and `jwt`.

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
