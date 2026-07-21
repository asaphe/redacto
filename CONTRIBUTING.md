# Contributing to redacto

Thanks for considering a contribution.

## Developer Certificate of Origin (DCO)

Contributions require a sign-off, not a signed CLA. Add `-s` to your commits:

```sh
git commit -s -m "fix: ..."
```

This adds a `Signed-off-by` trailer certifying you have the right to submit
the change under this project's license (Apache-2.0). See
[developercertificate.org](https://developercertificate.org/) for the exact
text you're certifying.

## Before opening a PR

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Adding a new pattern

Secret-value patterns live in `src/patterns/secrets.rs`, infrastructure
identifiers in `src/patterns/infra_ids.rs`. Each is a `regex::Regex` plus a
`Pattern::simple` / `Pattern::literal` / `Pattern::with_fn` constructor — see
existing patterns for the shape. New patterns need at least one unit test
demonstrating a real match and one demonstrating a plausible false-positive
that's correctly *not* matched.

Structural (multi-line) secrets go in `src/structural/` following the PEM
handler's model: never let a redaction cross a physical-line boundary, and
distinguish safe containment/nesting from genuine ambiguity (abort and flag
the latter rather than guessing).

## Reporting a security issue

If you find a pattern that fails to redact a real secret, or a case where
redaction could corrupt a file, please open an issue — this is a security
tool, so false negatives and corruption bugs are treated as high priority.
