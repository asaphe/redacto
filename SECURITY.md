# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
**[Report a vulnerability](https://github.com/asaphe/redacto/security/advisories/new)**

Please do not open a public issue for a security report.

This is a solo-maintained project. Expect an acknowledgement within a week and a
fix or an explicit decision not to fix within a month. There is no paid support
and no SLA.

## Supported versions

Pre-1.0. Only the current `main` is supported — fixes land there rather than as
backports to a tagged release.

## What counts as a vulnerability here

redacto runs unattended. The plugin's `SessionStart` hook invokes the binary with
`--write` over local Claude Code log sinks, which are the files most likely to
hold a pasted secret. Judge a report against that, not against a library's threat
model. In scope:

- A pattern that fails to match a secret shape it claims to cover, or a code path
  where a matched secret is written back unredacted.
- Any change to a swept file's mode, ownership or location that widens who can
  read it.
- Loss or corruption of a swept file. The write path must never leave a file
  partially rewritten, and must never widen it.
- **A failure that reports as success.** A crash, a skipped path or an unreadable
  file that ends in a silent clean report is a security defect here, not a
  robustness one: it asserts the corpus is clean when it is not, which is the
  failure this tool exists to prevent.
- Anything that causes secret material to leave the machine, including through
  reported output.

Out of scope:

- Findings that require an attacker who already holds write access to your
  `~/.claude` directory, your `PATH`, or the binary itself.
- False positives. Over-redaction is a bug, not a vulnerability.
- The image sweep's deliberate blanket-by-age policy. Without OCR nothing
  distinguishes an image holding a secret from one holding a chart; the reasoning
  is in the README.
