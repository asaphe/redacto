use regex::Regex;
use std::sync::LazyLock;

use super::Pattern;

// Rust's regex crate has no lookahead, so the trailing boundary is captured (group 1) and re-emitted via $1 instead of consumed. Negated/permissive (any char, or end-of-string) rather than an allowlist: an allowlist misses every real delimiter it didn't enumerate (confirmed: OAuth callback URLs like `...&state=abc` were a total miss, not a partial one, since no-match here means the whole token goes undetected). The preceding segments are greedy, so whatever actually follows is already guaranteed not to be more token body.
const BOUNDARY: &str = r"(?:([\s\S])|\z)";

static AWS_ACCESS_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b").unwrap());

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\bey[a-zA-Z0-9_-]{{17,}}\.ey(?:[a-zA-Z0-9_/-]|\\/){{17,}}\.(?:(?:[a-zA-Z0-9_/-]|\\/){{10,}}={{0,2}})?{BOUNDARY}"
    ))
    .unwrap()
});

// gitleaks ends this rule in `[a-zA-Z0-9-]*`, which is safe for a detector but eats the rest of the line in a rewriter — the secret segment is alphanumeric in every real token, so dropping `-` from the charset is what stops the swallow.
static SLACK_BOT_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}").unwrap());

// Pre-2020 two-segment bot tokens: without this the tightened three-segment rule above would silently stop covering them.
static SLACK_LEGACY_BOT_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}").unwrap());

// xoxs/xoxo legacy tokens, structurally identical to the xoxp user token but with a hex tail.
static SLACK_LEGACY_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bxox[os]-(?:[0-9]{6,13}-){3}(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{10})").unwrap()
});

// Only the documented five-segment xoxa/xoxr shape: gitleaks' looser variant is entropy-gated, and this crate has no entropy filter to fall back on.
static SLACK_LEGACY_WORKSPACE_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bxox[ar]-[0-9]-(?:[0-9]{6,13}-){3}(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{18})").unwrap()
});

// Registered before the classic rule below, which would otherwise consume this token's first 20 body chars and leave the rest. Body is alphanumeric-only and the tail is `\b`-terminated because upstream leans on an entropy gate this crate lacks: with `-`/`_` admitted, the greedy body spanned ordinary kebab-case prose to any dotted nine-letter word and deleted the lot.
static GITLAB_PAT_ROUTABLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bglpat-[0-9a-zA-Z]{27,300}\.[0-9a-z]{9}\b").unwrap());

static GITLAB_PAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bglpat-[0-9a-zA-Z_-]{20}").unwrap());

static GITHUB_OAUTH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgho_[0-9a-zA-Z]{36}").unwrap());

// Left unbounded on purpose: the charset excludes every delimiter, so the only text this can over-consume is more alphanumerics, whereas gitleaks' {10,99} cap would leave the tail of a longer live key sitting in the file.
static STRIPE_ACCESS_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{{10,}}{BOUNDARY}"
    ))
    .unwrap()
});

// Each path segment is bounded separately because `/` inside one span made the rule eat following path segments, while a span wide enough for the 4-segment workflows/triggers form would have widened that swallow instead of fixing it.
static SLACK_WEBHOOK_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:https?://)?\bhooks\.slack\.com/(?:services/[A-Za-z0-9+]{8,12}/[A-Za-z0-9+]{8,12}/[A-Za-z0-9+]{20,28}|(?:workflows|triggers)/[A-Za-z0-9+]{8,12}/[A-Za-z0-9+]{8,12}/[0-9]{15,22}/[A-Za-z0-9+]{20,28}|triggers/[A-Za-z0-9+]{8,12}/[0-9]{10,16}/[A-Za-z0-9+]{28,36})",
    )
    .unwrap()
});

static CLICKHOUSE_CLOUD_API_SECRET_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b4b1d[A-Za-z0-9]{38}\b").unwrap());

// Left-anchored and exact-length on purpose — this crate rewrites files, so a loose bound is an unrecoverable edit rather than a triageable finding.
static GITHUB_PAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bghp_[0-9a-zA-Z]{36}").unwrap());

// ghr_ (refresh token) rides the same upstream alternation and is an equally live credential.
static GITHUB_APP_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:ghu|ghs|ghr)_[0-9a-zA-Z]{36}").unwrap());

static GITHUB_FINE_GRAINED_PAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgithub_pat_[0-9A-Za-z_]{82}").unwrap());

// Deliberately left as shipped: with no lookahead, a ranged tail cannot both always match and never over-consume — see CHANGELOG for the measured trade this rule still carries.
static SLACK_USER_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}").unwrap());

static SLACK_APP_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxapp-[0-9]-[A-Z0-9]{9,}-[0-9]{10,13}-[a-f0-9]{64}").unwrap());

static GOOGLE_API_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAIza[0-9A-Za-z_-]{35}").unwrap());

// The api03/admin01 infix and AA terminator are load-bearing: without them this matches ordinary kebab-case prose after any word ending in "sk".
static ANTHROPIC_API_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-ant-(?:api03|admin01)-[0-9a-zA-Z_-]{93}AA").unwrap());

static NPM_ACCESS_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnpm_[0-9a-zA-Z]{36}").unwrap());

static DOCKER_PAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bdckr_pat_[0-9a-zA-Z_-]{27}").unwrap());

// v0.1 high-confidence subset validated against real data — see README for what's deferred and why.
pub fn secret_patterns() -> Vec<Pattern> {
    vec![
        Pattern::simple("aws-access-token", &AWS_ACCESS_TOKEN_RE),
        Pattern::with_boundary("jwt", &JWT_RE),
        Pattern::simple("slack-bot-token", &SLACK_BOT_TOKEN_RE),
        Pattern::simple("slack-legacy-bot-token", &SLACK_LEGACY_BOT_TOKEN_RE),
        Pattern::simple("slack-legacy-token", &SLACK_LEGACY_TOKEN_RE),
        Pattern::simple(
            "slack-legacy-workspace-token",
            &SLACK_LEGACY_WORKSPACE_TOKEN_RE,
        ),
        Pattern::simple("gitlab-pat-routable", &GITLAB_PAT_ROUTABLE_RE),
        Pattern::simple("gitlab-pat", &GITLAB_PAT_RE),
        Pattern::simple("github-oauth", &GITHUB_OAUTH_RE),
        Pattern::with_boundary("stripe-access-token", &STRIPE_ACCESS_TOKEN_RE),
        Pattern::simple("slack-webhook-url", &SLACK_WEBHOOK_URL_RE),
        Pattern::simple(
            "clickhouse-cloud-api-secret-key",
            &CLICKHOUSE_CLOUD_API_SECRET_KEY_RE,
        ),
        Pattern::simple("github-pat", &GITHUB_PAT_RE),
        Pattern::simple("github-app-token", &GITHUB_APP_TOKEN_RE),
        Pattern::simple("github-fine-grained-pat", &GITHUB_FINE_GRAINED_PAT_RE),
        Pattern::simple("slack-user-token", &SLACK_USER_TOKEN_RE),
        Pattern::simple("slack-app-token", &SLACK_APP_TOKEN_RE),
        Pattern::simple("google-api-key", &GOOGLE_API_KEY_RE),
        Pattern::simple("anthropic-api-key", &ANTHROPIC_API_KEY_RE),
        Pattern::simple("npm-access-token", &NPM_ACCESS_TOKEN_RE),
        Pattern::simple("docker-pat", &DOCKER_PAT_RE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::Pattern as P;

    #[test]
    fn jwt_is_detected_before_an_ampersand_in_an_oauth_callback_url() {
        let pattern = P::with_boundary("jwt", &JWT_RE);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let text = format!("id_token={jwt}&state=abc");
        let (out, count) = pattern.apply(&text);
        assert_eq!(
            count, 1,
            "must detect the token even though '&' isn't in an enumerated boundary list"
        );
        assert_eq!(out, "id_token=[REDACTED-jwt]&state=abc");
    }

    #[test]
    fn jwt_header_with_base64url_dash_and_underscore_is_detected() {
        let pattern = P::with_boundary("jwt", &JWT_RE);
        let jwt = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImEtYl9jIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.sig_part-here12345";
        let (_, count) = pattern.apply(jwt);
        assert_eq!(
            count, 1,
            "a kid-bearing header commonly base64url-encodes to include - and _"
        );
    }

    #[test]
    fn stripe_key_is_detected_before_a_trailing_comma() {
        // sk_test_ (not sk_live_): still exercises the same prefix alternation, without a live-key shape that trips real-world secret scanners on this file itself.
        let pattern = P::with_boundary("stripe-access-token", &STRIPE_ACCESS_TOKEN_RE);
        let text = "sk_test_abcdefghijklmnopqrstuvwxyz0123456789,";
        let (out, count) = pattern.apply(text);
        assert_eq!(count, 1);
        assert_eq!(out, "[REDACTED-stripe-access-token],");
    }

    #[test]
    fn stripe_key_longer_than_the_old_99_char_cap_is_still_detected() {
        let pattern = P::with_boundary("stripe-access-token", &STRIPE_ACCESS_TOKEN_RE);
        let long_body = "a".repeat(150);
        let text = format!("sk_test_{long_body}");
        let (_, count) = pattern.apply(&text);
        assert_eq!(count, 1);
    }

    fn pattern_for(id: &str) -> P {
        secret_patterns().into_iter().find(|p| p.id == id).unwrap()
    }

    // Four shapes per rule, because a length-only near-miss passes against almost any wrong bound. `anchor_probe` must not match at all (proves the left boundary); `trailing` must survive the redaction byte-for-byte (proves the right bound stops where the vendor's token does).
    fn assert_shapes(
        id: &str,
        token: &str,
        anchor_probe: &str,
        trailing: &str,
        negatives: &[&str],
    ) {
        let text = format!("value={token} end");
        let (out, count) = pattern_for(id).apply(&text);
        assert_eq!(count, 1, "{id} must detect a full-length token");
        assert_eq!(out, format!("value=[REDACTED-{id}] end"));

        let (_, c) = pattern_for(id).apply(anchor_probe);
        assert_eq!(
            c, 0,
            "{id} fired on {anchor_probe} - missing left \\b, so it can match inside a longer run"
        );

        let butted = format!("{token}{trailing}");
        let (out, c) = pattern_for(id).apply(&butted);
        assert_eq!(c, 1, "{id} must still match with {trailing} appended");
        assert!(
            out.ends_with(trailing),
            "{id} swallowed adjacent text - bound is not exact: {out}"
        );

        // Wrapped like the positive: `\b` behaves identically at string start and after `=`, so the bare form that used to sit here was the same test twice.
        for n in negatives {
            let probe = format!("value={n} end");
            let (_, c) = pattern_for(id).apply(&probe);
            assert_eq!(c, 0, "{id} must not match {probe}");
        }
    }

    // Same body as assert_ranged_pattern; only the default trailing probe differs, which for an exact-length rule may be in-charset.
    fn assert_pattern(id: &str, token: &str, negatives: &[&str]) {
        assert_shapes(id, token, &format!("xyz{token}"), "AAAA", negatives);
    }

    // An out-of-charset probe cannot pin the bound (the match stops at the delimiter whatever the quantifier says) - it only proves the rule does not run past a delimiter. The cap itself is pinned by assert_upper_bound.
    fn assert_ranged_pattern(id: &str, token: &str, trailing: &str, negatives: &[&str]) {
        assert_shapes(id, token, &format!("xyz{token}"), trailing, negatives);
    }

    const B36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    #[test]
    fn github_pat() {
        assert_pattern("github-pat", &format!("ghp_{B36}"), &["ghp_tooshort"]);
    }

    #[test]
    fn github_app_token_covers_every_prefix_in_its_alternation() {
        for prefix in ["ghu", "ghs", "ghr"] {
            assert_pattern(
                "github-app-token",
                &format!("{prefix}_{B36}"),
                &[&format!("{prefix}_short")],
            );
        }
        let (_, c) = pattern_for("github-app-token").apply(&format!("gha_{B36}"));
        assert_eq!(c, 0, "gha_ is not a GitHub token prefix");
    }

    #[test]
    fn github_fine_grained_pat() {
        let body = format!("{B36}{B36}_{}", &B36[..9]);
        assert_eq!(body.len(), 82);
        assert_pattern(
            "github-fine-grained-pat",
            &format!("github_pat_{body}"),
            &["github_pat_short", "my_github_pat_cache_key_0123456789"],
        );
    }

    // The 32-char tail is the length every published sample carries; the previous fixture used the rule's own 34-char maximum, so the no-swallow assertion held for a reason unrelated to the bound.
    #[test]
    fn slack_user_token() {
        assert_ranged_pattern(
            "slack-user-token",
            &format!("xoxp-{SEG}-{SEG_B}-{SEG_C}-{}", &B36[..32]),
            " end",
            &["xoxp-123-456", "xoxp-1234567890-1234567890-abcdef"],
        );
    }

    // The residual this rule still carries: `-` is in the tail charset and the range has 2 chars of slack over a real 32-char tail, so adjacent kebab-case text loses those 2 chars. Narrowing the charset instead drops any tail containing a hyphen, and with no lookahead a ranged tail cannot both always match and never over-consume.
    #[test]
    fn slack_user_token_over_consumes_into_adjacent_text_up_to_its_range() {
        let text = format!("xoxp-{SEG}-{SEG_B}-{SEG_C}-{}-eu-west-1-prod", &B36[..32]);
        let (out, count) = pattern_for("slack-user-token").apply(&text);
        assert_eq!(count, 1);
        assert_eq!(out, "[REDACTED-slack-user-token]u-west-1-prod");
    }

    #[test]
    fn slack_app_token() {
        let tail = "0123456789abcdef".repeat(4);
        assert_ranged_pattern(
            "slack-app-token",
            &format!("xapp-1-A0B1C2D3E-1234567890-{tail}"),
            "abcd",
            &["xapp-1-ABC-123-short"],
        );
    }

    #[test]
    fn google_api_key_does_not_fire_inside_a_base64_blob() {
        // A 39-char window over a base64 alphabet collides inside ordinary blobs without a left anchor.
        let body = format!("{}-_", &B36[..33]);
        assert_eq!(body.len(), 35);
        assert_pattern(
            "google-api-key",
            &format!("AIza{body}"),
            &[
                "AIzaShort",
                "exX5cDZeFaAknBVKRZJ7Q995kgkNErAIzaQKW5udj76ImifDqan5bpq1vBrS4xl",
            ],
        );
    }

    #[test]
    fn anthropic_api_key_does_not_fire_on_kebab_case_prose() {
        // Without the infix, any word ending in "sk" followed by a kebab-case run matched.
        let body = format!("{B36}{B36}{}-_", &B36[..19]);
        assert_eq!(body.len(), 93);
        assert_pattern(
            "anthropic-api-key",
            &format!("sk-ant-api03-{body}AA"),
            &[
                "sk-ant-short",
                "the risk-ant-pattern-matching-benchmark-suite-results-for-2026",
                "task-ant-colony-optimization-algorithm-implementation-notes-v2",
                &format!("sk-ant-api03-{body}ZZ"),
            ],
        );
        let (_, c) = pattern_for("anthropic-api-key").apply(&format!("sk-ant-admin01-{body}AA"));
        assert_eq!(c, 1, "admin01 keys are as live as api03 keys");
    }

    #[test]
    fn npm_access_token() {
        assert_pattern("npm-access-token", &format!("npm_{B36}"), &["npm_install"]);
    }

    #[test]
    fn docker_pat() {
        let body = format!("{}-_", &B36[..25]);
        assert_eq!(body.len(), 27);
        assert_pattern(
            "docker-pat",
            &format!("dckr_pat_{body}"),
            &["dckr_pat_short"],
        );
    }

    // Slack numeric segments, kept out of a contiguous literal so this file never carries a whole token-shaped string, and distinct from each other so a rule that accidentally required two of them to be equal would still fail.
    const SEG: &str = "1234567890";
    const SEG_B: &str = "2233445566";
    const SEG_C: &str = "9988776655";

    // A ranged rule's upper bound is only real if something proves the match stops there — without this, {16,40} and an unbounded {16,} pass identically.
    fn assert_upper_bound(id: &str, prefix: &str, max: usize) {
        let tail = "a".repeat(max + 20);
        let text = format!("{prefix}{tail}");
        let (out, count) = pattern_for(id).apply(&text);
        assert_eq!(count, 1, "{id} must still match at its cap");
        assert_eq!(
            out,
            format!("[REDACTED-{id}]{}", &tail[max..]),
            "{id} must match exactly its {max}-char cap - ends_with alone passes for any shorter match too"
        );
    }

    // The floor needs both halves: assert_upper_bound is satisfied by a match at max *or shorter*, so raising a minimum past the real token length goes unnoticed unless something asserts the minimum itself still matches.
    fn assert_lower_bound(id: &str, prefix: &str, min: usize) {
        let at = format!("value={prefix}{} end", "a".repeat(min));
        let (_, c) = pattern_for(id).apply(&at);
        assert_eq!(c, 1, "{id} must match a body of exactly {min}");
        let below = format!("value={prefix}{} end", "a".repeat(min - 1));
        let (_, c) = pattern_for(id).apply(&below);
        assert_eq!(c, 0, "{id} matched {} chars, under its floor", min - 1);
    }

    #[test]
    fn ranged_slack_rules_accept_their_floor_and_reject_one_char_under_it() {
        assert_lower_bound("slack-bot-token", &format!("xoxb-{SEG}-{SEG_B}-"), 24);
        assert_lower_bound("slack-legacy-bot-token", &format!("xoxb-{SEG}-"), 18);
        assert_lower_bound(
            "slack-legacy-token",
            "xoxs-416843729-132049654-560996830-",
            10,
        );
        assert_lower_bound(
            "slack-user-token",
            &format!("xoxp-{SEG}-{SEG_B}-{SEG_C}-"),
            28,
        );
        assert_lower_bound(
            "slack-legacy-workspace-token",
            "xoxa-2-511111111-311111111-311111111-",
            18,
        );
    }

    // aws-access-token and clickhouse are the only two rules ending in `\b`: butted against an alphanumeric they match nothing at all, so the credential survives the whole pass. Pinned as a test rather than changed, because for a fixed-length credential that same anchor is what stops the rule firing inside a longer run.
    #[test]
    fn the_two_trailing_anchor_rules_match_nothing_when_butted_against_alphanumerics() {
        let ch = format!("4b1d{B36}{}A", &B36[..2]);
        assert_eq!(
            pattern_for("clickhouse-cloud-api-secret-key").apply(&ch).1,
            0
        );
        let aws = format!("AKIA{}A", "Z".repeat(16));
        assert_eq!(pattern_for("aws-access-token").apply(&aws).1, 0);
    }

    #[test]
    fn ranged_slack_rules_stop_at_their_vendor_caps() {
        assert_upper_bound("slack-bot-token", &format!("xoxb-{SEG}-{SEG_B}-"), 32);
        assert_upper_bound("slack-legacy-bot-token", &format!("xoxb-{SEG}-"), 26);
        assert_upper_bound(
            "slack-legacy-token",
            "xoxs-416843729-132049654-560996830-",
            64,
        );
        assert_upper_bound(
            "slack-user-token",
            &format!("xoxp-{SEG}-{SEG_B}-{SEG_C}-"),
            34,
        );
        assert_upper_bound(
            "slack-legacy-workspace-token",
            "xoxa-2-511111111-311111111-311111111-",
            64,
        );
    }

    #[test]
    fn slack_bot_token() {
        assert_ranged_pattern(
            "slack-bot-token",
            &format!("xoxb-{SEG}-{SEG_B}-{}", &B36[..24]),
            "-more-text",
            &[
                "xoxb-123-456",
                "xoxb-xoxb-my-bot-token",
                &format!("xoxb-{SEG}-{SEG_B}-{}", &B36[..15]),
            ],
        );
    }

    #[test]
    fn slack_legacy_bot_token() {
        assert_ranged_pattern(
            "slack-legacy-bot-token",
            &format!("xoxb-{SEG}-{}", &B36[..24]),
            "-more",
            &["xoxb-abcdef-abcdef", "xoxb-12345-abcd234"],
        );
    }

    #[test]
    fn slack_legacy_token() {
        assert_ranged_pattern(
            "slack-legacy-token",
            &format!(
                "xoxs-416843729-132049654-560996830-{}",
                "0123456789abcdef".repeat(4)
            ),
            "ghij",
            &[
                "xoxs-123-456-789-abc",
                "https://indieweb.org/images/3/35/2018-250-xoxo-indieweb-1.jpg",
            ],
        );
    }

    #[test]
    fn slack_legacy_workspace_token() {
        let tail = format!("{}{}", &B36[..16], &B36[..2]);
        assert_eq!(tail.len(), 18);
        assert_ranged_pattern(
            "slack-legacy-workspace-token",
            &format!("xoxa-2-511111111-311111111-311111111-{tail}"),
            "ghij",
            &[
                "xoxa-faketoken",
                "https://github.com/xoxa-nyc/xoxa-nyc.github.io/blob/master/README.md",
            ],
        );
    }

    #[test]
    fn gitlab_pat() {
        assert_pattern(
            "gitlab-pat",
            &format!("glpat-{}_-", &B36[..18]),
            &["glpat-tooshort", &format!("glpat-{}", &B36[..19])],
        );
    }

    #[test]
    fn gitlab_pat_routable() {
        assert_ranged_pattern(
            "gitlab-pat-routable",
            &format!("glpat-{}.{}", &B36[..27], &B36[..9]),
            "-tail",
            &[
                &format!("glpat-{}.{}", &B36[..20], &B36[..9]),
                &format!("glpat-{}x{}", &B36[..27], &B36[..9]),
            ],
        );
    }

    // The classic 20-char rule would otherwise consume a routable token's first 20 body chars and leave the rest of the credential in the file, so registration order is load-bearing rather than cosmetic.
    #[test]
    fn a_routable_gitlab_pat_is_redacted_whole_by_the_ordered_set() {
        let token = format!("glpat-{}.{}", &B36[..27], &B36[..9]);
        let mut text = format!("token={token} end");
        for p in secret_patterns() {
            text = p.apply(&text).0.into_owned();
        }
        assert_eq!(text, "token=[REDACTED-gitlab-pat-routable] end");
    }

    #[test]
    fn github_oauth() {
        assert_pattern("github-oauth", &format!("gho_{B36}"), &["gho_tooshort"]);
    }

    #[test]
    fn slack_webhook_url() {
        let path = format!("T00000000/B00000000/{}", &B36[..24]);
        let token = format!("https://hooks.slack.com/services/{path}");
        assert_shapes(
            "slack-webhook-url",
            &token,
            &format!("xyzhooks.slack.com/services/{path}"),
            "/archive/2026",
            &["https://hooks.slack.com/services/short"],
        );
    }

    // The four-segment form is 65-67 chars; the single {43,56} span this replaced truncated it and left the trigger secret's tail in the file.
    #[test]
    fn slack_webhook_url_covers_the_four_segment_workflow_forms() {
        for kind in ["workflows", "triggers"] {
            let token = format!(
                "https://hooks.slack.com/{kind}/T016M3G1GHZ/A04J3BAF7AA/442660231806210747/{}",
                &B36[..24]
            );
            let text = format!("{token} done");
            let (out, count) = pattern_for("slack-webhook-url").apply(&text);
            assert_eq!(count, 1, "{kind} form must be detected");
            assert_eq!(out, "[REDACTED-slack-webhook-url] done");
        }
    }

    #[test]
    fn slack_webhook_url_matches_the_scheme_less_form_log_text_carries() {
        let token = format!(
            "hooks.slack.com/services/T00000000/B00000000/{}",
            &B36[..24]
        );
        let text = format!("see {token} now");
        let (_, count) = pattern_for("slack-webhook-url").apply(&text);
        assert_eq!(count, 1);
    }

    #[test]
    fn clickhouse_cloud_api_secret_key() {
        let body = format!("{B36}{}", &B36[..2]);
        assert_eq!(body.len(), 38);
        assert_ranged_pattern(
            "clickhouse-cloud-api-secret-key",
            &format!("4b1d{body}"),
            "-tail",
            &["4b1dshort"],
        );
    }

    // The numeric segment floors are unpinned separately from the body floors: every fixture above uses 9-10 digit segments, so raising a {6,13} or {8,14} minimum past the real vendor length went unnoticed.
    #[test]
    fn slack_numeric_segments_match_at_their_shortest_documented_length() {
        let legacy_bot = format!("xoxb-12345678-{}", &B36[..24]);
        assert_eq!(
            pattern_for("slack-legacy-bot-token").apply(&legacy_bot).1,
            1
        );
        let legacy = format!("xoxo-523423-234243-234233-{}", "0123456789abcdef".repeat(4));
        assert_eq!(pattern_for("slack-legacy-token").apply(&legacy).1, 1);
        let workspace = format!("xoxa-2-511111-311111-311111-{}{}", &B36[..16], &B36[..2]);
        assert_eq!(
            pattern_for("slack-legacy-workspace-token")
                .apply(&workspace)
                .1,
            1
        );
    }

    // The routable rule's body must exclude `-`/`_`: admitting them let the greedy body span ordinary kebab-case prose as far as any dotted nine-letter word and delete all of it.
    #[test]
    fn a_classic_gitlab_token_followed_by_dotted_kebab_prose_keeps_the_prose() {
        let mut out = format!(
            "GITLAB_TOKEN: glpat-{}-prod-runner-shared-config.terraform state",
            &B36[..20]
        );
        for pattern in secret_patterns() {
            out = pattern.apply(&out).0.into_owned();
        }
        assert_eq!(
            out,
            "GITLAB_TOKEN: [REDACTED-gitlab-pat]-prod-runner-shared-config.terraform state"
        );
    }

    // Without the trailing \b the checksum can end mid-word, so a dotted word longer than nine letters is consumed as if it were the checksum. Declining here leaves the classic rule's partial redaction, which is recoverable; consuming the prose is not.
    #[test]
    fn the_routable_checksum_must_end_at_a_word_boundary() {
        let mut out = format!("token glpat-{}.terraformabc end", &B36[..27]);
        for pattern in secret_patterns() {
            out = pattern.apply(&out).0.into_owned();
        }
        assert_eq!(
            out,
            format!(
                "token [REDACTED-gitlab-pat]{}.terraformabc end",
                &B36[20..27]
            )
        );
    }

    // Slack's trigger webhooks are team/id/secret - three segments, not the four the workflow form carries, so routing them through the workflow branch drops a live credential class.
    #[test]
    fn slack_trigger_webhook_urls_are_covered() {
        let token = format!(
            "https://hooks.slack.com/triggers/T0266FRGM/6199336638709/{}",
            "0123456789abcdef".repeat(2)
        );
        let text = format!("curl {token} end");
        let (out, count) = pattern_for("slack-webhook-url").apply(&text);
        assert_eq!(count, 1, "the 3-segment trigger form is a live credential");
        assert_eq!(out, "curl [REDACTED-slack-webhook-url] end");
    }

    // A services secret runs to 28 chars; a cap below that truncates and writes the tail back into the file.
    #[test]
    fn slack_services_webhook_secret_matches_to_its_full_length() {
        let text = format!(
            "https://hooks.slack.com/services/T00000000/B00000000/{} end",
            &B36[..28]
        );
        let (out, count) = pattern_for("slack-webhook-url").apply(&text);
        assert_eq!(count, 1);
        assert_eq!(out, "[REDACTED-slack-webhook-url] end");
    }

    // Both legacy tails are hex. Widening the charset to alphanumeric would let the 64-char branch run 54 characters past a real 10-char tail and delete whatever followed.
    #[test]
    fn the_legacy_slack_tails_stop_at_the_first_non_hex_character() {
        let trailing = "ghijklmnopqrstuvwxyz".repeat(3);
        for (id, prefix) in [
            (
                "slack-legacy-token",
                "xoxs-416843729-132049654-560996830-".to_string(),
            ),
            (
                "slack-legacy-workspace-token",
                "xoxa-2-511111111-311111111-311111111-".to_string(),
            ),
        ] {
            let tail = if id == "slack-legacy-token" {
                "0123456789".to_string()
            } else {
                "0123456789abcdef01".to_string()
            };
            let text = format!("{prefix}{tail}{trailing}");
            let (out, count) = pattern_for(id).apply(&text);
            assert_eq!(count, 1, "{id}");
            assert!(
                out.ends_with(&trailing),
                "{id} ran past its hex tail into {trailing}: {out}"
            );
        }
    }

    // Each alternation branch is a separate credential class; without a case per branch, deleting one is invisible.
    #[test]
    fn every_slack_prefix_alternation_branch_is_covered() {
        for p in ["xoxp", "xoxe"] {
            let tok = format!("{p}-{SEG}-{SEG_B}-{SEG_C}-{}", &B36[..32]);
            assert_eq!(pattern_for("slack-user-token").apply(&tok).1, 1, "{p}");
        }
        for p in ["xoxs", "xoxo"] {
            let tok = format!(
                "{p}-416843729-132049654-560996830-{}",
                "0123456789abcdef".repeat(4)
            );
            assert_eq!(pattern_for("slack-legacy-token").apply(&tok).1, 1, "{p}");
        }
        for p in ["xoxa", "xoxr"] {
            let tok = format!(
                "{p}-2-511111111-311111111-311111111-{}{}",
                &B36[..16],
                &B36[..2]
            );
            assert_eq!(
                pattern_for("slack-legacy-workspace-token").apply(&tok).1,
                1,
                "{p}"
            );
        }
    }

    // Pins the gap the README documents: jwt is the one rule that is both open-ended and delimiter-permissive, so it takes the following path segment with it. If this starts failing the rule was fixed, and the README paragraph needs deleting.
    #[test]
    fn jwt_still_consumes_a_following_path_segment() {
        let pattern = P::with_boundary("jwt", &JWT_RE);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let text = format!("GET /api/v1/verify/{jwt}/status?ok=1");
        let (out, count) = pattern.apply(&text);
        assert_eq!(count, 1);
        assert_eq!(out, "GET /api/v1/verify/[REDACTED-jwt]?ok=1");
    }
}
