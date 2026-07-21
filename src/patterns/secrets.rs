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

static SLACK_BOT_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap());

static GITLAB_PAT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"glpat-[\w-]{20,}").unwrap());

static GITHUB_OAUTH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gho_[0-9a-zA-Z]{36,}").unwrap());

static STRIPE_ACCESS_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{{10,}}{BOUNDARY}"
    ))
    .unwrap()
});

static SLACK_WEBHOOK_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
    )
    .unwrap()
});

static CLICKHOUSE_CLOUD_API_SECRET_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b4b1d[A-Za-z0-9]{38}\b").unwrap());

// v0.1 high-confidence subset validated against real data — see README for what's deferred and why.
pub fn secret_patterns() -> Vec<Pattern> {
    vec![
        Pattern::simple("aws-access-token", &AWS_ACCESS_TOKEN_RE),
        Pattern::with_boundary("jwt", &JWT_RE),
        Pattern::simple("slack-bot-token", &SLACK_BOT_TOKEN_RE),
        Pattern::simple("gitlab-pat", &GITLAB_PAT_RE),
        Pattern::simple("github-oauth", &GITHUB_OAUTH_RE),
        Pattern::with_boundary("stripe-access-token", &STRIPE_ACCESS_TOKEN_RE),
        Pattern::simple("slack-webhook-url", &SLACK_WEBHOOK_URL_RE),
        Pattern::simple(
            "clickhouse-cloud-api-secret-key",
            &CLICKHOUSE_CLOUD_API_SECRET_KEY_RE,
        ),
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
}
