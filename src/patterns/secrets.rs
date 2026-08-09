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

// Left-anchored and exact-length on purpose — this crate rewrites files, so a loose bound is an unrecoverable edit rather than a triageable finding.
static GITHUB_PAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bghp_[0-9a-zA-Z]{36}").unwrap());

// ghr_ (refresh token) rides the same upstream alternation and is an equally live credential.
static GITHUB_APP_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:ghu|ghs|ghr)_[0-9a-zA-Z]{36}").unwrap());

static GITHUB_FINE_GRAINED_PAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgithub_pat_[0-9A-Za-z_]{82}").unwrap());

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

    // Three shapes per rule, because a length-only near-miss passes against almost any wrong bound.
    fn assert_pattern(id: &str, token: &str, negatives: &[&str]) {
        let text = format!("value={token} end");
        let (out, count) = pattern_for(id).apply(&text);
        assert_eq!(count, 1, "{id} must detect a full-length token");
        assert_eq!(out, format!("value=[REDACTED-{id}] end"));

        let embedded = format!("xyz{token}");
        let (_, c) = pattern_for(id).apply(&embedded);
        assert_eq!(
            c, 0,
            "{id} fired with its prefix preceded by a word char - missing left \\b, so it can match inside a base64 blob"
        );

        let butted = format!("{token}AAAA");
        let (out, c) = pattern_for(id).apply(&butted);
        assert_eq!(c, 1, "{id} must still match with in-charset text appended");
        assert!(
            out.ends_with("AAAA"),
            "{id} swallowed adjacent text - bound is not exact: {out}"
        );

        for n in negatives {
            let (_, c) = pattern_for(id).apply(n);
            assert_eq!(c, 0, "{id} must not match {n}");
        }
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

    #[test]
    fn slack_user_token() {
        let tail = &B36[..34];
        assert_pattern(
            "slack-user-token",
            &format!("xoxp-1234567890-1234567890-1234567890-{tail}"),
            &["xoxp-123-456", "xoxp-1234567890-1234567890-abcdef"],
        );
    }

    #[test]
    fn slack_app_token() {
        let tail = "0123456789abcdef".repeat(4);
        assert_pattern(
            "slack-app-token",
            &format!("xapp-1-A0B1C2D3E-1234567890-{tail}"),
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
}
