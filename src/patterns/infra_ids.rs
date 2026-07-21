use regex::{Captures, Regex};
use std::sync::LazyLock;

use super::Pattern;

// Resource IDs must run before account IDs to avoid partial hex matches.
static AWS_RESOURCE_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(vpc|sg|subnet|vpce|igw|rtb|acl|eni|vol|snap|nat|eipalloc|pcx)-[0-9a-f]{8,17}\b")
        .unwrap()
});

static AWS_INSTANCE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bi-[0-9a-f]{8,17}\b").unwrap());

static ROUTE53_ZONE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bZ[0-9A-Z]{10,32}\b").unwrap());

// Only after `::`/`:`/`/` delimiters, to avoid false positives on bare numbers.
static AWS_ACCOUNT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(::?|/)\d{12}\b").unwrap());

static USER_HOME_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/(Users|home)/[a-zA-Z0-9._-]+/").unwrap());

static GITHUB_ORG_REPO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(github\.com/|repos/)([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)").unwrap()
});

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
});

// `--repo org/repo` CLI flag form, not caught by the URL-shaped pattern above.
static REPO_FLAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"--repo\s+([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)").unwrap());

fn aws_resource_id_replacement(caps: &Captures) -> String {
    let prefix = caps.get(1).map_or("", |m| m.as_str());
    format!("{prefix}-<ID>")
}

// A bare numeric placeholder (no leading zero, so it stays a valid JSON number literal), not "<ACCOUNT_ID>": the match can be a bare unquoted JSON number value (e.g. {"account_id":123456789012}), where non-numeric replacement text would break JSON.
fn aws_account_id_replacement(caps: &Captures) -> String {
    let delim = caps.get(1).map_or("", |m| m.as_str());
    format!("{delim}999999999999")
}

fn github_org_repo_replacement(caps: &Captures) -> String {
    let prefix = caps.get(1).map_or("", |m| m.as_str());
    format!("{prefix}<org>/<repo>")
}

fn repo_flag_replacement(_caps: &Captures) -> String {
    "--repo <org>/<repo>".to_string()
}

// Infra-identifier leaks, not credential secrets — see README for scope rationale.
pub fn infra_id_patterns() -> Vec<Pattern> {
    vec![
        Pattern::with_fn(
            "aws-resource-id",
            &AWS_RESOURCE_ID_RE,
            aws_resource_id_replacement,
        ),
        Pattern::literal("aws-instance-id", &AWS_INSTANCE_ID_RE, "i-<ID>"),
        Pattern::literal("route53-zone-id", &ROUTE53_ZONE_ID_RE, "Z<ZONE_ID>"),
        Pattern::with_fn(
            "aws-account-id",
            &AWS_ACCOUNT_ID_RE,
            aws_account_id_replacement,
        ),
        Pattern::literal("user-home-path", &USER_HOME_PATH_RE, "~/"),
        Pattern::with_fn(
            "github-org-repo",
            &GITHUB_ORG_REPO_RE,
            github_org_repo_replacement,
        ),
        Pattern::literal("uuid", &UUID_RE, "<UUID>"),
        Pattern::with_fn("repo-flag", &REPO_FLAG_RE, repo_flag_replacement),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::Pattern as P;

    #[test]
    fn account_id_replacement_stays_valid_json_when_the_match_is_a_bare_number_value() {
        let pattern = P::with_fn(
            "aws-account-id",
            &AWS_ACCOUNT_ID_RE,
            aws_account_id_replacement,
        );
        let (out, count) = pattern.apply(r#"{"account_id":123456789012,"ok":true}"#);
        assert_eq!(count, 1);
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "must still parse as JSON: {out}"
        );
    }

    #[test]
    fn account_id_replacement_still_works_inside_a_quoted_arn() {
        let pattern = P::with_fn(
            "aws-account-id",
            &AWS_ACCOUNT_ID_RE,
            aws_account_id_replacement,
        );
        let (out, count) = pattern.apply("arn:aws:iam::123456789012:role/MyRole");
        assert_eq!(count, 1);
        assert_eq!(out, "arn:aws:iam::999999999999:role/MyRole");
    }
}
