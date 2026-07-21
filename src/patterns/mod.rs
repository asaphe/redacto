pub mod infra_ids;
pub mod secrets;

use regex::{Captures, Regex};
use std::borrow::Cow;

enum Replacement {
    Token(String),
    Literal(&'static str),
    Fn(fn(&Captures) -> String),
}

// Values published in vendor docs as literal examples — real-world testing confirmed AWS's own AKIAIOSFODNN7EXAMPLE shows up constantly in test fixtures and code discussing secret-detection, never as a real leaked credential.
const KNOWN_BENIGN_VALUES: &[&str] = &["AKIAIOSFODNN7EXAMPLE"];

fn is_known_benign(matched: &str) -> bool {
    KNOWN_BENIGN_VALUES.contains(&matched)
}

// One detection rule: a regex plus how to redact what it matches.
pub struct Pattern {
    pub id: &'static str,
    regex: &'static Regex,
    replacement: Replacement,
}

impl Pattern {
    // Whole match becomes a bare "[REDACTED-<id>]" token.
    pub fn simple(id: &'static str, regex: &'static Regex) -> Self {
        Self {
            id,
            regex,
            replacement: Replacement::Token(format!("[REDACTED-{id}]")),
        }
    }

    // Like `simple`, but the regex's last capture group is a trailing boundary char to preserve (see secrets.rs BOUNDARY).
    pub fn with_boundary(id: &'static str, regex: &'static Regex) -> Self {
        Self {
            id,
            regex,
            replacement: Replacement::Token(format!("[REDACTED-{id}]$1")),
        }
    }

    // Whole match becomes a fixed literal string (e.g. infra-ID placeholders like "~/" or "<UUID>").
    pub fn literal(id: &'static str, regex: &'static Regex, literal: &'static str) -> Self {
        Self {
            id,
            regex,
            replacement: Replacement::Literal(literal),
        }
    }

    // Replacement is computed from the match's capture groups (e.g. preserving a prefix/delimiter).
    pub fn with_fn(id: &'static str, regex: &'static Regex, f: fn(&Captures) -> String) -> Self {
        Self {
            id,
            regex,
            replacement: Replacement::Fn(f),
        }
    }

    // Applies this pattern to `text`, returning the (possibly unchanged) result and how many matches were redacted. A known-benign match (e.g. a vendor doc's own example key) is left untouched and not counted.
    pub fn apply<'t>(&self, text: &'t str) -> (Cow<'t, str>, usize) {
        let mut count = 0usize;
        let result = match &self.replacement {
            Replacement::Token(template) => self.regex.replace_all(text, |caps: &Captures| {
                let whole = caps.get(0).map_or("", |m| m.as_str());
                if is_known_benign(whole) {
                    return whole.to_string();
                }
                count += 1;
                expand_template(template, caps)
            }),
            Replacement::Literal(lit) => self.regex.replace_all(text, |caps: &Captures| {
                let whole = caps.get(0).map_or("", |m| m.as_str());
                if is_known_benign(whole) {
                    return whole.to_string();
                }
                count += 1;
                (*lit).to_string()
            }),
            Replacement::Fn(f) => self.regex.replace_all(text, |caps: &Captures| {
                let whole = caps.get(0).map_or("", |m| m.as_str());
                if is_known_benign(whole) {
                    return whole.to_string();
                }
                count += 1;
                f(caps)
            }),
        };
        (result, count)
    }
}

// Minimal `$1`-style expansion for the handful of templates we actually use (no arbitrary $name support needed).
fn expand_template(template: &str, caps: &Captures) -> String {
    if let Some(rest) = template.strip_suffix("$1") {
        let group1 = caps.get(1).map_or("", |m| m.as_str());
        format!("{rest}{group1}")
    } else {
        template.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PatternSet {
    Secrets,
    Infra,
    All,
}

impl PatternSet {
    pub fn patterns(self) -> Vec<Pattern> {
        match self {
            PatternSet::Secrets => secrets::secret_patterns(),
            PatternSet::Infra => infra_ids::infra_id_patterns(),
            PatternSet::All => all_patterns(),
        }
    }

    // Private-key/PEM material is a secret value, not an infra identifier — only run the structural handler when this selection actually includes secrets.
    pub fn includes_pem(self) -> bool {
        matches!(self, PatternSet::Secrets | PatternSet::All)
    }
}

// The full v0.1 pattern set: secret values + infra identifiers.
pub fn all_patterns() -> Vec<Pattern> {
    let mut patterns = secrets::secret_patterns();
    patterns.extend(infra_ids::infra_id_patterns());
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_benign_aws_example_key_is_left_untouched() {
        let patterns = secrets::secret_patterns();
        let aws_pattern = patterns
            .iter()
            .find(|p| p.id == "aws-access-token")
            .unwrap();
        let text = "leak AKIAIOSFODNN7EXAMPLE in code";
        let (out, count) = aws_pattern.apply(text);
        assert_eq!(
            count, 0,
            "the well-known vendor-doc example key must not be flagged"
        );
        assert_eq!(out, text);
    }

    #[test]
    fn a_real_looking_key_that_isnt_the_known_example_is_still_redacted() {
        let patterns = secrets::secret_patterns();
        let aws_pattern = patterns
            .iter()
            .find(|p| p.id == "aws-access-token")
            .unwrap();
        let text = "leak AKIAZZZZZZZZZZZZZZZZ in code";
        let (_, count) = aws_pattern.apply(text);
        assert_eq!(count, 1);
    }
}
