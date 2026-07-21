use std::collections::HashMap;

use crate::patterns::Pattern;
use crate::structural::pem;

#[derive(Debug, Default)]
pub struct RedactSummary {
    pub pattern_counts: HashMap<String, usize>,
    pub pem_pairs_redacted: usize,
    pub pem_orphan_begin: usize,
    pub pem_orphan_end: usize,
    pub pem_aborted_lines: Vec<usize>,
}

impl RedactSummary {
    pub fn total_redactions(&self) -> usize {
        self.pattern_counts.values().sum::<usize>() + self.pem_pairs_redacted
    }

    // Adds another summary's counts into this one instead of overwriting, so repeated patterns (e.g. a custom rule reused across lines) accumulate rather than undercounting.
    fn merge(&mut self, other: RedactSummary) {
        for (id, count) in other.pattern_counts {
            *self.pattern_counts.entry(id).or_insert(0) += count;
        }
        self.pem_pairs_redacted += other.pem_pairs_redacted;
        self.pem_orphan_begin += other.pem_orphan_begin;
        self.pem_orphan_end += other.pem_orphan_end;
        self.pem_aborted_lines.extend(other.pem_aborted_lines);
    }
}

// Applies every regex pattern, then the PEM structural handler when requested (line-bounded, so it can never undo a regex-based redaction's own line-safety). include_pem is false when the caller selected an infra-ID-only pattern set — PEM is a secret-value concern.
pub fn redact_text(text: &str, patterns: &[Pattern], include_pem: bool) -> (String, RedactSummary) {
    let mut current = text.to_string();
    let mut summary = RedactSummary::default();

    for p in patterns {
        let (new_text, count) = p.apply(&current);
        if count > 0 {
            *summary.pattern_counts.entry(p.id.to_string()).or_insert(0) += count;
            current = new_text.into_owned();
        }
    }

    if !include_pem {
        return (current, summary);
    }

    let pem_result = pem::redact_pem_blocks(&current);
    summary.pem_pairs_redacted = pem_result.pairs_redacted;
    summary.pem_orphan_begin = pem_result.orphan_begin;
    summary.pem_orphan_end = pem_result.orphan_end;
    summary.pem_aborted_lines = pem_result.aborted_lines;

    (pem_result.text, summary)
}

// Redacts a JSONL file one record at a time so a single line whose redaction would break JSON only costs that line, not every other secret redaction in the file (a bad account-id/JSON-number interaction once blocked writes for an entire file this way).
pub fn redact_jsonl(
    text: &str,
    patterns: &[Pattern],
    include_pem: bool,
) -> (String, RedactSummary, Vec<usize>) {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
    let mut summary = RedactSummary::default();
    let mut failed_lines = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            new_lines.push((*line).to_string());
            continue;
        }

        let (redacted, line_summary) = redact_text(line, patterns, include_pem);
        if line_summary.total_redactions() == 0 {
            new_lines.push((*line).to_string());
            continue;
        }

        let was_valid_json = serde_json::from_str::<serde_json::Value>(line).is_ok();
        let is_valid_json = serde_json::from_str::<serde_json::Value>(&redacted).is_ok();
        if is_valid_json || !was_valid_json {
            summary.merge(line_summary);
            new_lines.push(redacted);
        } else {
            failed_lines.push(i + 1);
            new_lines.push((*line).to_string());
        }
    }

    (new_lines.join("\n"), summary, failed_lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::all_patterns;

    #[test]
    fn redacts_secret_and_infra_id_in_one_pass() {
        let patterns = all_patterns();
        let text = "AKIAABCDEFGHIJKLMNOP and vpc-0abc123def456789a";
        let (out, summary) = redact_text(text, &patterns, true);
        assert_eq!(out, "[REDACTED-aws-access-token] and vpc-<ID>");
        assert_eq!(summary.pattern_counts.get("aws-access-token"), Some(&1));
        assert_eq!(summary.pattern_counts.get("aws-resource-id"), Some(&1));
    }

    #[test]
    fn redacts_pem_block_after_pattern_pass() {
        let patterns = all_patterns();
        let text = "prefix -----BEGIN PRIVATE KEY----- body -----END PRIVATE KEY----- suffix";
        let (out, summary) = redact_text(text, &patterns, true);
        assert_eq!(out, "prefix [REDACTED-private-key] suffix");
        assert_eq!(summary.pem_pairs_redacted, 1);
    }

    #[test]
    fn pem_is_skipped_when_include_pem_is_false() {
        let patterns = all_patterns();
        let text = "prefix -----BEGIN PRIVATE KEY----- body -----END PRIVATE KEY----- suffix";
        let (out, summary) = redact_text(text, &patterns, false);
        assert_eq!(
            out, text,
            "PEM block must be left untouched when the pattern set excludes secrets"
        );
        assert_eq!(summary.pem_pairs_redacted, 0);
    }

    #[test]
    fn unchanged_text_produces_zero_redactions() {
        let patterns = all_patterns();
        let text = "nothing sensitive here";
        let (out, summary) = redact_text(text, &patterns, true);
        assert_eq!(out, text);
        assert_eq!(summary.total_redactions(), 0);
    }

    #[test]
    fn duplicate_pattern_ids_across_lines_accumulate_not_overwrite() {
        let patterns = all_patterns();
        let text = "vpc-0abc123def456789a\nvpc-0fedcba987654321f\n";
        let (_, summary, failed) = redact_jsonl(text, &patterns, true);
        assert!(failed.is_empty());
        assert_eq!(summary.pattern_counts.get("aws-resource-id"), Some(&2));
    }

    #[test]
    fn a_line_that_would_break_json_is_left_untouched_but_others_still_redact() {
        let patterns = all_patterns();
        let text = "{\"account_id\":123456789012}\n{\"key\":\"AKIAABCDEFGHIJKLMNOP\"}\n";
        let (out, summary, failed) = redact_jsonl(text, &patterns, true);
        let lines: Vec<&str> = out.split('\n').collect();
        assert!(
            serde_json::from_str::<serde_json::Value>(lines[0]).is_ok(),
            "account-id line must stay valid JSON now that the fix is JSON-safe: {}",
            lines[0]
        );
        assert!(lines[1].contains("[REDACTED-aws-access-token]"));
        assert!(failed.is_empty());
        assert_eq!(summary.pattern_counts.get("aws-access-token"), Some(&1));
    }

    #[test]
    fn a_line_already_invalid_json_before_redaction_still_gets_redacted_best_effort() {
        let patterns = all_patterns();
        let text = "not json at all AKIAABCDEFGHIJKLMNOP\n{\"key\":\"AKIAZZZZZZZZZZZZZZZZ\"}\n";
        let (out, _summary, failed) = redact_jsonl(text, &patterns, true);
        let lines: Vec<&str> = out.split('\n').collect();
        assert!(
            failed.is_empty(),
            "a line that was never valid JSON to begin with shouldn't block on the JSON gate"
        );
        assert!(
            lines[0].contains("[REDACTED-aws-access-token]"),
            "the secret on the already-malformed line must still be redacted"
        );
        assert!(lines[1].contains("[REDACTED-aws-access-token]"));
    }

    #[test]
    fn a_redaction_that_would_break_previously_valid_json_is_isolated_to_that_line() {
        use crate::patterns::Pattern as P;
        use regex::Regex;
        use std::sync::LazyLock;
        static BREAKS_JSON_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new("BADSECRET").unwrap());
        let patterns = vec![P::literal("breaks-json", &BREAKS_JSON_RE, "x\"y")];
        let text = "{\"a\":\"BADSECRET\"}\n{\"b\":\"BADSECRET\"}\n";
        let (out, summary, failed) = redact_jsonl(text, &patterns, true);
        let lines: Vec<&str> = out.split('\n').collect();
        assert_eq!(
            failed,
            vec![1, 2],
            "both lines were valid JSON before redaction and invalid after, both must be flagged"
        );
        assert_eq!(
            lines[0], "{\"a\":\"BADSECRET\"}",
            "left untouched, not corrupted"
        );
        assert_eq!(summary.total_redactions(), 0);
    }
}
