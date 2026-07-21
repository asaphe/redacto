use regex::Regex;
use std::sync::LazyLock;

// Case-sensitive, lazy, and no dash/underscore in the gap: no real PEM type label uses them, and allowing either let the gap bridge straight through an adjacent marker's own "-----" scaffolding to reach a later PRIVATE KEY (confirmed: silently left real key material unredacted).
static BEGIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN[ A-Z0-9]{0,100}?PRIVATE KEY(?: BLOCK)?-----").unwrap()
});
static END_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----END[ A-Z0-9]{0,100}?PRIVATE KEY(?: BLOCK)?-----").unwrap());

#[derive(Debug, Default, PartialEq)]
pub struct LineResult {
    pub text: String,
    pub pairs_redacted: usize,
    pub orphan_begin: usize,
    pub orphan_end: usize,
    pub aborted: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Begin,
    End,
}

// LIFO BEGIN/END stack-match with containment-merge: a BEGIN BEGIN END END sequence is proper nesting (outer span alone is redacted, inner drops as redundant), never a partial-crossing overlap to guess at.
pub fn process_line(line: &str) -> LineResult {
    if !line.contains("PRIVATE KEY") {
        return LineResult {
            text: line.to_string(),
            ..Default::default()
        };
    }

    let mut markers: Vec<(Kind, usize, usize)> = Vec::new();
    for m in BEGIN_RE.find_iter(line) {
        markers.push((Kind::Begin, m.start(), m.end()));
    }
    for m in END_RE.find_iter(line) {
        markers.push((Kind::End, m.start(), m.end()));
    }
    markers.sort_by_key(|&(_, start, _)| start);

    let mut stack: Vec<(usize, usize)> = Vec::new();
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    let mut orphan_end = 0usize;

    for (kind, start, end) in markers {
        match kind {
            Kind::Begin => stack.push((start, end)),
            Kind::End => {
                if let Some((bstart, _)) = stack.pop() {
                    pairs.push((bstart, end));
                } else {
                    orphan_end += 1;
                }
            }
        }
    }
    let orphan_begin = stack.len();

    pairs.sort();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    let mut aborted = false;
    for p in pairs {
        match merged.last() {
            Some(&(_, last_end)) if p.0 < last_end => {
                if p.1 > last_end {
                    aborted = true;
                    break;
                }
                // else: fully contained in the current outer span, redundant — drop
            }
            _ => merged.push(p),
        }
    }

    if aborted {
        return LineResult {
            text: line.to_string(),
            orphan_begin,
            orphan_end,
            aborted: true,
            ..Default::default()
        };
    }

    if merged.is_empty() {
        return LineResult {
            text: line.to_string(),
            orphan_begin,
            orphan_end,
            ..Default::default()
        };
    }

    let mut new_text = String::with_capacity(line.len());
    let mut last = 0usize;
    for &(bstart, eend) in &merged {
        new_text.push_str(&line[last..bstart]);
        new_text.push_str("[REDACTED-private-key]");
        last = eend;
    }
    new_text.push_str(&line[last..]);

    LineResult {
        text: new_text,
        pairs_redacted: merged.len(),
        orphan_begin,
        orphan_end,
        aborted: false,
    }
}

#[derive(Debug, Default)]
pub struct FileResult {
    pub text: String,
    pub pairs_redacted: usize,
    pub orphan_begin: usize,
    pub orphan_end: usize,
    pub aborted_lines: Vec<usize>,
}

// Splits on real '\n' first so redaction can never cross a physical-line/JSON-record boundary — the exact failure mode that let an earlier (Python) prototype's capped-but-still-greedy regex jump 1127 lines to an unrelated END marker.
pub fn redact_pem_blocks(text: &str) -> FileResult {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
    let mut result = FileResult::default();

    for (i, line) in lines.iter().enumerate() {
        let r = process_line(line);
        result.orphan_begin += r.orphan_begin;
        result.orphan_end += r.orphan_end;
        if r.aborted {
            result.aborted_lines.push(i + 1);
            new_lines.push(line.to_string());
            continue;
        }
        result.pairs_redacted += r.pairs_redacted;
        new_lines.push(r.text);
    }

    result.text = new_lines.join("\n");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_pair_redacted() {
        let line = r#"prefix -----BEGIN PRIVATE KEY----- abc123 -----END PRIVATE KEY----- suffix"#;
        let r = process_line(line);
        assert_eq!(r.pairs_redacted, 1);
        assert_eq!(r.text, "prefix [REDACTED-private-key] suffix");
        assert!(!r.aborted);
    }

    #[test]
    fn nested_begin_begin_end_end_collapses_to_outer_span() {
        let line = "X -----BEGIN PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY----- inner -----END RSA PRIVATE KEY----- -----END PRIVATE KEY----- Y";
        let r = process_line(line);
        assert_eq!(
            r.pairs_redacted, 1,
            "nesting must collapse to a single outer redaction, not two"
        );
        assert_eq!(r.text, "X [REDACTED-private-key] Y");
        assert!(!r.aborted);
    }

    #[test]
    fn sequential_multi_pair_all_redacted() {
        let line = "-----BEGIN PRIVATE KEY----- a -----END PRIVATE KEY----- -----BEGIN PRIVATE KEY----- b -----END PRIVATE KEY-----";
        let r = process_line(line);
        assert_eq!(r.pairs_redacted, 2);
        assert_eq!(r.text, "[REDACTED-private-key] [REDACTED-private-key]");
    }

    #[test]
    fn orphan_begin_with_no_end_is_untouched() {
        let line = "-----BEGIN PRIVATE KEY----- no end marker on this line";
        let r = process_line(line);
        assert_eq!(r.pairs_redacted, 0);
        assert_eq!(r.orphan_begin, 1);
        assert_eq!(r.text, line);
    }

    #[test]
    fn orphan_end_with_no_begin_is_untouched() {
        let line = "trailing tail -----END PRIVATE KEY-----";
        let r = process_line(line);
        assert_eq!(r.pairs_redacted, 0);
        assert_eq!(r.orphan_end, 1);
        assert_eq!(r.text, line);
    }

    #[test]
    fn line_without_private_key_text_is_untouched_fast_path() {
        let line = "nothing interesting here";
        let r = process_line(line);
        assert_eq!(r.text, line);
        assert_eq!(r.pairs_redacted, 0);
    }

    #[test]
    fn redaction_never_crosses_a_physical_line_boundary() {
        let text = "-----BEGIN PRIVATE KEY-----\nunrelated json record\n-----END PRIVATE KEY-----";
        let r = redact_pem_blocks(text);
        assert_eq!(
            r.pairs_redacted, 0,
            "must not pair BEGIN/END across real newlines"
        );
        assert_eq!(r.orphan_begin, 1);
        assert_eq!(r.orphan_end, 1);
        assert_eq!(r.text, text);
    }

    #[test]
    fn marker_gap_never_case_folds_across_lowercase_body_text() {
        let line = "-----BEGIN PRIVATE KEY----- lowercase body one -----END PRIVATE KEY----- -----BEGIN PRIVATE KEY----- lowercase body two -----END PRIVATE KEY-----";
        let r = process_line(line);
        assert_eq!(
            r.pairs_redacted, 2,
            "each block must redact independently, not merge into one giant match"
        );
        assert_eq!(r.text, "[REDACTED-private-key] [REDACTED-private-key]");
    }

    #[test]
    fn key_material_never_survives_even_with_an_unrelated_marker_look_alike_in_the_body() {
        let line = "-----BEGIN PRIVATE KEY----- MIIEvQSECRETMATERIAL -----BEGIN CERTIFICATE----- -----END PRIVATE KEY-----";
        let r = process_line(line);
        assert_eq!(
            r.orphan_begin, 0,
            "the real BEGIN must pair with the real END, not get orphaned by a bogus bridged match"
        );
        assert_eq!(r.pairs_redacted, 1);
        assert!(
            !r.text.contains("SECRETMATERIAL"),
            "key material must be inside the redacted span"
        );
    }

    #[test]
    fn a_non_private_key_marker_never_produces_a_match() {
        let line = "-----BEGIN CERTIFICATE----- -----END PRIVATE KEY-----";
        let r = process_line(line);
        assert_eq!(r.pairs_redacted, 0);
        assert_eq!(r.orphan_end, 1);
        assert_eq!(r.text, line);
    }

    // LIFO stack-matching shares balanced-bracket matching's non-crossing guarantee; the abort branch is believed unreachable here, kept only as a safety net for future reuse with less well-behaved delimiters.

    #[test]
    fn lifo_lawfully_matched_pairs_never_trigger_the_crossing_abort() {
        let line = "-----BEGIN PRIVATE KEY----- a -----BEGIN PRIVATE KEY----- b -----END PRIVATE KEY----- c -----END PRIVATE KEY-----";
        let r = process_line(line);
        assert!(!r.aborted);
        assert_eq!(
            r.pairs_redacted, 1,
            "nested pair collapses to the single outer span"
        );
    }

    #[test]
    fn idempotent_on_already_redacted_text() {
        let line = "prefix -----BEGIN PRIVATE KEY----- abc -----END PRIVATE KEY----- suffix";
        let first = process_line(line);
        let second = process_line(&first.text);
        assert_eq!(second.pairs_redacted, 0);
        assert_eq!(second.text, first.text);
    }
}
