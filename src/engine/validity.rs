#[derive(Debug, PartialEq)]
pub enum FileKind {
    Jsonl,
    Json,
    PlainText,
}

fn is_jsonl_shaped(text: &str) -> bool {
    let mut saw_any = false;
    for line in text.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        if serde_json::from_str::<serde_json::Value>(line).is_err() {
            return false;
        }
        saw_any = true;
    }
    saw_any
}

impl FileKind {
    pub fn from_path(path: &std::path::Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("jsonl") => FileKind::Jsonl,
            Some("json") => FileKind::Json,
            _ => FileKind::PlainText,
        }
    }

    // Extension is only a hint: a real ".json"-named file was found in practice to hold JSONL-shaped content (multiple newline-delimited records), which fails whole-file parsing before any redaction touches it — sniff actual content shape rather than trusting the name.
    pub fn detect(path: &std::path::Path, original_content: &str) -> Self {
        let hinted = Self::from_path(path);
        if hinted == FileKind::Json
            && serde_json::from_str::<serde_json::Value>(original_content).is_err()
        {
            if is_jsonl_shaped(original_content) {
                return FileKind::Jsonl;
            }
            return FileKind::PlainText;
        }
        hinted
    }
}

// Never write a redaction that would corrupt the file's own structure — the gate that caught a real regex bug before anything hit disk this project's Python prototype was validated against.
pub fn is_valid(kind: &FileKind, text: &str) -> bool {
    match kind {
        FileKind::Jsonl => text
            .split('\n')
            .filter(|line| !line.trim().is_empty())
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()),
        FileKind::Json => serde_json::from_str::<serde_json::Value>(text).is_ok(),
        // No structural format to check against; guard only against a pathological size blowup.
        FileKind::PlainText => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn valid_jsonl_passes() {
        let text = "{\"a\":1}\n{\"b\":2}\n";
        assert!(is_valid(&FileKind::Jsonl, text));
    }

    #[test]
    fn jsonl_with_broken_line_fails() {
        let text = "{\"a\":1}\n{\"b\": not json\n";
        assert!(!is_valid(&FileKind::Jsonl, text));
    }

    #[test]
    fn jsonl_ignores_blank_lines() {
        let text = "{\"a\":1}\n\n{\"b\":2}\n";
        assert!(is_valid(&FileKind::Jsonl, text));
    }

    #[test]
    fn valid_whole_file_json_passes() {
        let text = "{\"a\": [1, 2, 3]}";
        assert!(is_valid(&FileKind::Json, text));
    }

    #[test]
    fn broken_whole_file_json_fails() {
        let text = "{\"a\": [1, 2, 3]";
        assert!(!is_valid(&FileKind::Json, text));
    }

    #[test]
    fn file_kind_detected_from_extension() {
        assert_eq!(FileKind::from_path(Path::new("x.jsonl")), FileKind::Jsonl);
        assert_eq!(FileKind::from_path(Path::new("x.json")), FileKind::Json);
        assert_eq!(FileKind::from_path(Path::new("x.log")), FileKind::PlainText);
        assert_eq!(FileKind::from_path(Path::new("x.txt")), FileKind::PlainText);
    }

    #[test]
    fn dot_json_file_with_actual_jsonl_content_is_detected_as_jsonl() {
        let content = "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
        assert_eq!(
            FileKind::detect(Path::new("telemetry.json"), content),
            FileKind::Jsonl
        );
    }

    #[test]
    fn dot_json_file_with_real_whole_file_json_stays_json() {
        let content = "{\"a\": [1, 2, 3]}";
        assert_eq!(
            FileKind::detect(Path::new("x.json"), content),
            FileKind::Json
        );
    }

    #[test]
    fn dot_json_file_with_neither_shape_falls_back_to_plain_text() {
        let content = "not json at all, just some log lines\nmore text\n";
        assert_eq!(
            FileKind::detect(Path::new("x.json"), content),
            FileKind::PlainText
        );
    }
}
