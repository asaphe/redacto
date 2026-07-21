use std::path::Path;

use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    patterns: PatternsSection,
}

#[derive(Debug, Default, Deserialize)]
struct PatternsSection {
    #[serde(default)]
    custom: Vec<String>,
}

// User-defined patterns beyond the built-in secret/infra-ID set, compiled from redacto.toml's [patterns].custom list.
pub fn load_custom_patterns(config_path: &Path) -> Vec<Regex> {
    let Ok(raw) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    let Ok(parsed) = toml::from_str::<RawConfig>(&raw) else {
        eprintln!("redacto: failed to parse config file {config_path:?}, ignoring");
        return Vec::new();
    };

    parsed
        .patterns
        .custom
        .into_iter()
        .filter_map(|pattern| match Regex::new(&pattern) {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("redacto: skipping invalid custom pattern {pattern:?}: {e}");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_valid_custom_patterns() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[patterns]\ncustom = [\"my-company\", \"internal\\\\.example\\\\.co\"]"
        )
        .unwrap();
        let patterns = load_custom_patterns(file.path());
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn skips_invalid_pattern_but_keeps_valid_ones() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "[patterns]\ncustom = [\"valid-one\", \"(unclosed\"]").unwrap();
        let patterns = load_custom_patterns(file.path());
        assert_eq!(patterns.len(), 1);
    }

    #[test]
    fn missing_config_file_returns_empty() {
        let patterns = load_custom_patterns(Path::new("/nonexistent/redacto.toml"));
        assert!(patterns.is_empty());
    }
}
