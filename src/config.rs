use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::patterns::Pattern;

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

// The rules that compiled, plus one sentence per thing dropped; those name a position and never a pattern, whose text may be what the user wants kept from a reader.
fn read_custom_patterns(config_path: &Path) -> (Vec<Regex>, Vec<String>) {
    let name = config_path.display();
    let all_off = |what: &str| {
        let problem = format!("{name} {what}, so custom patterns are off");
        eprintln!("redacto: {problem}");
        (Vec::new(), vec![problem])
    };
    let Ok(raw) = std::fs::read_to_string(config_path) else {
        return all_off("is missing or unreadable");
    };
    let Ok(parsed) = toml::from_str::<RawConfig>(&raw) else {
        return all_off("does not parse");
    };

    let mut regexes = Vec::new();
    let mut problems = Vec::new();
    for (index, pattern) in parsed.patterns.custom.into_iter().enumerate() {
        match Regex::new(&pattern) {
            Ok(regex) => regexes.push(regex),
            Err(e) => {
                eprintln!("redacto: skipping invalid custom pattern {pattern:?}: {e}");
                problems.push(format!(
                    "{name} has an invalid custom pattern at position {}, which is off",
                    index + 1
                ));
            }
        }
    }
    (regexes, problems)
}

// User-defined patterns beyond the built-in secret/infra-ID set, compiled from redacto.toml's [patterns].custom list.
pub fn load_custom_patterns(config_path: &Path) -> Vec<Regex> {
    read_custom_patterns(config_path).0
}

// Leaked on purpose: Pattern holds &'static Regex, and a process loads its config once and exits.
fn into_patterns(regexes: Vec<Regex>) -> Vec<Pattern> {
    regexes
        .into_iter()
        .map(|regex| Pattern::simple("custom", Box::leak(Box::new(regex))))
        .collect()
}

pub fn custom_patterns(config_path: &Path) -> Vec<Pattern> {
    into_patterns(load_custom_patterns(config_path))
}

// For a hook, whose stderr reaches nobody: the problems go in its reply instead.
pub fn custom_patterns_with_problems(config_path: &Path) -> (Vec<Pattern>, Vec<String>) {
    let (regexes, problems) = read_custom_patterns(config_path);
    (into_patterns(regexes), problems)
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
