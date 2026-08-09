// Pure half of the build-time revision lookup, split out of build.rs so the packaged-crate and wrong-enclosing-repo cases are testable without a filesystem or a git repo (`cargo test` never runs a build script's own tests) — and every item here must also be used by build.rs, because this file compiles into the build script as well as the test crate and `clippy -D warnings` fails the build-script compile on an item only the tests use.

#[derive(Debug, PartialEq, Eq)]
pub enum Revision {
    Packaged { sha: String, dirty: bool },
    Git(String),
    Unknown,
}

impl Revision {
    // A crate packaged from a modified tree is not what its commit contains, so the stamp says so rather than asserting a provenance the artifact does not have.
    pub fn stamp(&self) -> String {
        match self {
            Revision::Packaged { sha, dirty } => {
                if *dirty {
                    format!("{sha}-dirty")
                } else {
                    sha.clone()
                }
            }
            Revision::Git(sha) => sha.clone(),
            Revision::Unknown => "unknown".to_string(),
        }
    }
}

// Parsed as JSON rather than split on the key: splitting takes the first `"sha1"` anywhere in the document, so a sibling object hands back a sha from the wrong one and a half-written file still answers confidently.
pub fn parse_vcs_info(vcs_info: &str) -> Option<(String, bool)> {
    let value: serde_json::Value = serde_json::from_str(vcs_info).ok()?;
    let git = value.get("git")?;
    let sha1 = git.get("sha1")?.as_str()?;
    // Char-wise rather than `sha1[..12]`, which panics on a byte index landing mid-character — and a panic in a build script aborts the consumer's build.
    let short: String = sha1.chars().take(12).collect();
    (short.chars().count() == 12).then(|| {
        let dirty = git
            .get("dirty")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        (short, dirty)
    })
}

// git resolves the NEAREST enclosing repo, so a copy vendored inside an unrelated repository takes that repository's HEAD. Being tracked does not rule this out — a committed `vendor/` subdirectory is tracked — so the repo root must also be this crate's own manifest directory.
pub fn is_own_checkout(repo_toplevel: Option<&str>, manifest_dir: &str) -> bool {
    repo_toplevel == Some(manifest_dir)
}

// No `tracked` flag: build.rs folds that into whether `head` is Some, so every state reachable here is one build.rs can actually produce.
pub fn resolve_revision(packaged: Option<(String, bool)>, head: Option<String>) -> Revision {
    match (packaged, head) {
        (Some((sha, dirty)), _) => Revision::Packaged { sha, dirty },
        (None, Some(sha)) => Revision::Git(sha),
        (None, None) => Revision::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured verbatim from `cargo package` (cargo 1.94): pretty-printed, with a space after each colon. Hand-written fixtures were minified, a shape cargo never emits, so a parser tightened to `"sha1":"` would pass the suite while returning None for every real crate.
    const REAL: &str = "{\n  \"git\": {\n    \"sha1\": \"adf46f3611a0af812f1e22ca8e92f5fd5ca1ca8e\"\n  },\n  \"path_in_vcs\": \"\"\n}";
    const REAL_DIRTY: &str = "{\n  \"git\": {\n    \"sha1\": \"adf46f3611a0af812f1e22ca8e92f5fd5ca1ca8e\",\n    \"dirty\": true\n  },\n  \"path_in_vcs\": \"\"\n}";

    #[test]
    fn the_shape_cargo_actually_writes_parses() {
        assert_eq!(
            parse_vcs_info(REAL),
            Some(("adf46f3611a0".to_string(), false))
        );
    }

    #[test]
    fn a_crate_packaged_from_a_modified_tree_is_not_stamped_as_that_commit() {
        assert_eq!(
            parse_vcs_info(REAL_DIRTY),
            Some(("adf46f3611a0".to_string(), true))
        );
        assert_eq!(
            resolve_revision(parse_vcs_info(REAL_DIRTY), None).stamp(),
            "adf46f3611a0-dirty"
        );
    }

    #[test]
    fn a_sha_in_a_sibling_object_is_not_mistaken_for_the_git_one() {
        let json = "{\"vendored\":{\"sha1\":\"deadbeefdeadbeefdeadbeef\"},\"git\":{\"sha1\":\"0123456789abcdef0123456789abcdef01234567\"}}";
        assert_eq!(
            parse_vcs_info(json).map(|(sha, _)| sha),
            Some("0123456789ab".to_string())
        );
    }

    #[test]
    fn a_half_written_file_yields_nothing_rather_than_a_confident_answer() {
        assert_eq!(
            parse_vcs_info("{\"git\":{\"sha1\":\"0123456789abcdef"),
            None
        );
    }

    #[test]
    fn a_multi_byte_sha_is_truncated_by_character_instead_of_panicking() {
        assert_eq!(
            parse_vcs_info("{\"git\":{\"sha1\":\"abcdefghijk\u{2026}\"}}"),
            Some(("abcdefghijk\u{2026}".to_string(), false))
        );
    }

    // Every length below the short form, not one sample: the guard width and the truncation width are separate literals, and a threshold anywhere between them passes a single-sample test while slicing out of bounds.
    #[test]
    fn every_sha_shorter_than_the_short_form_is_rejected() {
        for len in 0..12 {
            let json = format!("{{\"git\":{{\"sha1\":\"{}\"}}}}", "a".repeat(len));
            assert_eq!(
                parse_vcs_info(&json),
                None,
                "{len}-char sha must be rejected"
            );
        }
        let json = format!("{{\"git\":{{\"sha1\":\"{}\"}}}}", "a".repeat(12));
        assert_eq!(parse_vcs_info(&json), Some(("a".repeat(12), false)));
    }

    #[test]
    fn a_copy_vendored_inside_another_repo_is_not_our_own_checkout() {
        assert!(is_own_checkout(Some("/a/redacto"), "/a/redacto"));
        assert!(!is_own_checkout(Some("/a"), "/a/vendor/redacto"));
        assert!(!is_own_checkout(None, "/a/redacto"));
    }

    // Only states build.rs can actually produce. The previous tests asserted on (packaged, tracked, head) triples the caller cannot construct, so they could neither fail on a real defect nor pass on real correctness.
    #[test]
    fn the_three_reachable_states_resolve_as_documented() {
        assert_eq!(
            resolve_revision(Some(("abc123def456".to_string(), false)), None),
            Revision::Packaged {
                sha: "abc123def456".to_string(),
                dirty: false
            }
        );
        assert_eq!(
            resolve_revision(None, Some("999999999999".to_string())),
            Revision::Git("999999999999".to_string())
        );
        assert_eq!(resolve_revision(None, None), Revision::Unknown);
    }

    #[test]
    fn stamps_render_the_way_the_binary_reports_them() {
        assert_eq!(
            Revision::Git("abc123def456".to_string()).stamp(),
            "abc123def456"
        );
        assert_eq!(
            Revision::Packaged {
                sha: "abc123def456".to_string(),
                dirty: true
            }
            .stamp(),
            "abc123def456-dirty"
        );
        assert_eq!(Revision::Unknown.stamp(), "unknown");
    }
}
