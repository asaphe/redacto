use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use globset::GlobSet;
use walkdir::WalkDir;

use super::redact::{RedactSummary, redact_jsonl, redact_text};
use super::validity::{FileKind, is_valid};
use super::watermark::Watermark;
use crate::patterns::Pattern;

pub struct ScanOptions {
    pub write: bool,
    pub exclude: GlobSet,
    // Files modified more recently than this are treated as possibly still being written and skipped, mirroring the "never rewrite a live session's own transcript" rule.
    pub live_window: Duration,
    pub state_path: PathBuf,
    pub include_pem: bool,
}

pub enum FileOutcome {
    Skipped {
        reason: SkipReason,
    },
    Clean,
    Redacted {
        summary: RedactSummary,
        written: bool,
        unsafe_lines: Vec<usize>,
    },
    ValidationFailed {
        summary: RedactSummary,
    },
}

pub enum SkipReason {
    Excluded,
    PossiblyLive,
    Unchanged,
    ReadError,
}

pub struct ScanResult {
    pub path: PathBuf,
    pub outcome: FileOutcome,
}

// A root path that doesn't exist or can't be walked — reported, not silently swallowed (a typo'd path used to produce zero output and exit 0).
pub struct RootError {
    pub path: PathBuf,
    pub message: String,
}

pub struct ScanReport {
    pub results: Vec<ScanResult>,
    pub root_errors: Vec<RootError>,
}

pub fn scan_paths(
    paths: &[PathBuf],
    patterns: &[Pattern],
    opts: &ScanOptions,
) -> Result<ScanReport> {
    let mut watermark = Watermark::load(&opts.state_path);
    let mut results = Vec::new();
    let mut root_errors = Vec::new();

    for root in paths {
        if !root.exists() {
            root_errors.push(RootError {
                path: root.clone(),
                message: "path does not exist".to_string(),
            });
            continue;
        }
        if root.is_file() {
            results.push(scan_one(root, patterns, opts, &mut watermark));
            continue;
        }
        for entry in WalkDir::new(root) {
            match entry {
                Ok(e) if e.file_type().is_file() => {
                    results.push(scan_one(e.path(), patterns, opts, &mut watermark));
                }
                Ok(_) => {}
                Err(e) => root_errors.push(RootError {
                    path: root.clone(),
                    message: e.to_string(),
                }),
            }
        }
    }

    watermark
        .save(&opts.state_path)
        .context("failed to persist scan watermark")?;
    Ok(ScanReport {
        results,
        root_errors,
    })
}

fn scan_one(
    path: &Path,
    patterns: &[Pattern],
    opts: &ScanOptions,
    watermark: &mut Watermark,
) -> ScanResult {
    let path_buf = path.to_path_buf();
    let skip = |reason| ScanResult {
        path: path_buf.clone(),
        outcome: FileOutcome::Skipped { reason },
    };

    if opts.exclude.is_match(path) {
        return skip(SkipReason::Excluded);
    }

    let Ok(metadata) = std::fs::metadata(path) else {
        return skip(SkipReason::ReadError);
    };
    let mtime = metadata.modified().unwrap_or(SystemTime::now());
    let size = metadata.len();

    // A future mtime (clock skew, restored backup) makes duration_since fail; treating that as "definitely live" would skip the file forever. Fail toward scanning it, not toward a silent permanent miss.
    let elapsed_since_mtime = SystemTime::now()
        .duration_since(mtime)
        .unwrap_or(Duration::MAX);
    if elapsed_since_mtime < opts.live_window {
        return skip(SkipReason::PossiblyLive);
    }

    if watermark.is_unchanged(path, mtime, size) {
        return skip(SkipReason::Unchanged);
    }

    let Ok(original) = std::fs::read_to_string(path) else {
        return skip(SkipReason::ReadError);
    };

    let kind = FileKind::detect(path, &original);
    let (redacted, summary, unsafe_lines) = match kind {
        FileKind::Jsonl => {
            let (text, summary, failed) = redact_jsonl(&original, patterns, opts.include_pem);
            (text, summary, failed)
        }
        FileKind::Json | FileKind::PlainText => {
            let (text, summary) = redact_text(&original, patterns, opts.include_pem);
            (text, summary, Vec::new())
        }
    };

    // A file needs a human before it can be considered resolved if anything was left deliberately untouched — not just when nothing at all matched. An orphan/aborted PEM marker or an unsafe JSONL line is exactly that: real sensitive content the scan chose not to touch, not a "nothing here" result.
    let has_unresolved = summary.has_pem_concern() || !unsafe_lines.is_empty();

    if summary.total_redactions() == 0 && !has_unresolved {
        watermark.record(path, mtime, size);
        return ScanResult {
            path: path_buf,
            outcome: FileOutcome::Clean,
        };
    }

    if matches!(kind, FileKind::Json | FileKind::PlainText) && !is_valid(&kind, &redacted) {
        // Not recorded in the watermark on purpose: an invalid result must be retried next scan, not silently skipped forever.
        return ScanResult {
            path: path_buf,
            outcome: FileOutcome::ValidationFailed { summary },
        };
    }

    let mut written = false;
    if opts.write
        && summary.total_redactions() > 0
        && let Some((new_mtime, new_size)) = write_atomically(path, &redacted, mtime, size)
    {
        written = true;
        // A file can have both a successfully-redacted secret AND an unresolved PEM orphan/abort or unsafe line in the same pass. Recording the watermark here would make the resolved part's write look like "this file is fully handled" and silently hide the still-unresolved part on every future scan. Only mark it seen when nothing is left outstanding.
        if !has_unresolved {
            watermark.record(path, new_mtime, new_size);
        }
    }

    ScanResult {
        path: path_buf,
        outcome: FileOutcome::Redacted {
            summary,
            written,
            unsafe_lines,
        },
    }
}

// Writes via a temp file + rename (never truncates in place, so a crash mid-write can't corrupt the original) and re-stats immediately before the rename to narrow the TOCTOU window against a concurrent writer. Returns the post-write (mtime, size) on success so the caller can decide whether recording the watermark is actually correct for this file, rather than doing it unconditionally here.
fn write_atomically(
    path: &Path,
    redacted: &str,
    expected_mtime: SystemTime,
    expected_size: u64,
) -> Option<(SystemTime, u64)> {
    let Ok(current_meta) = std::fs::metadata(path) else {
        return None;
    };
    let current_mtime = current_meta.modified().unwrap_or(SystemTime::now());
    if current_mtime != expected_mtime || current_meta.len() != expected_size {
        return None;
    }

    let tmp_path = path.with_extension(format!(
        "redacto-tmp-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if std::fs::write(&tmp_path, redacted).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return None;
    }
    // The temp file is born with the umask default, so a 600 log would come back 644 after the rename.
    if std::fs::set_permissions(&tmp_path, current_meta.permissions()).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return None;
    }
    if std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return None;
    }

    std::fs::metadata(path).ok().map(|new_meta| {
        let new_mtime = new_meta.modified().unwrap_or(SystemTime::now());
        (new_mtime, new_meta.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::all_patterns;
    use globset::GlobSetBuilder;
    use std::fs;

    fn opts(state_path: PathBuf, write: bool) -> ScanOptions {
        ScanOptions {
            write,
            exclude: GlobSetBuilder::new().build().unwrap(),
            live_window: Duration::ZERO,
            state_path,
            include_pem: true,
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_redacting_write_preserves_the_original_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("private.log");
        // Built rather than spelled out, as secrets.rs's own AWS fixture is.
        let fixture = format!("leak AKIA{} here\n", "ABCDEFGHIJKLMNOP");
        fs::write(&file_path, &fixture).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

        let report = scan_paths(
            std::slice::from_ref(&file_path),
            &all_patterns(),
            &opts(dir.path().join("watermark.json"), true),
        )
        .unwrap();
        let written = match &report.results[0].outcome {
            FileOutcome::Redacted { written, .. } => *written,
            _ => panic!("expected a Redacted outcome"),
        };

        assert!(written, "the fixture must actually be rewritten");
        // 0o600 as a literal: comparing against the mode read back would pass for any value.
        let mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "an owner-only log must not come back group/world-readable after redaction"
        );
    }

    #[test]
    fn orphan_pem_marker_alone_is_not_reported_clean_and_is_never_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("leak.log");
        // BEGIN with no matching END anywhere in the file — the exact shape that used to report Clean with the key left untouched.
        fs::write(
            &file_path,
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n",
        )
        .unwrap();
        let state_path = dir.path().join("watermark.json");
        let patterns = all_patterns();

        let report = scan_paths(
            std::slice::from_ref(&file_path),
            &patterns,
            &opts(state_path.clone(), false),
        )
        .unwrap();
        assert_eq!(report.results.len(), 1);
        match &report.results[0].outcome {
            FileOutcome::Redacted { summary, .. } => {
                assert!(
                    summary.has_pem_concern(),
                    "orphan BEGIN must be surfaced, not silently dropped"
                );
                assert_eq!(summary.pem_orphan_begin, 1);
            }
            FileOutcome::Clean => {
                panic!("an unresolved orphan PEM marker must never be reported Clean")
            }
            _ => panic!("unexpected outcome for an orphan-only file"),
        }

        // Re-scan against the same watermark file: an unresolved concern must never be silently skipped on a later run.
        let report2 = scan_paths(&[file_path], &patterns, &opts(state_path, false)).unwrap();
        match &report2.results[0].outcome {
            FileOutcome::Skipped { .. } => {
                panic!("an unresolved orphan PEM marker must be re-flagged every scan, not skipped")
            }
            FileOutcome::Redacted { summary, .. } => assert!(summary.has_pem_concern()),
            _ => panic!("unexpected outcome on re-scan"),
        }
    }

    #[test]
    fn partial_write_with_unresolved_pem_orphan_is_still_flagged_on_the_next_scan() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("mixed.log");
        // One redactable secret plus one PEM BEGIN with no END anywhere — the file both gets written AND still has something unresolved in the same pass.
        fs::write(
            &file_path,
            "AKIAABCDEFGHIJKLMNOP\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n",
        )
        .unwrap();
        let state_path = dir.path().join("watermark.json");
        let patterns = all_patterns();

        let report = scan_paths(
            std::slice::from_ref(&file_path),
            &patterns,
            &opts(state_path.clone(), true),
        )
        .unwrap();
        let (summary1, written1) = match &report.results[0].outcome {
            FileOutcome::Redacted {
                summary, written, ..
            } => (summary, *written),
            _ => panic!("expected a Redacted outcome"),
        };
        assert!(written1, "the AWS key must actually get written");
        assert!(summary1.pattern_counts.contains_key("aws-access-token"));
        assert!(
            summary1.has_pem_concern(),
            "the orphan BEGIN must still be flagged even though something else in the file was fixed"
        );

        let written_content = fs::read_to_string(&file_path).unwrap();
        assert!(written_content.contains("[REDACTED-aws-access-token]"));
        assert!(
            written_content.contains("-----BEGIN PRIVATE KEY-----"),
            "the unresolved orphan must be left untouched, not guessed at"
        );

        // Re-scan against the same watermark: the file must NOT be silently skipped just because the resolved part of it was already written.
        let report2 = scan_paths(&[file_path], &patterns, &opts(state_path, true)).unwrap();
        match &report2.results[0].outcome {
            FileOutcome::Skipped { .. } => panic!(
                "a file with an unresolved PEM orphan must never be silently skipped after a partial write"
            ),
            FileOutcome::Redacted {
                summary, written, ..
            } => {
                assert!(
                    summary.has_pem_concern(),
                    "the orphan must still be reported on every subsequent scan"
                );
                assert!(
                    !written,
                    "nothing new to write on the second pass — the secret was already redacted"
                );
            }
            _ => panic!("unexpected outcome on re-scan"),
        }
    }
}
