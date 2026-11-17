use std::io::Write;
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

// Writes via a temp file + rename (never truncates in place, so a crash mid-write can't corrupt the original). Returns the replacement's (mtime, size), taken from the temp file before it is published, so the caller can decide whether recording the watermark is actually correct for this file.
pub(crate) fn write_atomically(
    path: &Path,
    redacted: &str,
    expected_mtime: SystemTime,
    expected_size: u64,
) -> Option<(SystemTime, u64)> {
    write_atomically_observed(path, redacted, expected_mtime, expected_size, &mut |_| {})
}

// The points where a concurrent writer's append is most dangerous; tests inject one at each.
#[derive(Clone, Copy, PartialEq, Debug)]
enum WritePhase {
    TempWritten,
    Published,
}

fn write_atomically_observed(
    path: &Path,
    redacted: &str,
    expected_mtime: SystemTime,
    expected_size: u64,
    observe: &mut dyn FnMut(WritePhase),
) -> Option<(SystemTime, u64)> {
    let unchanged = || -> Option<std::fs::Metadata> {
        let meta = std::fs::metadata(path).ok()?;
        (meta.modified().ok()? == expected_mtime && meta.len() == expected_size).then_some(meta)
    };
    let current_meta = unchanged()?;

    let tmp_path = path.with_extension(format!(
        "redacto-tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let written = (|| -> std::io::Result<(SystemTime, u64)> {
        let mut file = create_exclusive(&tmp_path, &current_meta.permissions())?;
        file.write_all(redacted.as_bytes())?;
        // Created at most as permissive as the original (mode & ~umask); this restores the exact mode, so a 600 log stays 600.
        file.set_permissions(current_meta.permissions())?;
        file.sync_all()?;
        // Stamped before publishing: a stat after the rename could include an append the scan never read.
        let meta = file.metadata()?;
        Ok((meta.modified()?, meta.len()))
    })();
    let Ok(stamp) = written else {
        let _ = std::fs::remove_file(&tmp_path);
        return None;
    };
    observe(WritePhase::TempWritten);
    // Re-checked after the temp write, not only before it: an append during a large write would otherwise be renamed away.
    if unchanged().is_none() || std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return None;
    }
    observe(WritePhase::Published);
    sync_parent_dir(path);
    Some(stamp)
}

// create_new refuses a path that already exists (a planted file or symlink), and the initial mode is never wider than the original's.
fn create_exclusive(
    path: &Path,
    permissions: &std::fs::Permissions,
) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(permissions.mode() & 0o7777);
    }
    #[cfg(not(unix))]
    let _ = permissions;
    options.open(path)
}

// Durability only: the rename already happened, so a failure here is not a failed write.
fn sync_parent_dir(path: &Path) {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
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

    fn stamp_of(path: &Path) -> (SystemTime, u64) {
        let meta = fs::metadata(path).unwrap();
        (meta.modified().unwrap(), meta.len())
    }

    fn leftover_temps(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("redacto-tmp-"))
            .collect()
    }

    #[test]
    fn write_atomically_returns_the_published_files_own_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        fs::write(&path, "before\n").unwrap();
        let (mtime, size) = stamp_of(&path);

        let stamp = write_atomically(&path, "after!!\n", mtime, size)
            .expect("an unchanged file must be replaced");

        assert_eq!(fs::read_to_string(&path).unwrap(), "after!!\n");
        assert_eq!(
            stamp,
            stamp_of(&path),
            "the returned stamp must be the one the published file carries"
        );
        assert!(
            leftover_temps(dir.path()).is_empty(),
            "no temp file may survive a successful write"
        );
    }

    #[test]
    fn write_atomically_refuses_a_file_that_changed_since_it_was_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        fs::write(&path, "before\n").unwrap();
        let (mtime, size) = stamp_of(&path);
        fs::write(&path, "before\nappended by the session\n").unwrap();

        assert!(write_atomically(&path, "redacted\n", mtime, size).is_none());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "before\nappended by the session\n",
            "the append must survive"
        );
        assert!(
            leftover_temps(dir.path()).is_empty(),
            "a refused write must clean up its temp file"
        );
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn an_append_while_the_replacement_is_written_survives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        fs::write(&path, "before\n").unwrap();
        let (mtime, size) = stamp_of(&path);

        let result = write_atomically_observed(&path, "redacted\n", mtime, size, &mut |phase| {
            if phase == WritePhase::TempWritten {
                append(&path, "appended by the session\n");
            }
        });

        assert!(
            result.is_none(),
            "a file that grew during the temp write must not be replaced"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "before\nappended by the session\n"
        );
        assert!(
            leftover_temps(dir.path()).is_empty(),
            "the refused replacement must be removed"
        );
    }

    #[test]
    fn an_append_after_publishing_is_not_stamped_as_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        fs::write(&path, "before\n").unwrap();
        let (mtime, size) = stamp_of(&path);

        let stamp = write_atomically_observed(&path, "redacted\n", mtime, size, &mut |phase| {
            if phase == WritePhase::Published {
                append(&path, "appended after the rename\n");
            }
        })
        .expect("the replacement itself was published");

        let mut wm = Watermark::default();
        wm.record(&path, stamp.0, stamp.1);
        let (now_mtime, now_size) = stamp_of(&path);
        assert!(
            !wm.is_unchanged(&path, now_mtime, now_size),
            "the recorded stamp must not cover bytes appended after the rename"
        );
    }

    #[test]
    fn a_watermark_save_leaves_no_temp_file_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("watermark.json");
        let target = dir.path().join("x.log");
        fs::write(&target, "x").unwrap();
        let (mtime, size) = stamp_of(&target);
        let mut wm = Watermark::load(&state);
        wm.record(&target, mtime, size);
        wm.save(&state).unwrap();

        assert!(Watermark::load(&state).is_unchanged(&target, mtime, size));
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(!names.iter().any(|n| n.contains(".tmp-")), "{names:?}");
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
