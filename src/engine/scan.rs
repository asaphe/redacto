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

    if summary.total_redactions() == 0 && unsafe_lines.is_empty() {
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
    if opts.write && summary.total_redactions() > 0 {
        written = write_atomically(path, &redacted, mtime, size, watermark);
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

// Writes via a temp file + rename (never truncates in place, so a crash mid-write can't corrupt the original) and re-stats immediately before the rename to narrow the TOCTOU window against a concurrent writer.
fn write_atomically(
    path: &Path,
    redacted: &str,
    expected_mtime: SystemTime,
    expected_size: u64,
    watermark: &mut Watermark,
) -> bool {
    let Ok(current_meta) = std::fs::metadata(path) else {
        return false;
    };
    let current_mtime = current_meta.modified().unwrap_or(SystemTime::now());
    if current_mtime != expected_mtime || current_meta.len() != expected_size {
        return false;
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
        return false;
    }
    if std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }

    if let Ok(new_meta) = std::fs::metadata(path) {
        let new_mtime = new_meta.modified().unwrap_or(SystemTime::now());
        watermark.record(path, new_mtime, new_meta.len());
    }
    true
}
