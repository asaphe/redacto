use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use globset::{Glob, GlobSetBuilder};

use redacto::config::load_custom_patterns;
use redacto::engine::scan::{FileOutcome, ScanOptions, ScanReport, SkipReason, scan_paths};
use redacto::patterns::{Pattern, PatternSet};

#[derive(Parser)]
#[command(
    name = "redacto",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("REDACTO_BUILD_REV"), ")"),
    about = "Redacts secrets and infra identifiers from files in place, safely and repeatedly."
)]
struct Cli {
    /// One or more files or directories to scan.
    paths: Vec<PathBuf>,
    /// Actually rewrite files; without this, only report what would change.
    #[arg(long)]
    write: bool,
    /// Path to a redacto.toml with a [patterns].custom list.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Directory for the incremental-scan watermark file.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Glob to exclude from scanning (repeatable).
    #[arg(long = "exclude")]
    exclude: Vec<String>,
    /// Skip files modified more recently than this many seconds (possibly still being written).
    #[arg(long, default_value_t = 300)]
    live_window_secs: u64,
    /// Which rules to apply: "secrets" (default, safe for personal logs), "infra" (identifiers only, for sanitizing before sharing), or "all".
    #[arg(long, value_enum, default_value = "secrets")]
    patterns: PatternSet,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.paths.is_empty() {
        eprintln!("redacto: at least one path is required");
        std::process::exit(64);
    }

    let mut patterns: Vec<Pattern> = cli.patterns.patterns();
    let custom_regexes: Vec<regex::Regex> = cli
        .config
        .as_deref()
        .map(load_custom_patterns)
        .unwrap_or_default();
    patterns.extend(custom_regexes_to_patterns(custom_regexes));

    let mut exclude_builder = GlobSetBuilder::new();
    for pattern in &cli.exclude {
        exclude_builder.add(Glob::new(pattern)?);
    }
    let exclude = exclude_builder.build()?;

    let state_path = match cli.state_dir {
        Some(dir) => dir.join("watermark.json"),
        None => redacto::engine::watermark::default_state_path(),
    };

    let opts = ScanOptions {
        write: cli.write,
        exclude,
        live_window: Duration::from_secs(cli.live_window_secs),
        state_path,
        include_pem: cli.patterns.includes_pem(),
    };

    let scan_report = scan_paths(&cli.paths, &patterns, &opts)?;
    let trouble = report(&scan_report, cli.write);
    if trouble {
        std::process::exit(1);
    }
    Ok(())
}

fn custom_regexes_to_patterns(regexes: Vec<regex::Regex>) -> Vec<Pattern> {
    regexes
        .into_iter()
        .map(|r| Box::leak(Box::new(r)) as &'static regex::Regex)
        .map(|r| Pattern::simple("custom", r))
        .collect()
}

// Returns true if anything means a cron/CI caller should treat this run as not fully clean: a validation failure, an unsafe line left untouched, an unresolved PEM orphan/abort, or a root path that couldn't be scanned at all.
fn report(scan_report: &ScanReport, write_mode: bool) -> bool {
    let mut redacted_files = 0usize;
    let mut total_redactions = 0usize;
    let mut validation_failures = 0usize;
    let mut possibly_live_skips = 0usize;
    let mut unsafe_line_files = 0usize;
    let mut pem_concern_files = 0usize;

    for r in &scan_report.results {
        match &r.outcome {
            FileOutcome::Redacted {
                summary,
                written,
                unsafe_lines,
            } => {
                redacted_files += 1;
                total_redactions += summary.total_redactions();
                let mode = if *written { "written" } else { "dry-run" };
                println!(
                    "{} [{}] {} redaction(s): {:?}",
                    r.path.display(),
                    mode,
                    summary.total_redactions(),
                    summary.pattern_counts
                );
                if summary.has_pem_concern() {
                    pem_concern_files += 1;
                }
                if !summary.pem_aborted_lines.is_empty() {
                    println!(
                        "  ! private-key structural ambiguity on line(s) {:?} — left untouched, needs manual review",
                        summary.pem_aborted_lines
                    );
                }
                if summary.pem_orphan_begin > 0 || summary.pem_orphan_end > 0 {
                    println!(
                        "  ! {} orphan BEGIN / {} orphan END marker(s) with no same-line pair — left untouched",
                        summary.pem_orphan_begin, summary.pem_orphan_end
                    );
                }
                if !unsafe_lines.is_empty() {
                    unsafe_line_files += 1;
                    println!(
                        "  ! line(s) {unsafe_lines:?} would break JSON if redacted — left untouched, needs manual review"
                    );
                }
            }
            FileOutcome::ValidationFailed { summary } => {
                validation_failures += 1;
                println!(
                    "{} FAILED validity gate, NOT written: {:?}",
                    r.path.display(),
                    summary.pattern_counts
                );
            }
            FileOutcome::Skipped { reason } => match reason {
                SkipReason::ReadError => println!("{} skipped (read error)", r.path.display()),
                SkipReason::PossiblyLive => possibly_live_skips += 1,
                SkipReason::Excluded | SkipReason::Unchanged => {}
            },
            FileOutcome::Clean => {}
        }
    }

    for err in &scan_report.root_errors {
        eprintln!("{}: {}", err.path.display(), err.message);
    }

    if possibly_live_skips > 0 {
        println!("{possibly_live_skips} file(s) skipped as possibly still being written");
    }

    println!(
        "\nredacto: {redacted_files} file(s) with matches, {total_redactions} total redaction(s), {validation_failures} validation failure(s), {unsafe_line_files} file(s) with unsafe lines, {pem_concern_files} file(s) with unresolved PEM markers, write_mode={write_mode}"
    );

    validation_failures > 0
        || unsafe_line_files > 0
        || pem_concern_files > 0
        || !scan_report.root_errors.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redacto::engine::redact::RedactSummary;
    use std::path::PathBuf;

    #[test]
    fn unresolved_pem_orphan_makes_the_run_trouble_even_with_zero_redactions() {
        let summary = RedactSummary {
            pem_orphan_begin: 1,
            ..Default::default()
        };
        assert_eq!(summary.total_redactions(), 0);
        let scan_report = ScanReport {
            results: vec![redacto::engine::scan::ScanResult {
                path: PathBuf::from("leak.log"),
                outcome: FileOutcome::Redacted {
                    summary,
                    written: false,
                    unsafe_lines: Vec::new(),
                },
            }],
            root_errors: Vec::new(),
        };

        assert!(
            report(&scan_report, false),
            "a file with an unresolved PEM orphan and nothing else must still trip the exit-code trouble signal, so a CI/cron caller relying on the exit code actually sees it"
        );
    }
}
