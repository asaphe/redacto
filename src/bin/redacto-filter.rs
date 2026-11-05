use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;

use redacto::config::custom_patterns_with_problems;
use redacto::engine::filter::{filter_event, private_key_block_pattern};
use redacto::patterns::Pattern;
use redacto::patterns::secrets::secret_patterns;

#[derive(Parser)]
#[command(
    name = "redacto-filter",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("REDACTO_BUILD_REV"), ")"),
    about = "Claude Code PostToolUse hook: masks secrets in a tool result before the model and the transcript get it."
)]
struct Cli {
    /// Path to a redacto.toml with a [patterns].custom list.
    #[arg(long)]
    config: Option<PathBuf>,
}

fn run(cli: &Cli) -> Result<Option<String>> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("could not read the hook payload")?;
    let claude_dir = match std::env::var_os("CLAUDE_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".claude"),
    };

    let mut patterns: Vec<Pattern> = vec![private_key_block_pattern()];
    patterns.extend(secret_patterns());
    let (custom, problems) = cli
        .config
        .as_deref()
        .map(custom_patterns_with_problems)
        .unwrap_or_default();
    patterns.extend(custom);

    let mut reply = filter_event(&input, &patterns, &claude_dir)?;
    if !problems.is_empty() {
        let warning = format!(
            "redacto-filter: {}; built-in rules still ran.",
            problems.join("; ")
        );
        let reply = reply.get_or_insert_with(|| {
            json!({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": ""}})
        });
        let context = &mut reply["hookSpecificOutput"]["additionalContext"];
        *context = json!(format!("{warning} {}", context.as_str().unwrap_or("")).trim_end());
    }
    Ok(reply.map(|value| value.to_string()))
}

// Error text names the failure only, never payload content; a non-zero exit with empty stdout is the wrapper's cue to withhold the result.
fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(Some(reply)) => println!("{reply}"),
        Ok(None) => {}
        Err(error) => {
            eprintln!("redacto-filter: {error}");
            std::process::exit(1);
        }
    }
}
