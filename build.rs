use std::path::Path;
use std::process::Command;

mod build_rev;

use build_rev::{Revision, is_own_checkout, parse_vcs_info, resolve_revision};

fn git(dir: &str, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

// Both sides are canonicalized before comparison because the manifest dir and git's answer can spell the same directory differently (a symlinked /tmp, a worktree), and a spurious mismatch would stamp every build `unknown`.
fn canonical(path: &str) -> Option<String> {
    Some(std::fs::canonicalize(path).ok()?.to_str()?.to_string())
}

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());

    let packaged = std::fs::read_to_string(Path::new(&dir).join(".cargo_vcs_info.json"))
        .ok()
        .as_deref()
        .and_then(parse_vcs_info);

    // Probed only when there is no packaged revision, so a crates.io build never shells out to git at all.
    let head = if packaged.is_some() {
        None
    } else {
        let manifest = canonical(&dir).unwrap_or_else(|| dir.clone());
        let own = git(&dir, &["ls-files", "--error-unmatch", "Cargo.toml"]).is_some()
            && is_own_checkout(
                git(&dir, &["rev-parse", "--show-toplevel"])
                    .and_then(|top| canonical(&top))
                    .as_deref(),
                &manifest,
            );
        own.then(|| git(&dir, &["rev-parse", "--short=12", "HEAD"]))
            .flatten()
    };

    let revision = resolve_revision(packaged, head);

    match &revision {
        Revision::Packaged { .. } => println!("cargo:rerun-if-changed=.cargo_vcs_info.json"),
        Revision::Git(_) => {
            // --git-path resolves through a worktree, where .git is a file rather than a directory.
            for spec in ["HEAD", "logs/HEAD"] {
                if let Some(path) = git(&dir, &["rev-parse", "--git-path", spec]) {
                    println!("cargo:rerun-if-changed={path}");
                }
            }
        }
        Revision::Unknown => {}
    }

    println!("cargo:rustc-env=REDACTO_BUILD_REV={}", revision.stamp());
}
