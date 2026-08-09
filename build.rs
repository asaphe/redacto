use std::path::Path;
use std::process::Command;

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

// `cargo package` records the true revision here; a packaged crate has no .git to probe.
fn packaged_revision(dir: &str) -> Option<String> {
    let text = std::fs::read_to_string(Path::new(dir).join(".cargo_vcs_info.json")).ok()?;
    let sha = text
        .split("\"sha1\"")
        .nth(1)?
        .split('"')
        .nth(1)?
        .to_string();
    (sha.len() >= 12).then(|| sha[..12].to_string())
}

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());

    if let Some(sha) = packaged_revision(&dir) {
        println!("cargo:rerun-if-changed=.cargo_vcs_info.json");
        println!("cargo:rustc-env=REDACTO_BUILD_REV={sha}");
        return;
    }

    // git resolves the NEAREST enclosing repo, so an extracted copy inside an unrelated repo would otherwise be stamped with that repo's revision — a wrong SHA is worse than none.
    let tracked = git(&dir, &["ls-files", "--error-unmatch", "Cargo.toml"]).is_some();

    let revision = if tracked {
        git(&dir, &["rev-parse", "--short=12", "HEAD"])
    } else {
        None
    };

    match revision {
        Some(sha) => {
            // --git-path resolves through a worktree, where .git is a file rather than a directory.
            for spec in ["HEAD", "logs/HEAD"] {
                if let Some(path) = git(&dir, &["rev-parse", "--git-path", spec]) {
                    println!("cargo:rerun-if-changed={path}");
                }
            }
            println!("cargo:rustc-env=REDACTO_BUILD_REV={sha}");
        }
        None => println!("cargo:rustc-env=REDACTO_BUILD_REV=unknown"),
    }
}
