use std::process::Command;

// A bare "0.1.0" on every build makes an install predating a fix indistinguishable from a current one — which is how a build missing a shipped security fix stayed live and undetected.
fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");

    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // A crates.io or tarball install has no git metadata; "unknown" is honest where a fake SHA is not.
    let sha = sha.unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let suffix = if dirty { "-dirty" } else { "" };
    println!("cargo:rustc-env=REDACTO_BUILD_REV={sha}{suffix}");
}
