use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const TOKEN: &str = "Zq7Lm2Vt9RzK4pWc8Hy3Nf6Jd1Sb5Ga0Ue7Xq2Tr9Mk4Pv8Y";

fn run(args: &[&str], input: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_redacto-filter"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn bash_event(stdout: &str) -> String {
    json!({"cwd": "/nonexistent-for-test", "tool_response": {"stdout": stdout, "stderr": "", "interrupted": false, "isImage": false}}).to_string()
}

fn config_with_named_rule() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        file,
        "[patterns]\ncustom = [\"__fixture_cookie=[A-Za-z0-9]{{32,}}\"]"
    )
    .unwrap();
    file
}

#[test]
fn a_custom_rule_from_config_masks_and_the_reply_never_holds_the_value() {
    let config = config_with_named_rule();
    let path = config.path().to_str().unwrap();
    let (code, stdout, stderr) = run(
        &["--config", path],
        &bash_event(&format!("__fixture_cookie={TOKEN}")),
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(!stdout.contains(TOKEN));
    let reply: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        reply["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "[REDACTED-custom]"
    );
}

#[test]
fn a_saved_copy_under_a_relocated_claude_dir_is_masked() {
    let claude_dir = tempfile::tempdir().unwrap();
    let dir = claude_dir.path().join("projects/p/s/tool-results");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out.txt");
    std::fs::write(&file, format!("__fixture_cookie={TOKEN}\n")).unwrap();
    let config = config_with_named_rule();
    let event = json!({"cwd": "/nonexistent-for-test", "tool_response": {"stdout": "preview", "persistedOutputPath": file}});

    let mut child = Command::new(env!("CARGO_BIN_EXE_redacto-filter"))
        .args(["--config", config.path().to_str().unwrap()])
        .env("CLAUDE_CONFIG_DIR", claude_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());

    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "[REDACTED-custom]\n"
    );
}

#[test]
fn clean_output_prints_nothing_and_exits_zero() {
    let config = config_with_named_rule();
    let path = config.path().to_str().unwrap();
    let (code, stdout, _) = run(&["--config", path], &bash_event("just some output"));
    assert_eq!((code, stdout.as_str()), (0, ""));
}

#[test]
fn an_unreadable_payload_exits_nonzero_with_nothing_on_stdout() {
    for input in ["", "not json", "{}"] {
        let (code, stdout, stderr) = run(&[], input);
        assert_eq!(code, 1, "{input}");
        assert_eq!(stdout, "");
        assert!(stderr.starts_with("redacto-filter:"), "{stderr}");
    }
}

#[test]
fn a_broken_config_warns_instead_of_silently_dropping_the_rules() {
    for (body, expected) in [
        ("[patterns\ncustom = []", "does not parse"),
        (
            "[patterns]\ncustom = [\"(unclosed\"]",
            "invalid custom pattern",
        ),
    ] {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "{body}").unwrap();
        let path = config.path().to_str().unwrap();
        let (code, stdout, _) = run(&["--config", path], &bash_event("clean output"));
        assert_eq!(code, 0);
        let reply: Value = serde_json::from_str(&stdout).unwrap();
        let context = reply["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert!(context.contains(expected), "{context}");
        assert!(!stdout.contains("(unclosed"), "{stdout}");
    }
}

#[test]
fn an_invalid_pattern_warns_and_the_valid_ones_still_mask() {
    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "[patterns]\ncustom = [\"(unclosed\", \"__fixture_cookie=[A-Za-z0-9]{{32,}}\"]"
    )
    .unwrap();
    let path = config.path().to_str().unwrap();
    let (code, stdout, _) = run(
        &["--config", path],
        &bash_event(&format!("__fixture_cookie={TOKEN}")),
    );
    assert_eq!(code, 0);
    assert!(!stdout.contains(TOKEN));
    let reply: Value = serde_json::from_str(&stdout).unwrap();
    let out = &reply["hookSpecificOutput"];
    assert_eq!(out["updatedToolOutput"]["stdout"], "[REDACTED-custom]");
    assert!(
        out["additionalContext"]
            .as_str()
            .unwrap()
            .contains("invalid custom pattern")
    );
}

#[test]
fn a_missing_config_warns_but_built_in_rules_still_run() {
    let (code, stdout, _) = run(
        &["--config", "/nonexistent/redacto.toml"],
        bash_event(&format!(r#"db_password = "{}""#, &TOKEN[..16])).as_str(),
    );
    assert_eq!(code, 0);
    let reply: Value = serde_json::from_str(&stdout).unwrap();
    let out = &reply["hookSpecificOutput"];
    assert!(
        out["additionalContext"]
            .as_str()
            .unwrap()
            .contains("is missing")
    );
    assert_eq!(
        out["updatedToolOutput"]["stdout"],
        r#"db_password = "[REDACTED-password-assignment]""#
    );

    let (code, stdout, _) = run(
        &["--config", "/nonexistent/redacto.toml"],
        &bash_event("clean output"),
    );
    assert_eq!(code, 0);
    let reply: Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        reply["hookSpecificOutput"]
            .get("updatedToolOutput")
            .is_none()
    );
}
