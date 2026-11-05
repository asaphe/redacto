use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Value, json};

use super::redact::redact_text;
use super::scan::write_atomically;
use crate::patterns::Pattern;

const EXEMPT_MARKER: &str = ".redacto-exempt";

// A live result is held whole in memory, so unlike a file sweep this may cross lines; requiring a body keeps a bare header in source code or docs readable.
static PRIVATE_KEY_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    const SEP: &str = r"(?:\s|\\n|\\r)+";
    // What `grep -rn`, `grep -n`, `cat -n`, `git diff` or a comment puts before each line.
    const PREFIX: &str = r"[ \t]*(?:\S*:\d+[:\-][ \t]*|\d+[:\-\t ][ \t]*|[-+#>|][ \t]*)?";
    const FOOTER: &str = r"-----END[ A-Z0-9]*PRIVATE KEY[ A-Z]*-----";
    Regex::new(&format!(
        r"-----BEGIN[ A-Z0-9]*PRIVATE KEY[ A-Z]*-----{SEP}(?:{PREFIX}[A-Za-z0-9+/=]{{16,}}(?:{SEP}|$))+(?:{PREFIX}[A-Za-z0-9+/=]{{1,15}}(?:{SEP}|$))?(?:{PREFIX}{FOOTER})?"
    ))
    .unwrap()
});

pub fn private_key_block_pattern() -> Pattern {
    Pattern::simple("private-key", &PRIVATE_KEY_BLOCK_RE)
}

#[derive(Debug, Default)]
struct Masked {
    counts: BTreeMap<String, usize>,
}

impl Masked {
    fn total(&self) -> usize {
        self.counts.values().sum()
    }

    fn scan(&mut self, text: &str, patterns: &[Pattern]) -> Option<String> {
        let (redacted, summary) = redact_text(text, patterns, true);
        if summary.total_redactions() == 0 {
            return None;
        }
        for (id, count) in summary.pattern_counts {
            *self.counts.entry(id).or_insert(0) += count;
        }
        if summary.pem_pairs_redacted > 0 {
            *self.counts.entry("private-key".to_string()).or_insert(0) +=
                summary.pem_pairs_redacted;
        }
        Some(redacted)
    }

    fn walk(&mut self, value: &mut Value, patterns: &[Pattern]) {
        match value {
            Value::String(text) => {
                if let Some(redacted) = self.scan(text, patterns) {
                    *text = redacted;
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|v| self.walk(v, patterns)),
            // A `base64` field is an encoded image or document, which these text rules cannot read and could only corrupt.
            Value::Object(map) => map
                .iter_mut()
                .filter(|(key, _)| key.as_str() != "base64")
                .for_each(|(_, v)| self.walk(v, patterns)),
            _ => {}
        }
    }
}

fn under_exempt_dir(path: &Path) -> bool {
    path.ancestors().any(|dir| dir.join(EXEMPT_MARKER).exists())
}

// A Read is judged by its file, not the session's directory; resolving first stops `..` or a symlink keeping an exemption after leaving the tree.
fn is_exempt(event: &Value) -> bool {
    let target = event
        .pointer("/tool_input/file_path")
        .or_else(|| event.get("cwd"))
        .and_then(Value::as_str);
    target.is_some_and(|raw| {
        let path = Path::new(raw);
        under_exempt_dir(&path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
    })
}

fn is_image(response: &Value) -> bool {
    response.get("isImage").and_then(Value::as_bool) == Some(true)
        || response.get("type").and_then(Value::as_str) == Some("image")
}

// Written before this hook runs and never appended to, so a whole-file rewrite loses nothing; the path check stops a look-alike field aiming the rewrite elsewhere.
fn scrub_persisted_output(
    response: &Value,
    claude_dir: &Path,
    patterns: &[Pattern],
    masked: &mut Masked,
) -> Result<()> {
    let Some(raw) = response.get("persistedOutputPath").and_then(Value::as_str) else {
        return Ok(());
    };
    let path = PathBuf::from(raw)
        .canonicalize()
        .context("the path does not resolve")?;
    let root = claude_dir.join("projects");
    let root = root.canonicalize().unwrap_or(root);
    if !path.starts_with(&root) || !path.iter().any(|part| part == "tool-results") {
        bail!("the path is outside the expected directory");
    }
    let meta = std::fs::metadata(&path)?;
    // Lossy: one stray byte must not leave the rest of the file raw, and only a file that gets rewritten is changed.
    let bytes = std::fs::read(&path)?;
    let text = String::from_utf8_lossy(&bytes);
    if let Some(redacted) = masked.scan(&text, patterns) {
        write_atomically(&path, &redacted, meta.modified()?, meta.len())
            .context("could not rewrite the persisted output")?;
    }
    Ok(())
}

fn notice(masked: &Masked) -> String {
    let rules: Vec<String> = masked
        .counts
        .iter()
        .map(|(id, count)| format!("{id}: {count}"))
        .collect();
    format!(
        "redacto-filter masked {} value(s) in this tool result ({}). The [REDACTED-*] text is not the real output, and the real value did not reach you or the transcript. Do not try to recover it, and do not write [REDACTED-*] text back to a file, which would destroy the real value; if the task needs the value, tell the user.",
        masked.total(),
        rules.join(", ")
    )
}

// Returns the hook reply, or None to leave the result byte-identical; an Err means the event could not be read, and the caller must not treat that as clean.
pub fn filter_event(input: &str, patterns: &[Pattern], claude_dir: &Path) -> Result<Option<Value>> {
    let event: Value = serde_json::from_str(input).context("hook payload is not JSON")?;
    if !event.is_object() {
        bail!("hook payload is not a JSON object");
    }
    let Some(response) = event.get("tool_response").filter(|v| !v.is_null()) else {
        bail!("hook payload has no tool_response");
    };
    if is_exempt(&event) || is_image(response) {
        return Ok(None);
    }

    let mut masked = Masked::default();
    // A saved copy that cannot be checked is a disk problem; the result the model receives can still be masked.
    let file_problem = scrub_persisted_output(response, claude_dir, patterns, &mut masked).err();
    let in_file = masked.total();

    let mut updated = response.clone();
    masked.walk(&mut updated, patterns);
    if masked.total() == 0 && file_problem.is_none() {
        return Ok(None);
    }

    let mut notes = Vec::new();
    if masked.total() > 0 {
        notes.push(notice(&masked));
    }
    if let Some(problem) = file_problem {
        notes.push(format!(
            "redacto-filter could not check the saved copy of this result ({problem:#}), so it may still hold a secret on disk."
        ));
    }
    let mut output = json!({
        "hookEventName": "PostToolUse",
        "additionalContext": notes.join(" "),
    });
    if masked.total() > in_file {
        output["updatedToolOutput"] = updated;
    }
    Ok(Some(json!({ "hookSpecificOutput": output })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::secrets::secret_patterns;

    const TOKEN: &str = "Zq7Lm2Vt9RzK4pWc8Hy3Nf6Jd1Sb5Ga0Ue7Xq2Tr9Mk4Pv8Y";

    fn patterns() -> Vec<Pattern> {
        static NAMED: LazyLock<Regex> =
            LazyLock::new(|| Regex::new("__fixture_cookie=[A-Za-z0-9]{32,}").unwrap());
        let mut all = vec![private_key_block_pattern()];
        all.extend(secret_patterns());
        all.push(Pattern::simple("custom", &NAMED));
        all
    }

    fn bash(stdout: &str, stderr: &str) -> String {
        json!({
            "cwd": "/nonexistent-for-test",
            "tool_response": {"stdout": stdout, "stderr": stderr, "interrupted": false, "isImage": false, "noOutputExpected": false}
        })
        .to_string()
    }

    fn run(input: &str) -> Option<Value> {
        filter_event(input, &patterns(), Path::new("/nonexistent-claude-dir")).unwrap()
    }

    fn a_cookie_read(path: &Path, cwd: &Path) -> String {
        json!({
            "cwd": cwd,
            "tool_input": {"file_path": path},
            "tool_response": {"type": "text", "file": {"filePath": path, "content": format!("__fixture_cookie={TOKEN}"), "numLines": 1, "startLine": 1, "totalLines": 1}}
        })
        .to_string()
    }

    fn key_markers() -> (String, String) {
        (
            format!("-----BEGIN {}PRIVATE KEY-----", ""),
            format!("-----END {}PRIVATE KEY-----", ""),
        )
    }

    const KEY_BODY: [&str; 3] = [
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
        "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3A=",
        "cXJzdHV2d3g=",
    ];

    fn assert_no_key_body(text: &str) {
        let reply = run(&bash(text, "")).unwrap();
        let stdout = reply["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
            .as_str()
            .unwrap();
        for line in KEY_BODY {
            assert!(!stdout.contains(line), "{line} left in: {stdout}");
        }
    }

    #[test]
    fn a_named_secret_in_stdout_and_stderr_is_masked_and_the_shape_is_kept() {
        let cookie = format!("__fixture_cookie={TOKEN}");
        let reply = run(&bash(&format!("before {cookie} after"), &cookie)).unwrap();
        let out = &reply["hookSpecificOutput"];
        assert_eq!(out["hookEventName"], "PostToolUse");
        let updated = &out["updatedToolOutput"];
        assert_eq!(updated["stdout"], "before [REDACTED-custom] after");
        assert_eq!(updated["stderr"], "[REDACTED-custom]");
        assert_eq!(updated["interrupted"], false);
        assert_eq!(updated["isImage"], false);
        assert_eq!(updated["noOutputExpected"], false);
        assert!(!reply.to_string().contains(TOKEN));
        let context = out["additionalContext"].as_str().unwrap();
        assert!(context.contains("custom: 2"), "{context}");
        assert!(context.contains("back to a file"), "{context}");
    }

    #[test]
    fn a_read_result_is_masked_inside_its_nested_shape() {
        let input = json!({
            "cwd": "/nonexistent-for-test",
            "tool_response": {"type": "text", "file": {"filePath": "/x/data.txt", "content": format!("a\n__fixture_cookie={TOKEN}\nb"), "numLines": 3, "startLine": 1, "totalLines": 3}}
        });
        let reply = run(&input.to_string()).unwrap();
        let file = &reply["hookSpecificOutput"]["updatedToolOutput"]["file"];
        assert_eq!(file["content"], "a\n[REDACTED-custom]\nb");
        assert_eq!(file["filePath"], "/x/data.txt");
        assert_eq!(file["numLines"], 3);
    }

    #[test]
    fn ordinary_output_gets_no_reply_at_all() {
        for stdout in [
            r#""SearchString": "L2xvZ2lu""#,
            "synthetic_login_cookie = \"__fixture_cookie\"",
            "password = (sensitive value)",
            "sha256:0f3a9c1d7b2e4f60aa11cc22dd33ee44ff5566778899aabbccddeeff00112233",
        ] {
            assert!(run(&bash(stdout, "")).is_none(), "{stdout}");
        }
    }

    #[test]
    fn a_multiline_private_key_is_masked_but_a_bare_header_is_not() {
        let header = format!("-----BEGIN {}PRIVATE KEY-----", "");
        let footer = format!("-----END {}PRIVATE KEY-----", "");
        let body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\nMDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3A=\n";
        let reply = run(&bash(&format!("x\n{header}\n{body}{footer}\ny"), "")).unwrap();
        let stdout = reply["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
            .as_str()
            .unwrap();
        assert_eq!(stdout, "x\n[REDACTED-private-key]\ny");
        assert!(run(&bash(&format!("grep found {header} in source"), "")).is_none());
    }

    #[test]
    fn a_key_with_a_short_last_line_or_no_final_newline_leaves_no_body_behind() {
        let (header, footer) = key_markers();
        let body = KEY_BODY.join("\n");
        assert_no_key_body(&format!("{header}\n{body}\n{footer}\n"));
        assert_no_key_body(&format!("{header}\n{body}"));
        assert_no_key_body(&format!(
            r#"{{"k":"{header}\n{}\n{footer}\n"}}"#,
            KEY_BODY.join(r"\n")
        ));
    }

    #[test]
    fn a_key_printed_with_line_prefixes_leaves_no_body_behind() {
        let (header, footer) = key_markers();
        let lines: Vec<&str> = [header.as_str()]
            .into_iter()
            .chain(KEY_BODY)
            .chain([footer.as_str()])
            .collect();
        let render = |prefix: &dyn Fn(usize) -> String| {
            lines
                .iter()
                .enumerate()
                .map(|(i, line)| format!("{}{line}\n", prefix(i + 1)))
                .collect::<String>()
        };
        assert_no_key_body(&render(&|_| "-".to_string()));
        assert_no_key_body(&render(&|_| "# ".to_string()));
        assert_no_key_body(&render(&|n| format!("{n:6}\t")));
        assert_no_key_body(&render(&|n| format!("{n}:")));
        assert_no_key_body(&render(&|n| format!("a/key.pem:{n}:")));
    }

    #[test]
    fn a_header_followed_by_prose_is_left_alone() {
        let (header, _) = key_markers();
        assert!(run(&bash(&format!("{header}\nthe header of a key file\n"), "")).is_none());
    }

    #[test]
    fn malformed_or_incomplete_input_is_an_error_not_a_pass() {
        for input in [
            "",
            "not json",
            "[]",
            r#"{"cwd":"/x"}"#,
            r#"{"tool_response":null}"#,
        ] {
            assert!(
                filter_event(input, &patterns(), Path::new("/nonexistent-claude-dir")).is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn an_image_result_and_a_base64_field_are_left_alone() {
        let image = json!({"cwd": "/nonexistent-for-test", "tool_response": {"stdout": format!("__fixture_cookie={TOKEN}"), "isImage": true}});
        assert!(run(&image.to_string()).is_none());
        let read = json!({"cwd": "/nonexistent-for-test", "tool_response": {"type": "pdf", "file": {"base64": format!("__fixture_cookie={TOKEN}")}}});
        assert!(run(&read.to_string()).is_none());
    }

    #[test]
    fn an_exempt_directory_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join(EXEMPT_MARKER), "").unwrap();
        let input = json!({"cwd": nested, "tool_response": {"stdout": format!("__fixture_cookie={TOKEN}")}});
        assert!(run(&input.to_string()).is_none());
    }

    #[test]
    fn a_read_is_judged_by_its_resolved_file_and_not_the_sessions_directory() {
        let exempt = tempfile::tempdir().unwrap();
        std::fs::write(exempt.path().join(EXEMPT_MARKER), "").unwrap();
        std::fs::write(exempt.path().join("fixture.txt"), "x").unwrap();
        let other = tempfile::tempdir().unwrap();
        let outside = other.path().join("creds.txt");
        std::fs::write(&outside, "x").unwrap();
        let elsewhere = Path::new("/nonexistent-for-test");

        let inside = exempt.path().join("fixture.txt");
        assert!(run(&a_cookie_read(&inside, elsewhere)).is_none());
        assert!(run(&a_cookie_read(&outside, exempt.path())).is_some());
        let climbing = exempt
            .path()
            .join("..")
            .join(other.path().file_name().unwrap())
            .join("creds.txt");
        assert!(run(&a_cookie_read(&climbing, elsewhere)).is_some());
    }

    #[test]
    fn a_persisted_file_with_a_stray_byte_is_still_masked() {
        let dir = tempfile::tempdir().unwrap();
        let tool_results = dir.path().join("projects/p/s/tool-results");
        std::fs::create_dir_all(&tool_results).unwrap();
        let file = tool_results.join("out.txt");
        let mut bytes = format!("__fixture_cookie={TOKEN}\n").into_bytes();
        bytes.push(0xff);
        std::fs::write(&file, bytes).unwrap();
        let input = json!({"cwd": "/nonexistent-for-test", "tool_response": {"stdout": "preview only", "persistedOutputPath": file}});
        assert!(
            filter_event(&input.to_string(), &patterns(), dir.path())
                .unwrap()
                .is_some()
        );
        let after = String::from_utf8_lossy(&std::fs::read(&file).unwrap()).into_owned();
        assert!(after.starts_with("[REDACTED-custom]\n"), "{after}");
    }

    #[test]
    fn a_persisted_output_file_is_rewritten_even_when_the_preview_is_clean() {
        let claude_dir = tempfile::tempdir().unwrap();
        let dir = claude_dir.path().join("projects/p/s/tool-results");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("out.txt");
        std::fs::write(&file, format!("start\n__fixture_cookie={TOKEN}\nend\n")).unwrap();
        let input = json!({"cwd": "/nonexistent-for-test", "tool_response": {"stdout": "preview only", "persistedOutputPath": file}});
        let reply = filter_event(&input.to_string(), &patterns(), claude_dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "start\n[REDACTED-custom]\nend\n"
        );
        let out = &reply["hookSpecificOutput"];
        assert!(out.get("updatedToolOutput").is_none());
        assert!(
            out["additionalContext"]
                .as_str()
                .unwrap()
                .contains("custom: 1")
        );
    }

    #[test]
    fn a_saved_copy_that_cannot_be_checked_warns_and_the_preview_is_still_masked() {
        let claude_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(claude_dir.path().join("projects")).unwrap();
        let outside = claude_dir.path().join("elsewhere.txt");
        let original = format!("__fixture_cookie={TOKEN}\n");
        std::fs::write(&outside, &original).unwrap();
        let gone = claude_dir.path().join("projects/p/s/tool-results/gone.txt");
        for path in [&outside, &gone] {
            let input = json!({"cwd": "/nonexistent-for-test", "tool_response": {"stdout": format!("__fixture_cookie={TOKEN}"), "persistedOutputPath": path}});
            let reply = filter_event(&input.to_string(), &patterns(), claude_dir.path())
                .unwrap()
                .unwrap();
            let out = &reply["hookSpecificOutput"];
            assert_eq!(out["updatedToolOutput"]["stdout"], "[REDACTED-custom]");
            assert!(
                out["additionalContext"]
                    .as_str()
                    .unwrap()
                    .contains("saved copy")
            );
        }
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), original);
    }
}
