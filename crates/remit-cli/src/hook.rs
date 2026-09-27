//! `remit hook pre-tool-use`: the agent plugin's guide rail (ADR 0009).
//!
//! Reads a Claude Code `PreToolUse` event on standard input and, when the tool is a shell
//! command that starts a cloud command-line tool directly, denies it with the reason to use
//! `remit_run` instead. It is a guide rail, not the boundary: a disguised command can get
//! past any reading of a shell line. The boundary is that the agent holds no cloud
//! credentials; only the broker does, and only for a warrant.

use std::io::Read;
use std::path::Path;

use serde_json::{Value, json};

use super::Result;

/// Cloud command-line tools that must go through `remit_run`.
const CLOUD_CLIS: &[&str] = &["aws", "az", "gcloud", "gsutil", "bq"];

/// Words that run the next word as a command.
const PREFIXES: &[&str] = &[
    "sudo", "env", "command", "exec", "time", "nohup", "nice", "xargs", "timeout", "builtin",
];

/// The cloud tool a shell line starts directly, if any. Splits on the separators that
/// begin a new command (`;` `&&` `||` `|` `&` newlines, `$(` and backquotes), skips
/// variable assignments and wrapper words, and compares the first word's file name.
pub(crate) fn cloud_cli(line: &str) -> Option<&'static str> {
    let mut spaced = String::with_capacity(line.len());
    for c in line.chars() {
        if matches!(c, ';' | '|' | '&' | '\n' | '`' | '(' | ')') {
            spaced.push('\n');
        } else {
            spaced.push(c);
        }
    }
    for segment in spaced.split('\n') {
        let mut words = segment
            .split_whitespace()
            .map(|w| w.trim_matches(|c| c == '"' || c == '\'' || c == '$' || c == '{' || c == '}'));
        let first = loop {
            match words.next() {
                None => break None,
                Some("") => {}
                Some(w) if w.contains('=') && !w.starts_with('-') => {}
                Some(w) if PREFIXES.contains(&w) => {}
                Some(w) if w.starts_with('-') => {}
                // A wrapper's duration or niceness: `timeout 30 aws`, `nice -n 10 aws`.
                Some(w) if is_number(w) => {}
                Some(w) => break Some(w),
            }
        };
        if let Some(word) = first {
            let name = Path::new(word)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(word);
            if let Some(cli) = CLOUD_CLIS.iter().find(|c| **c == name) {
                return Some(cli);
            }
        }
    }
    None
}

fn is_number(word: &str) -> bool {
    let digits = word.trim_end_matches(['s', 'm', 'h', 'd']);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// The hook's answer for one event: `Some(deny)` or `None` for no decision.
pub(crate) fn decide(event: &Value) -> Option<Value> {
    if event.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return None;
    }
    let command = event.get("tool_input")?.get("command")?.as_str()?;
    let cli = cloud_cli(command)?;
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!(
                "{cli} is not run directly here: this agent reaches the cloud only through its Remit warrant. \
                 Call the remit_run tool with the same command as a list of arguments, for example \
                 [\"{cli}\", ...]; remit_warrant shows what the warrant allows and remit_check tests one action."
            )
        }
    }))
}

/// Reads one event from standard input and prints the decision, if any.
pub(crate) fn pre_tool_use() -> Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("stdin: {e}"))?;
    let event: Value =
        serde_json::from_str(&input).map_err(|e| format!("not a hook event: {e}"))?;
    if let Some(out) = decide(&event) {
        println!("{out}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_cloud_commands_are_found_however_they_are_started() {
        for line in [
            "aws s3 ls",
            "/usr/local/bin/aws s3 ls",
            "AWS_PROFILE=admin aws s3 ls",
            "sudo -E aws iam list-users",
            "env AWS_REGION=us-east-1 aws sts get-caller-identity",
            "cd /tmp && aws s3 cp x s3://b/x",
            "echo hi; gcloud projects list",
            "cat ids | xargs -n1 az group show --name",
            "echo $(aws sts get-caller-identity)",
            "echo `gsutil ls`",
            "false || bq ls",
            "\"aws\" s3 ls",
            "timeout 30 aws s3 ls",
            "nice -n 10 gcloud compute instances list",
        ] {
            assert!(cloud_cli(line).is_some(), "missed: {line}");
        }
    }

    #[test]
    fn other_commands_and_mentions_pass() {
        for line in [
            "ls -la",
            "remit run --chain c --root r --role x --log-policy p --log-proof q -- aws s3 ls",
            "grep aws README.md",
            "echo 'use aws later'",
            "cargo test -p remit-aws",
            "python3 awsx.py",
            "git commit -m 'aws: fix'",
        ] {
            assert!(cloud_cli(line).is_none(), "blocked wrongly: {line}");
        }
    }

    #[test]
    fn only_shell_tool_calls_are_judged_and_the_denial_says_what_to_do() {
        let bash = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "aws s3 ls"}});
        let out = decide(&bash).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            out["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("remit_run")
        );
        let other = json!({"tool_name": "Read", "tool_input": {"file_path": "aws"}});
        assert!(decide(&other).is_none());
        let fine = json!({"tool_name": "Bash", "tool_input": {"command": "ls"}});
        assert!(decide(&fine).is_none());
    }
}
