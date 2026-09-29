//! `remit mcp`: a Model Context Protocol server over standard input and output (ADR 0009).
//!
//! Three tools, each the existing Remit path and nothing more: `remit_warrant` describes the
//! leaf warrant, `remit_check` is the warrant's own decision (SPEC 3.4) for one action,
//! and `remit_run` runs one command exactly as `remit run` does. Every call reads and
//! verifies the chain and its log proof again, so nothing here can outlive or widen a
//! warrant. The protocol is JSON-RPC 2.0, one message per line.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use remit_core::{Request, Warrant, verify_chain};
use serde_json::{Value, json};

use super::{CLOSED, Result, SessionArgs, log, now, open_session, read_chain, roots, session_env};

/// Protocol revisions this server speaks; the tools are the same in each. The client's
/// requested revision is used when it is one of these, the first otherwise.
/// The newest revision, answered when the client asks for one this server does not know.
const LATEST: &str = "2025-11-25";

pub(crate) const PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

#[derive(Args)]
pub(crate) struct McpArgs {
    /// The warrant chain the agent works under.
    #[arg(long)]
    chain: PathBuf,
    /// Trusted root key identifiers; the chain must start at one of them.
    #[arg(long = "root", required = true)]
    roots: Vec<String>,
    /// The role `remit_run` assumes; its trust policy must require a source identity.
    #[arg(long)]
    role: String,
    /// The role's maximum session duration in seconds.
    #[arg(long, default_value_t = 3600)]
    role_max_seconds: u64,
    /// The trust policy for the log (SPEC 9.2).
    #[arg(long)]
    log_policy: PathBuf,
    /// The proof that every link of the chain is logged (`remit log prove`).
    #[arg(long)]
    log_proof: PathBuf,
    /// The region for STS and for commands.
    #[arg(long)]
    region: Option<String>,
    #[command(flatten)]
    service: crate::BrokerServiceArgs,
    /// Programs `remit_run` may start, by name found on `PATH` (for example `aws`) or by
    /// path; any, if none is given. Each is resolved once, when the server starts, to the
    /// file it names, and only those files are run.
    #[arg(long = "allow")]
    allow: Vec<String>,
    /// Seconds a command may run before it is stopped.
    #[arg(long, default_value_t = 300)]
    timeout_seconds: u64,
    /// Bytes of each of stdout and stderr returned; the rest is cut and said to be.
    #[arg(long, default_value_t = 65_536)]
    max_output_bytes: usize,
}

/// What the tools do. The live one reaches AWS; tests use a fake. Only running a command
/// waits on anything; describing and checking a warrant are local.
pub(crate) trait Backend {
    fn warrant(&self) -> Result<Value>;
    fn check(&self, action: &str, resource: &str) -> Result<Value>;
    async fn run(&self, argv: &[String]) -> Result<Value>;
}

fn tools() -> Value {
    json!([
        {
            "name": "remit_warrant",
            "description": "What you may do in the cloud under your Remit warrant: its grants (actions on resources), its time window and purpose, and whether it is proven logged. Read-only. Call it before planning cloud work.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "remit_check",
            "description": "Whether your warrant permits one action on one resource right now, and if not, why. Read-only; the same decision the warrant makes. Use it to stay inside your bounds instead of discovering them by failure. Actions are like s3:GetObject; resources are ARNs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "One action, for example s3:GetObject. No wildcards."},
                    "resource": {"type": "string", "description": "One resource ARN. No wildcards."}
                },
                "required": ["action", "resource"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "remit_run",
            "description": "Run one cloud command under your warrant, the only way you get cloud credentials. Give the program and its arguments as a list (no shell, no pipes), for example [\"aws\", \"s3\", \"ls\", \"s3://bucket\"]. The command gets short-lived credentials bounded by the warrant and stamped with its identifier, so the cloud's own record shows every call it makes. Refused if the warrant is not valid now or not proven logged.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "The program and its arguments."}
                },
                "required": ["argv"],
                "additionalProperties": false
            },
            "annotations": {"destructiveHint": true, "openWorldHint": true}
        }
    ])
}

fn reply(id: &Value, result: Value) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("jsonrpc".to_owned(), json!("2.0"));
    out.insert("id".to_owned(), id.clone());
    out.insert("result".to_owned(), result);
    Value::Object(out)
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_result(outcome: Result<Value>) -> Value {
    match outcome {
        Ok(v) => json!({
            "content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}],
            "structuredContent": v,
            "isError": false
        }),
        Err(message) => json!({"content": [{"type": "text", "text": message}], "isError": true}),
    }
}

fn string_arg<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name}: a string is required"))
}

/// One message in, at most one message out: requests get a reply, notifications none.
pub(crate) async fn handle<B: Backend>(backend: &B, line: &str) -> Option<Value> {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return Some(error(&Value::Null, -32700, "parse error"));
    };
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return Some(error(
            msg.get("id").unwrap_or(&Value::Null),
            -32600,
            "invalid request",
        ));
    };
    // A message without an id is a notification (initialized, cancelled): no reply.
    let id = msg.get("id")?;
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
    let out = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = asked
                .filter(|v| PROTOCOL_VERSIONS.contains(v))
                .unwrap_or(LATEST);
            reply(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "remit", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "You reach the cloud only through a Remit warrant a person signed. Call remit_warrant to see what you may do, remit_check before an action you are unsure of, and remit_run to run a cloud command. Every call you make is recorded by the cloud with the warrant's identifier and reconciled against the warrant."
                }),
            )
        }
        "ping" => reply(id, json!({})),
        "tools/list" => reply(id, json!({"tools": tools()})),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let outcome = match name {
                "remit_warrant" => backend.warrant(),
                "remit_check" => match (string_arg(&args, "action"), string_arg(&args, "resource"))
                {
                    (Ok(a), Ok(r)) => backend.check(a, r),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                },
                "remit_run" => match args.get("argv").and_then(Value::as_array) {
                    Some(items) if !items.is_empty() => {
                        match items
                            .iter()
                            .map(|v| v.as_str().map(str::to_owned))
                            .collect::<Option<Vec<_>>>()
                        {
                            Some(words) => backend.run(&words).await,
                            None => Err("argv: every item must be a string".to_owned()),
                        }
                    }
                    _ => Err("argv: a non-empty list of strings is required".to_owned()),
                },
                _ => return Some(error(id, -32602, &format!("unknown tool: {name}"))),
            };
            reply(id, tool_result(outcome))
        }
        _ => error(id, -32601, &format!("method not found: {method}")),
    };
    Some(out)
}

/// Why a warrant does or does not permit a request (SPEC 3.4), in words an agent can act on.
pub(crate) fn decision(
    leaf: &Warrant,
    action: &str,
    resource: &str,
    at: u64,
) -> Result<(bool, String)> {
    let request =
        Request::new(leaf.subject().as_str(), action, resource, at).map_err(|e| e.to_string())?;
    if leaf.permits(&request) {
        return Ok((
            true,
            format!("warrant {} allows {action} on {resource}", leaf.id()),
        ));
    }
    let why = if at < leaf.not_before() {
        format!("the warrant is not valid until {}", leaf.not_before())
    } else if at > leaf.not_after() {
        format!("the warrant expired at {}", leaf.not_after())
    } else {
        format!(
            "no grant in warrant {} allows {action} on {resource}",
            leaf.id()
        )
    };
    Ok((false, why))
}

fn describe(leaf: &Warrant, links: usize, at: u64) -> Value {
    let grants: Vec<Value> = leaf
        .grants()
        .iter()
        .map(|g| {
            json!({
                "actions": g.actions().iter().map(remit_core::ActionPattern::as_str).collect::<Vec<_>>(),
                "resources": g.resources().iter().map(remit_core::ResourcePattern::as_str).collect::<Vec<_>>()
            })
        })
        .collect();
    json!({
        "warrant_id": leaf.id().as_str(),
        "issuer": leaf.issuer().as_str(),
        "subject": leaf.subject().as_str(),
        "purpose": leaf.purpose(),
        "not_before": leaf.not_before(),
        "not_after": leaf.not_after(),
        "seconds_left": leaf.not_after().saturating_sub(at),
        "grants": grants,
        "chain_links": links
    })
}

/// Cuts output to `max` bytes, on a character boundary, and says whether it cut.
pub(crate) fn cap(bytes: &[u8], max: usize) -> (String, bool) {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= max {
        return (text.into_owned(), false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (text.get(..end).unwrap_or_default().to_owned(), true)
}

/// The file a program name or path runs: a path is taken as given, a bare name is looked
/// up on `path` the way a shell would; either way the result is the canonical path, with
/// every link resolved.
pub(crate) fn resolve(program: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let runnable = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    let found = if program.contains('/') {
        Some(PathBuf::from(program)).filter(|p| runnable(p))
    } else {
        std::env::split_paths(path?)
            .map(|dir| dir.join(program))
            .find(|p| runnable(p))
    };
    found.and_then(|p| std::fs::canonicalize(p).ok())
}

/// The allowed programs, resolved; `None` when any program may run.
pub(crate) fn resolve_allowed(
    allow: &[String],
    path: Option<&std::ffi::OsStr>,
) -> Result<Option<Vec<PathBuf>>> {
    if allow.is_empty() {
        return Ok(None);
    }
    allow
        .iter()
        .map(|a| resolve(a, path).ok_or_else(|| format!("--allow {a}: no such program")))
        .collect::<Result<_>>()
        .map(Some)
}

/// The file to run for `program`, if it is allowed: the resolved file itself, so what
/// was checked is what runs, whatever a directory or `PATH` holds by then.
pub(crate) fn permitted_program(
    allowed: Option<&[PathBuf]>,
    program: &str,
    path: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let file = resolve(program, path)?;
    allowed
        .is_none_or(|list| list.contains(&file))
        .then_some(file)
}

struct Live {
    args: McpArgs,
    allowed: Option<Vec<PathBuf>>,
}

impl Live {
    fn leaf_checked(&self) -> Result<(Vec<remit_core::SignedWarrant>, Result<String>)> {
        let chain = read_chain(&self.args.chain)?;
        verify_chain(&chain, &roots(&self.args.roots)?).map_err(|e| format!("refused: {e}"))?;
        let logged = log::verify_links_logged(&self.args.log_policy, &chain, &self.args.log_proof)
            .map(|t| format!("{} at size {}", t.checkpoint.origin(), t.checkpoint.size()));
        Ok((chain, logged))
    }
}

impl Backend for Live {
    fn warrant(&self) -> Result<Value> {
        let (chain, logged) = self.leaf_checked()?;
        let leaf = verify_chain(&chain, &roots(&self.args.roots)?).map_err(|e| e.to_string())?;
        let mut out = describe(leaf, chain.len(), now());
        let proof = match logged {
            Ok(at) => json!({"proven": true, "at": at}),
            Err(e) => json!({"proven": false, "why": e}),
        };
        if let Some(fields) = out.as_object_mut() {
            fields.insert("logged".to_owned(), proof);
        }
        Ok(out)
    }

    fn check(&self, action: &str, resource: &str) -> Result<Value> {
        let (chain, logged) = self.leaf_checked()?;
        let leaf = verify_chain(&chain, &roots(&self.args.roots)?).map_err(|e| e.to_string())?;
        // A warrant that is not in the log is never honoured (SPEC 9.3), whatever it says.
        if let Err(e) = logged {
            return Ok(
                json!({"permitted": false, "reason": format!("the warrant is not proven logged: {e}")}),
            );
        }
        let (permitted, reason) = decision(leaf, action, resource, now())?;
        Ok(json!({"permitted": permitted, "reason": reason, "warrant_id": leaf.id().as_str()}))
    }

    async fn run(&self, argv: &[String]) -> Result<Value> {
        let (program, rest) = argv.split_first().ok_or("argv is empty")?;
        let Some(file) = permitted_program(
            self.allowed.as_deref(),
            program,
            std::env::var_os("PATH").as_deref(),
        ) else {
            return Err(format!(
                "refused: {program} is not one of the programs this server may run ({})",
                self.args.allow.join(", ")
            ));
        };
        let session = open_session(&SessionArgs {
            chain: &self.args.chain,
            roots: &self.args.roots,
            role: &self.args.role,
            role_max_seconds: self.args.role_max_seconds,
            log_policy: Some(&self.args.log_policy),
            log_proof: &self.args.log_proof,
            region: self.args.region.as_deref(),
            service: &self.args.service,
        })
        .await?;
        let mut cmd = tokio::process::Command::new(&file);
        cmd.args(rest)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        for var in CLOSED {
            cmd.env_remove(var);
        }
        cmd.envs(session_env(&session));
        let child = cmd.output();
        let output = tokio::time::timeout(Duration::from_secs(self.args.timeout_seconds), child)
            .await
            .map_err(|_| {
                format!(
                    "stopped: {program} ran past {} s",
                    self.args.timeout_seconds
                )
            })?
            .map_err(|e| format!("{program}: {e}"))?;
        let (stdout, out_cut) = cap(&output.stdout, self.args.max_output_bytes);
        let (stderr, err_cut) = cap(&output.stderr, self.args.max_output_bytes);
        Ok(json!({
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": out_cut,
            "stderr_truncated": err_cut,
            "warrant_id": session.plan.warrant_id.as_str(),
            "session_seconds": session.plan.duration_seconds,
            "logged": format!("{} at size {}", session.logged_origin, session.logged_size)
        }))
    }
}

/// Serves until standard input closes.
pub(crate) async fn serve(args: McpArgs) -> Result<()> {
    let allowed = resolve_allowed(&args.allow, std::env::var_os("PATH").as_deref())?;
    let backend = Live { args, allowed };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("stdin: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(out) = handle(&backend, &line).await {
            writeln!(stdout, "{out}")
                .and_then(|()| stdout.flush())
                .map_err(|e| format!("stdout: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use remit_core::WarrantSpec;

    struct Fake;

    impl Backend for Fake {
        fn warrant(&self) -> Result<Value> {
            Ok(json!({"warrant_id": "rw1-test"}))
        }
        fn check(&self, action: &str, resource: &str) -> Result<Value> {
            Ok(json!({"permitted": action == "s3:GetObject", "resource": resource}))
        }
        async fn run(&self, argv: &[String]) -> Result<Value> {
            // Yield once, as a real command would wait, so the fake is async like the live one.
            tokio::task::yield_now().await;
            if argv.first().map(String::as_str) == Some("fail") {
                Err("refused: not logged".to_owned())
            } else {
                Ok(json!({"argv": argv}))
            }
        }
    }

    fn call(line: &str) -> Option<Value> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .ok()?
            .block_on(handle(&Fake, line))
    }

    #[test]
    fn initialize_agrees_a_version_and_offers_tools() {
        let r = call(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#).unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r["id"], 1);
        let unknown = call(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#).unwrap();
        assert_eq!(unknown["result"]["protocolVersion"], LATEST);
        assert_eq!(PROTOCOL_VERSIONS.first().copied(), Some(LATEST));
    }

    #[test]
    fn notifications_get_no_reply_and_garbage_gets_errors() {
        assert!(call(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        assert_eq!(call("not json").unwrap()["error"]["code"], -32700);
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":3}"#).unwrap()["error"]["code"],
            -32600
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#).unwrap()["error"]["code"],
            -32601
        );
    }

    #[test]
    fn exactly_three_tools_and_none_grants_or_returns_credentials() {
        let r = call(r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#).unwrap();
        let names: Vec<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["remit_warrant", "remit_check", "remit_run"]);
    }

    #[test]
    fn tool_calls_validate_arguments_and_report_refusals_as_tool_errors() {
        let ok = call(r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"remit_check","arguments":{"action":"s3:GetObject","resource":"arn:aws:s3:::b/k"}}}"#).unwrap();
        assert_eq!(ok["result"]["isError"], false);
        assert_eq!(ok["result"]["structuredContent"]["permitted"], true);
        let missing = call(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"remit_check","arguments":{"action":"s3:GetObject"}}}"#).unwrap();
        assert_eq!(missing["result"]["isError"], true);
        let empty = call(r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"remit_run","arguments":{"argv":[]}}}"#).unwrap();
        assert_eq!(empty["result"]["isError"], true);
        let not_strings = call(r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"remit_run","arguments":{"argv":["aws",1]}}}"#).unwrap();
        assert_eq!(not_strings["result"]["isError"], true);
        let refused = call(r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"remit_run","arguments":{"argv":["fail"]}}}"#).unwrap();
        assert_eq!(refused["result"]["isError"], true);
        assert_eq!(
            refused["result"]["content"][0]["text"],
            "refused: not logged"
        );
        let unknown = call(
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"remit_issue"}}"#,
        )
        .unwrap();
        assert_eq!(unknown["error"]["code"], -32602);
    }

    fn warrant(grants: &[(&[&str], &[&str])], from: u64, to: u64) -> Warrant {
        Warrant::new(&WarrantSpec {
            issuer: "ed25519:issuer",
            subject: "ed25519:agent",
            purpose: "test",
            not_before: from,
            not_after: to,
            grants,
            parent: None,
            max_depth: 0,
        })
        .unwrap()
    }

    #[test]
    fn the_decision_is_the_warrants_and_says_why() {
        let w = warrant(&[(&["s3:GetObject"], &["arn:aws:s3:::bucket/*"])], 100, 200);
        assert!(
            decision(&w, "s3:GetObject", "arn:aws:s3:::bucket/k", 150)
                .unwrap()
                .0
        );
        let (ok, why) = decision(&w, "s3:PutObject", "arn:aws:s3:::bucket/k", 150).unwrap();
        assert!(!ok && why.contains("no grant"));
        let (ok, why) = decision(&w, "s3:GetObject", "arn:aws:s3:::other/k", 150).unwrap();
        assert!(!ok && why.contains("no grant"));
        let (ok, why) = decision(&w, "s3:GetObject", "arn:aws:s3:::bucket/k", 201).unwrap();
        assert!(!ok && why.contains("expired"));
        let (ok, why) = decision(&w, "s3:GetObject", "arn:aws:s3:::bucket/k", 99).unwrap();
        assert!(!ok && why.contains("not valid until"));
        assert!(
            decision(&w, "s3:*", "arn:aws:s3:::bucket/k", 150).is_err(),
            "a request is concrete: no wildcards"
        );
    }

    #[test]
    fn output_is_capped_on_a_character_boundary() {
        assert_eq!(cap(b"hello", 10), ("hello".to_owned(), false));
        let (s, cut) = cap("héllo".as_bytes(), 2);
        assert!(cut && s == "h", "never split a character: {s:?}");
    }

    #[test]
    fn only_the_allowed_files_run_whatever_they_are_called() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("remit-allow-{}", std::process::id()));
        let (bin, evil) = (dir.join("bin"), dir.join("evil"));
        for d in [&bin, &evil] {
            std::fs::create_dir_all(d).unwrap();
            let f = d.join("aws");
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::os::unix::fs::symlink(bin.join("aws"), bin.join("aws-link")).unwrap();
        let path = std::ffi::OsString::from(bin.as_os_str());
        let path = Some(path.as_os_str());
        let allowed = resolve_allowed(&["aws".to_owned()], path).unwrap().unwrap();
        let real = std::fs::canonicalize(bin.join("aws")).unwrap();

        assert_eq!(
            permitted_program(Some(&allowed), "aws", path),
            Some(real.clone())
        );
        let by_path = bin.join("aws");
        assert!(permitted_program(Some(&allowed), by_path.to_str().unwrap(), path).is_some());
        // Another file with the same name, and a link to the allowed one under another name.
        let other = evil.join("aws");
        assert_eq!(
            permitted_program(Some(&allowed), other.to_str().unwrap(), path),
            None
        );
        assert_eq!(
            permitted_program(Some(&allowed), "aws-link", path),
            Some(real)
        );
        assert_eq!(permitted_program(Some(&allowed), "sh", path), None);
        // No list: anything that exists runs; nothing that does not.
        assert!(permitted_program(None, other.to_str().unwrap(), path).is_some());
        assert_eq!(permitted_program(None, "no-such-program", path), None);
        assert!(resolve_allowed(&["no-such-program".to_owned()], path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
