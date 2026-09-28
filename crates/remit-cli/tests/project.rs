//! `remit init` and `remit task` end to end, through the real binary, in a scratch
//! directory with its own configuration home, so no real key is ever read or written.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("remit-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("home/.config")).unwrap();
        std::fs::create_dir_all(dir.join("my app")).unwrap();
        Self(dir)
    }

    fn project(&self) -> PathBuf {
        self.0.join("my app")
    }

    fn root_key(&self) -> PathBuf {
        self.0.join("home/.config/remit/root.key")
    }

    fn remit(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_remit"))
            .args(args)
            .current_dir(self.project())
            .env_clear()
            .env("HOME", self.0.join("home"))
            .output()
            .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_sets_up_a_project_and_each_task_becomes_the_current_warrant() {
    let scratch = Scratch::new("init");
    let first = scratch.remit(&["init"]);
    assert!(first.status.success(), "{}", text(&first));
    let out = text(&first);
    // The issuing key is the person's, outside the project, readable only by them.
    assert_eq!(mode(&scratch.root_key()), 0o600);
    assert_eq!(mode(scratch.root_key().parent().unwrap()), 0o700);
    let state = scratch.project().join(".remit");
    for f in ["agent.key", "log.key", "witness.key"] {
        assert_eq!(mode(&state.join(f)), 0o600, "{f}");
    }
    assert!(!state.join("root.key").exists());
    let ignored = std::fs::read_to_string(state.join(".gitignore")).unwrap();
    for pattern in ["*.key", "log/.lock"] {
        assert!(ignored.lines().any(|l| l == pattern), "{pattern}");
    }
    // The origin is kept to characters a log origin carries.
    assert_eq!(
        std::fs::read_to_string(state.join("origin")).unwrap(),
        "remit.local/my-app\n"
    );
    // Claude Code needs two slashes for an absolute path in a permission rule.
    assert!(
        out.contains(&format!("Read(/{})", scratch.root_key().display())),
        "{out}"
    );
    assert!(
        std::fs::read_to_string(state.join("role.yaml"))
            .unwrap()
            .contains("BrokerWithWarrantOnly")
    );

    // Nothing is overwritten by a second init.
    let again = scratch.remit(&["init"]);
    assert!(!again.status.success());
    assert!(text(&again).contains("already holds Remit state"));

    for (grant, purpose) in [
        ("s3:ListBucket=arn:aws:s3:::demo-bucket", "list it"),
        ("s3:GetObject=arn:aws:s3:::demo-bucket/*", "read one report"),
    ] {
        let task = scratch.remit(&[
            "task",
            "--grant",
            grant,
            "--for",
            "30m",
            "--purpose",
            purpose,
        ]);
        assert!(task.status.success(), "{}", text(&task));
        let id = text(&task)
            .lines()
            .find_map(|l| l.strip_prefix("logged and proven; the agent works under "))
            .and_then(|l| l.split_whitespace().next())
            .unwrap()
            .to_owned();
        // The current warrant is the one just issued, and its proof verifies.
        let current = std::fs::read(state.join("current.chain")).unwrap();
        let issued = std::fs::read(state.join("warrants").join(format!("{id}.chain"))).unwrap();
        assert_eq!(current, issued);
        let verify = scratch.remit(&[
            "log",
            "verify",
            "--policy",
            ".remit/log.policy",
            "--chain",
            ".remit/current.chain",
            "--proof",
            ".remit/current.proof",
        ]);
        assert!(verify.status.success(), "{}", text(&verify));
    }
}

#[test]
fn an_existing_issuing_key_is_used_and_never_replaced() {
    let s = Scratch::new("reuse");
    let dir = s.root_key().parent().unwrap().to_owned();
    std::fs::create_dir_all(&dir).unwrap();
    let made = s.remit(&["key", "new", "--out", s.root_key().to_str().unwrap()]);
    assert!(made.status.success());
    let before = std::fs::read(s.root_key()).unwrap();
    let o = s.remit(&["init"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("already there, used as it is"));
    assert_eq!(std::fs::read(s.root_key()).unwrap(), before);
}

#[test]
fn a_task_needs_a_project_a_purpose_and_a_real_duration() {
    let s = Scratch::new("task");
    let no_project = s.remit(&[
        "task",
        "--grant",
        "s3:ListBucket=*",
        "--for",
        "1h",
        "--purpose",
        "x",
    ]);
    assert!(!no_project.status.success());
    assert!(text(&no_project).contains("run `remit init` first"));
    assert!(s.remit(&["init"]).status.success());
    let no_purpose = s.remit(&["task", "--grant", "s3:ListBucket=*", "--for", "1h"]);
    assert!(!no_purpose.status.success());
    let zero = s.remit(&[
        "task",
        "--grant",
        "s3:ListBucket=*",
        "--for",
        "0h",
        "--purpose",
        "x",
    ]);
    assert!(!zero.status.success());
    assert!(!s.project().join(".remit/current.chain").exists());
}

#[test]
fn a_reader_that_leaves_gets_no_panic() {
    // `remit warrant show ... | head -1`: the reader closes the pipe before remit has
    // written everything. Closing it before the child starts writing makes that certain.
    use std::process::Stdio;
    let scratch = Scratch::new("pipe");
    let key = scratch.0.join("k.key");
    let made = scratch.remit(&["key", "new", "--out", key.to_str().unwrap()]);
    assert!(made.status.success());
    let mut child = Command::new(env!("CARGO_BIN_EXE_remit"))
        .args(["key", "id", "--key", key.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_eq!(out.status.code(), Some(141), "{stderr}");
}
