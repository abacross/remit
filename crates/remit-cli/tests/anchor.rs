//! `remit log anchor` and `remit log verify-anchors` through the real binary, with stand-in
//! authorities: small scripts that write a token and print a receipt, so nothing leaves
//! the machine. The live RFC 3161 and `OpenTimestamps` submitters are in `scripts/anchors/`.

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
        let dir = std::env::temp_dir().join(format!(
            "remit-anchor-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(dir.join("home/.config")).unwrap();
        std::fs::create_dir_all(dir.join("project")).unwrap();
        let s = Self(dir);
        assert!(s.remit(&["init"]).status.success());
        s.task("first");
        s
    }

    fn remit(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_remit"))
            .args(args)
            .current_dir(self.0.join("project"))
            .env_clear()
            .env("HOME", self.0.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap()
    }

    fn task(&self, purpose: &str) {
        let t = self.remit(&[
            "task",
            "--grant",
            "s3:ListBucket=arn:aws:s3:::b",
            "--for",
            "10m",
            "--purpose",
            purpose,
        ]);
        assert!(t.status.success(), "{}", text(&t));
    }

    fn anchors(&self) -> PathBuf {
        self.0.join("project/.remit/log/anchors")
    }

    /// A submitter script at `name` with the given body, run by `sh`.
    fn submitter(&self, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.0.join(name);
        std::fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// A well-behaved stand-in: writes tokens/<digest>.tok and counts its runs.
    fn good(&self) -> String {
        let count = self.0.join("runs");
        self.submitter(
            "good.sh",
            &format!(
                "mkdir -p \"$REMIT_ANCHORS/tokens\"\nprintf x > \"$REMIT_ANCHORS/tokens/$1.tok\"\n\
                 echo run >> {}\nprintf '{{\"kind\":\"test\",\"token\":\"tokens/%s.tok\"}}' \"$1\"",
                count.display()
            ),
        )
    }

    fn runs(&self) -> usize {
        std::fs::read_to_string(self.0.join("runs")).map_or(0, |s| s.lines().count())
    }

    fn anchor(&self, submitter: &str) -> Output {
        self.remit(&[
            "log",
            "anchor",
            "--dir",
            ".remit/log",
            "--submit",
            submitter,
        ])
    }

    fn verify(&self) -> Output {
        self.remit(&[
            "log",
            "verify-anchors",
            "--dir",
            ".remit/log",
            "--policy",
            ".remit/log.policy",
        ])
    }

    fn kept(&self) -> PathBuf {
        std::fs::read_dir(self.anchors())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "checkpoint"))
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

fn receipts(path: &Path) -> Vec<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(path.with_extension("json")).unwrap()).unwrap()
}

#[test]
fn a_checkpoint_is_anchored_once_and_stays_verifiable_as_the_log_grows() {
    let s = Scratch::new("grow");
    let good = s.good();
    let first = s.anchor(&good);
    assert!(first.status.success(), "{}", text(&first));
    let again = s.anchor(&good);
    assert!(
        text(&again).contains("already anchored"),
        "{}",
        text(&again)
    );
    assert_eq!(s.runs(), 1, "a recorded submitter is not run again");

    let kept = s.kept();
    let r = receipts(&kept);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["size"], 1);
    assert_eq!(
        r[0]["digest"].as_str().unwrap(),
        kept.file_stem().unwrap().to_str().unwrap()
    );

    let now = s.verify();
    assert!(now.status.success(), "{}", text(&now));
    assert!(text(&now).contains("the current checkpoint is anchored"));

    s.task("second");
    let later = s.verify();
    assert!(later.status.success(), "{}", text(&later));
    assert!(
        text(&later).contains("consistent with size 2"),
        "{}",
        text(&later)
    );
    assert!(text(&later).contains("not anchored yet"));
}

#[test]
fn an_edited_kept_checkpoint_or_a_missing_token_fails_verification() {
    let s = Scratch::new("tamper");
    assert!(s.anchor(&s.good()).status.success());
    let kept = s.kept();
    let original = std::fs::read_to_string(&kept).unwrap();

    std::fs::write(&kept, original.replacen("\n1\n", "\n2\n", 1)).unwrap();
    let edited = s.verify();
    assert!(!edited.status.success());
    assert!(
        text(&edited).contains("does not hash to its name"),
        "{}",
        text(&edited)
    );

    std::fs::write(&kept, &original).unwrap();
    let token = s.anchors().join(format!(
        "tokens/{}.tok",
        kept.file_stem().unwrap().to_str().unwrap()
    ));
    std::fs::remove_file(token).unwrap();
    let missing = s.verify();
    assert!(!missing.status.success());
    assert!(text(&missing).contains("is missing"), "{}", text(&missing));
}

#[test]
fn a_receipt_pointing_outside_the_anchors_or_a_failing_authority_records_nothing() {
    let s = Scratch::new("refuse");
    let outside = s.submitter(
        "outside.sh",
        "printf x > \"$REMIT_ANCHORS/../stray\"\nprintf '{\"kind\":\"test\",\"token\":\"../stray\"}'",
    );
    let outside_run = s.anchor(&outside);
    assert!(!outside_run.status.success());
    assert!(
        text(&outside_run).contains("not a path inside anchors/"),
        "{}",
        text(&outside_run)
    );
    assert!(!s.kept().with_extension("json").exists());

    let down = s.submitter("down.sh", "echo 'the authority is down' >&2\nexit 1");
    let down_run = s.anchor(&down);
    assert!(!down_run.status.success());
    assert!(
        text(&down_run).contains("the authority is down"),
        "{}",
        text(&down_run)
    );

    let silent = s.submitter("silent.sh", "exit 3");
    let silent_run = s.anchor(&silent);
    assert!(
        text(&silent_run).contains("said nothing"),
        "{}",
        text(&silent_run)
    );
    assert!(!s.kept().with_extension("json").exists());

    // Kept but never anchored is itself a finding.
    let verified = s.verify();
    assert!(!verified.status.success());
    assert!(
        text(&verified).contains("no authority has anchored it"),
        "{}",
        text(&verified)
    );
}
