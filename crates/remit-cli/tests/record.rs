//! `remit log append-record` and `remit log verify-record` through the real binary: a
//! record is logged by the hash of its exact bytes, kept beside the log, and proven
//! under a checkpoint the trust policy accepts.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use sha2::{Digest as _, Sha256};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("remit-record-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("home/.config")).unwrap();
        std::fs::create_dir_all(dir.join("project")).unwrap();
        let s = Self(dir);
        assert!(s.remit(&["init"]).status.success());
        s
    }

    fn remit(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_remit"))
            .args(args)
            .current_dir(self.0.join("project"))
            .env_clear()
            .env("HOME", self.0.join("home"))
            .output()
            .unwrap()
    }

    fn write(&self, name: &str, text: &str) -> String {
        std::fs::write(self.0.join("project").join(name), text).unwrap();
        name.to_owned()
    }

    fn append(&self, record: &str) -> Output {
        let origin = std::fs::read_to_string(self.0.join("project/.remit/origin")).unwrap();
        let origin = origin.trim();
        let witness = format!("{origin}/witness");
        self.remit(&[
            "log",
            "append-record",
            "--dir",
            ".remit/log",
            "--key",
            ".remit/log.key",
            "--origin",
            origin,
            "--record",
            record,
            "--witness-key",
            ".remit/witness.key",
            "--witness-name",
            &witness,
            "--witness-state",
            ".remit/witness.state",
        ])
    }

    fn verify(&self, record: &str) -> Output {
        self.remit(&[
            "log",
            "verify-record",
            "--dir",
            ".remit/log",
            "--policy",
            ".remit/log.policy",
            "--record",
            record,
        ])
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

#[test]
fn records_are_logged_once_proven_and_their_kept_bytes_checked() {
    let s = Scratch::new();
    let names: Vec<String> = (1..=3)
        .map(|i| s.write(&format!("r{i}.json"), &format!("{{\"seq\":{i}}}\n")))
        .collect();
    for name in &names {
        let appended = s.append(name);
        assert!(appended.status.success(), "{}", text(&appended));
    }
    assert!(text(&s.append(&names[1])).contains("already logged"));

    let proven = s.verify(&names[1]);
    assert!(proven.status.success(), "{}", text(&proven));
    assert!(text(&proven).contains("entry 1 of") && text(&proven).contains("at size 3"));

    let stranger = s.write("r9.json", "{\"seq\":9}\n");
    let unlogged = s.verify(&stranger);
    assert!(!unlogged.status.success());
    assert!(text(&unlogged).contains("not in the log"));

    // The kept copy is what a verifier reads; an edited copy is caught.
    let bytes = std::fs::read(s.0.join("project").join(&names[1])).unwrap();
    let hex = Sha256::digest(&bytes)
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
    let kept = s.0.join("project/.remit/log/record").join(hex);
    std::fs::write(&kept, b"{\"seq\":2,\"edited\":true}\n").unwrap();
    let edited = s.verify(&names[1]);
    assert!(!edited.status.success());
    assert!(text(&edited).contains("kept bytes"), "{}", text(&edited));
}
