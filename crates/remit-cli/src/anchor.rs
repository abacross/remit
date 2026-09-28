//! `remit log anchor` and `remit log verify-anchors`: a log's checkpoints timestamped by
//! authorities outside it (SPEC section 9.6).
//!
//! Witnesses prove there is one history; they do not prove when it was written, because
//! their clocks are their own. An anchor does: the SHA-256 of a checkpoint's body goes to
//! an authority that signs the time it saw it (an RFC 3161 timestamp authority) or commits
//! it to Bitcoin (`OpenTimestamps`), so the checkpoint provably existed by then and cannot
//! have been made up later. Remit speaks neither protocol itself: a submitter is a program
//! given the digest in hex, which writes its token under the log's `anchors/` directory
//! and prints a JSON receipt naming it (`scripts/anchors/` has one for each authority).
//! The anchored checkpoint is kept beside its receipts, so a verifier can check later that
//! the log signed it and that the log as it is now is consistent with it.

use std::path::{Path, PathBuf};
use std::process::Command;

use remit_log::{Checkpoint, Note, Tiles, TrustPolicy, merkle};
use remit_logstore::LogDir;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::{Result, now};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The digest an authority is given for a checkpoint: SHA-256 of its body, the signed text
/// without signatures, which cosignatures added later do not change.
fn digest(note: &Note) -> String {
    hex(&Sha256::digest(note.text().as_bytes()))
}

fn anchors_dir(dir: &Path) -> PathBuf {
    dir.join("anchors")
}

fn read_receipts(path: &Path) -> Result<Vec<Value>> {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(receipts)) => Ok(receipts),
            _ => Err(format!("{}: not a JSON list of receipts", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// A receipt's token files, relative to `anchors/`: every one must stay inside it, so the
/// log can be moved or published and its receipts still point at what they name.
fn token_paths(receipt: &Map<String, Value>) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for field in ["token", "proof"] {
        if let Some(value) = receipt.get(field) {
            let p = value
                .as_str()
                .ok_or_else(|| format!("receipt field {field} is not text"))?;
            let inside = !p.is_empty()
                && !p.starts_with('/')
                && Path::new(p)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)));
            if !inside {
                return Err(format!(
                    "receipt field {field} {p:?} is not a path inside anchors/"
                ));
            }
            paths.push(p.to_owned());
        }
    }
    if paths.is_empty() {
        return Err("the receipt names no token or proof file".into());
    }
    Ok(paths)
}

/// `remit log anchor`: the log's current checkpoint, submitted to each authority that has
/// not yet anchored it.
pub(crate) fn anchor(dir: &Path, submitters: &[PathBuf]) -> Result<()> {
    let text = LogDir::new(dir)
        .checkpoint_text()
        .map_err(|e| e.to_string())?;
    let note = Note::parse(&text).map_err(|e| format!("checkpoint: {e}"))?;
    let checkpoint = Checkpoint::parse(note.text()).map_err(|e| format!("checkpoint: {e}"))?;
    let d = digest(&note);
    let anchors = anchors_dir(dir);
    std::fs::create_dir_all(&anchors).map_err(|e| format!("{}: {e}", anchors.display()))?;
    let anchors =
        std::fs::canonicalize(&anchors).map_err(|e| format!("{}: {e}", anchors.display()))?;
    let kept = anchors.join(format!("{d}.checkpoint"));
    if !kept.exists() {
        std::fs::write(&kept, &text).map_err(|e| format!("{}: {e}", kept.display()))?;
    }
    let receipts_path = anchors.join(format!("{d}.json"));
    let mut receipts = read_receipts(&receipts_path)?;
    let mut failed = Vec::new();
    for submitter in submitters {
        let name = submitter
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if receipts
            .iter()
            .any(|r| r.get("submitter").and_then(Value::as_str) == Some(name.as_str()))
        {
            println!("  {name}: already anchored at size {}", checkpoint.size());
            continue;
        }
        let out = Command::new(submitter)
            .arg(&d)
            .env("REMIT_ANCHORS", &anchors)
            .output()
            .map_err(|e| format!("{}: {e}", submitter.display()))?;
        if !out.status.success() {
            let said = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            failed.push(if said.is_empty() {
                format!("{name}: failed ({}) and said nothing", out.status)
            } else {
                format!("{name}: {said}")
            });
            continue;
        }
        let Ok(Value::Object(receipt)) = serde_json::from_slice::<Value>(&out.stdout) else {
            failed.push(format!("{name}: did not print a JSON receipt"));
            continue;
        };
        let checked = receipt
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| "the receipt has no kind".to_owned())
            .and_then(|_| token_paths(&receipt))
            .and_then(|paths| {
                paths
                    .iter()
                    .find(|p| !anchors.join(p).is_file())
                    .map_or(Ok(()), |p| {
                        Err(format!("the receipt names {p}, which is not there"))
                    })
            });
        if let Err(e) = checked {
            failed.push(format!("{name}: {e}"));
            continue;
        }
        let mut receipt = receipt;
        receipt.insert("submitter".into(), Value::from(name.clone()));
        receipt.insert("digest".into(), Value::from(d.clone()));
        receipt.insert("size".into(), Value::from(checkpoint.size()));
        receipt.insert("anchored_at".into(), Value::from(now()));
        println!(
            "  {name}: anchored checkpoint {} at size {} ({})",
            short(&d),
            checkpoint.size(),
            receipt.get("kind").and_then(Value::as_str).unwrap_or("")
        );
        receipts.push(Value::Object(receipt));
        // Written after each success, so a later failure never loses an earlier receipt.
        let body = serde_json::to_string_pretty(&receipts).map_err(|e| e.to_string())?;
        std::fs::write(&receipts_path, body + "\n")
            .map_err(|e| format!("{}: {e}", receipts_path.display()))?;
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("not anchored: {}", failed.join("; ")))
    }
}

/// The digest an RFC 3161 token is over, read by openssl so no hand-written DER decides it.
/// `None` when openssl is not available.
fn token_imprint(token: &Path) -> Option<std::result::Result<String, String>> {
    let out = Command::new("openssl")
        .args(["ts", "-reply", "-text", "-in"])
        .arg(token)
        .output()
        .ok()?;
    if !out.status.success() {
        return Some(Err("openssl cannot read the token".into()));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut imprint = String::new();
    let mut in_data = false;
    for line in text.lines() {
        if line.trim_start().starts_with("Message data:") {
            in_data = true;
            continue;
        }
        if in_data {
            // Dump lines look like "    0000 - 5a 3b 00 ... 7f   ascii"; stop at the first
            // line that is not one.
            let Some((offset, rest)) = line.trim_start().split_once(" - ") else {
                break;
            };
            if !offset.chars().all(|c| c.is_ascii_hexdigit()) {
                break;
            }
            for word in rest.split([' ', '-']).filter(|w| !w.is_empty()) {
                if word.len() == 2 && word.chars().all(|c| c.is_ascii_hexdigit()) {
                    imprint.push_str(&word.to_ascii_lowercase());
                } else {
                    break;
                }
            }
        }
    }
    Some(Ok(imprint))
}

fn short(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

/// One kept checkpoint and its receipts, checked against the log as it is now. Returns
/// whether it is the current checkpoint, or what is wrong with it.
fn check_kept(
    log: &LogDir,
    current: &Checkpoint,
    policy: &TrustPolicy,
    path: &Path,
) -> std::result::Result<bool, String> {
    let anchors = path.parent().unwrap_or(path);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = std::fs::read_to_string(path).map_err(|_| "unreadable".to_owned())?;
    let note = Note::parse(&text).map_err(|e| format!("not a signed note: {e}"))?;
    if digest(&note) != stem {
        return Err("the kept checkpoint does not hash to its name".into());
    }
    note.verify(core::slice::from_ref(&policy.log))
        .map_err(|e| format!("not signed by the log: {e}"))?;
    let old = Checkpoint::parse(note.text()).map_err(|e| e.to_string())?;
    if old.origin() != policy.log.name() {
        return Err("a checkpoint of another log".into());
    }
    Tiles::new(log, current.size())
        .consistency_proof(old.size())
        .map_err(|e| e.to_string())
        .and_then(|proof| {
            merkle::verify_consistency(
                old.size(),
                current.size(),
                old.root(),
                current.root(),
                &proof,
            )
            .map_err(|e| e.to_string())
        })
        .map_err(|e| {
            format!(
                "size {} is not consistent with the log now, size {}: {e}",
                old.size(),
                current.size()
            )
        })?;
    let receipts = read_receipts(&anchors.join(format!("{stem}.json")))?;
    if receipts.is_empty() {
        return Err("kept, but no authority has anchored it".into());
    }
    for receipt in &receipts {
        let Value::Object(r) = receipt else {
            return Err("a receipt is not an object".into());
        };
        let kind = r.get("kind").and_then(Value::as_str).unwrap_or("?");
        let paths = token_paths(r).map_err(|e| format!("{kind}: {e}"))?;
        if let Some(missing) = paths.iter().find(|p| !anchors.join(p).is_file()) {
            return Err(format!("{kind}: {missing} is missing"));
        }
        let detail = match kind {
            "rfc3161" => match paths.first().and_then(|p| token_imprint(&anchors.join(p))) {
                None => "token present; openssl not found, its digest not checked".to_owned(),
                Some(Ok(imprint)) if imprint == stem => format!(
                    "the token is over this checkpoint, time {}",
                    r.get("tsa_time")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ),
                Some(Ok(imprint)) => {
                    return Err(format!(
                        "rfc3161: the token is over {imprint}, not this checkpoint"
                    ));
                }
                Some(Err(e)) => return Err(format!("rfc3161: {e}")),
            },
            "opentimestamps" => format!(
                "proof present, {}; `ots verify` checks it against Bitcoin",
                r.get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("state unknown")
            ),
            other => format!("{other}: token present, not a kind remit checks"),
        };
        println!(
            "  size {:>6}  {}  {kind}: {detail}",
            old.size(),
            short(&stem)
        );
    }
    Ok(old.size() == current.size() && old.root() == current.root())
}

/// `remit log verify-anchors`: every anchored checkpoint was signed by the log, is
/// consistent with the log as it is now, and has the receipts and tokens it claims.
pub(crate) fn verify_anchors(dir: &Path, policy: &TrustPolicy) -> Result<()> {
    let log = LogDir::new(dir);
    let current = log.checkpoint(&policy.log).map_err(|e| e.to_string())?;
    let anchors = anchors_dir(dir);
    let mut kept: Vec<PathBuf> = match std::fs::read_dir(&anchors) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "checkpoint"))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", anchors.display())),
    };
    // Oldest first: by the size each kept checkpoint records, read cheaply from its body.
    kept.sort_by_key(|p| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|t| t.lines().nth(1).and_then(|l| l.parse::<u64>().ok()))
            .unwrap_or(u64::MAX)
    });
    let mut problems = Vec::new();
    let mut current_anchored = false;
    for path in &kept {
        match check_kept(&log, &current, policy, path) {
            Ok(is_current) => current_anchored |= is_current,
            Err(e) => {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                problems.push(format!("{}: {e}", short(&stem)));
            }
        }
    }
    if !problems.is_empty() {
        return Err(format!("anchors do not verify: {}", problems.join("; ")));
    }
    println!(
        "  {} anchored checkpoint(s), all consistent with size {}{}",
        kept.len(),
        current.size(),
        if current_anchored {
            "; the current checkpoint is anchored"
        } else {
            "; the current checkpoint is not anchored yet"
        }
    );
    Ok(())
}
