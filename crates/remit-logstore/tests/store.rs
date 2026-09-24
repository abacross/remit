//! The log on disk: grown with a local witness, read back through its files, and
//! recovered from a crash at each point an append can stop.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;

use remit_core::{IssuerKey, RESULT_DOMAIN, Warrant, WarrantSpec, sign_in_domain};
use remit_log::{
    Entry, KeyKind, NoteSigner, TrustPolicy, VerifierKey, WitnessError, open, root,
    verify_inclusion,
};
use remit_logstore::{Cosigner, LocalWitness, Log, LogDir, StoreError};

const ORIGIN: &str = "log.example.com/remit-test";

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn log_key() -> NoteSigner {
    NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[4; 32]).unwrap()
}

fn witness_key() -> NoteSigner {
    NoteSigner::from_seed("witness.example.com/w1", KeyKind::Witness, &[5; 32]).unwrap()
}

fn clock() -> u64 {
    1_790_000_000
}

fn witness(state: &std::path::Path) -> LocalWitness {
    LocalWitness::open(
        witness_key(),
        vec![log_key().verifier_key().clone()],
        state,
        clock,
    )
    .unwrap()
}

fn policy() -> TrustPolicy {
    TrustPolicy {
        log: log_key().verifier_key().clone(),
        witnesses: vec![witness_key().verifier_key().clone()],
        quorum: 1,
    }
}

/// Distinct warrant entries, numbered from `from`.
fn entries(from: u64, n: u64) -> Vec<Entry> {
    let key = IssuerKey::from_seed(&[1; 32]);
    (from..from + n)
        .map(|i| {
            let w = Warrant::new(&WarrantSpec {
                issuer: key.id().as_str(),
                subject: "agent",
                purpose: "store tests",
                not_before: 1_790_000_000 + i,
                not_after: 1_790_003_600 + i,
                grants: &[(&["s3:GetObject"], &["arn:aws:s3:::reports/*"])],
                parent: None,
                max_depth: 0,
            })
            .unwrap();
            Entry::warrant(key.sign(&w).unwrap()).unwrap()
        })
        .collect()
}

fn log_vkey() -> VerifierKey {
    log_key().verifier_key().clone()
}

#[test]
fn a_witnessed_log_grows_and_every_entry_is_provable() {
    let d = dir("grows");
    let state = d.join("witness-state");
    let mut w = witness(&state);
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    let mut all = Vec::new();
    for (from, n) in [(0, 1), (1, 3), (4, 300), (304, 1)] {
        let batch = entries(from, n);
        let out = log.append(&batch, &mut [&mut w]).unwrap();
        assert_eq!(out.first, from);
        assert!(out.refusals.is_empty(), "{:?}", out.refusals);
        all.extend(batch);
        // The published checkpoint opens under a policy requiring the witness.
        let trusted = open(&out.checkpoint, &policy()).unwrap();
        assert_eq!(trusted.checkpoint.size(), all.len() as u64);
        let leaves: Vec<_> = all.iter().map(Entry::leaf_hash).collect();
        assert_eq!(trusted.checkpoint.root(), &root(&leaves));
    }
    // Read back without the lock, as a verifier would.
    let reader = LogDir::new(&d.join("log"));
    let current = reader.checkpoint(&log_vkey()).unwrap();
    let size = current.size();
    for i in [0, 1, 150, 303, 304] {
        let entry = reader.entry(i, size).unwrap();
        assert_eq!(entry, all[i as usize]);
        assert_eq!(reader.find(&entry, size).unwrap(), Some(i));
        let proof = reader.inclusion_proof(i, size).unwrap();
        verify_inclusion(i, size, &entry.leaf_hash(), &proof, current.root()).unwrap();
    }
    assert_eq!(reader.find(&entries(999, 1)[0], size).unwrap(), None);
    // The witness's durable state is the last size it cosigned.
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(text.starts_with(&format!("{ORIGIN} 305 ")), "{text}");
}

#[test]
fn one_writer_at_a_time() {
    let d = dir("lock");
    let log = Log::create(&d, log_key()).unwrap();
    assert!(matches!(Log::open(&d, log_key()), Err(StoreError::Locked)));
    drop(log);
    assert!(Log::open(&d, log_key()).is_ok());
    assert!(matches!(
        Log::create(&d, log_key()),
        Err(StoreError::Refused(_))
    ));
    // A different key cannot open it.
    let other = NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[6; 32]).unwrap();
    assert!(matches!(Log::open(&d, other), Err(StoreError::Corrupt(_))));
}

#[test]
fn a_crash_before_the_commit_leaves_nothing_behind() {
    let d = dir("crash-before");
    let mut log = Log::create(&d, log_key()).unwrap();
    log.append(&entries(0, 10), &mut []).unwrap();
    let committed = std::fs::read(d.join("checkpoint")).unwrap();
    // Tiles and bundles for 290 entries are written, then the process dies before the
    // checkpoint: simulated by putting the old checkpoint back.
    log.append(&entries(10, 290), &mut []).unwrap();
    std::fs::write(d.join("checkpoint"), &committed).unwrap();
    // Different entries go in next; the leftovers are overwritten, not believed.
    let state = d.join("witness-state");
    let mut w = witness(&state);
    let out = log.append(&entries(500, 260), &mut [&mut w]).unwrap();
    assert!(out.refusals.is_empty());
    let mut expected = entries(0, 10);
    expected.extend(entries(500, 260));
    let leaves: Vec<_> = expected.iter().map(Entry::leaf_hash).collect();
    let trusted = open(&out.checkpoint, &policy()).unwrap();
    assert_eq!(trusted.checkpoint.root(), &root(&leaves));
    let reader = LogDir::new(&d);
    assert_eq!(reader.entry(10, 270).unwrap(), expected[10]);
}

#[test]
fn a_crash_between_commit_and_cosigning_is_finished_later() {
    let d = dir("crash-between");
    let state = d.join("witness-state");
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    // Committed, but no witness was reached.
    log.append(&entries(0, 5), &mut []).unwrap();
    assert!(open(&log.dir().checkpoint_text().unwrap(), &policy()).is_err());
    let mut w = witness(&state);
    let out = log.cosign_current(&mut [&mut w]).unwrap();
    assert!(out.refusals.is_empty(), "{:?}", out.refusals);
    assert_eq!(
        open(&out.checkpoint, &policy()).unwrap().checkpoint.size(),
        5
    );
    // Asking again for the same checkpoint is harmless.
    assert!(
        log.cosign_current(&mut [&mut w])
            .unwrap()
            .refusals
            .is_empty()
    );
    // And the log carries on from there.
    let out = log.append(&entries(5, 5), &mut [&mut w]).unwrap();
    assert!(out.refusals.is_empty());
}

#[test]
fn a_witness_refuses_a_second_history_under_the_same_key() {
    let d = dir("fork");
    let state = d.join("witness-state");
    let mut w = witness(&state);
    let mut honest = Log::create(&d.join("honest"), log_key()).unwrap();
    honest.append(&entries(0, 8), &mut [&mut w]).unwrap();
    // The same key keeps a second log that disagrees about entry 3.
    let mut forked = Log::create(&d.join("forked"), log_key()).unwrap();
    let mut other = entries(0, 3);
    other.extend(entries(100, 9));
    let out = forked.append(&other, &mut [&mut w]).unwrap();
    assert_eq!(out.refusals.len(), 1, "{:?}", out.refusals);
    assert!(open(&out.checkpoint, &policy()).is_err());
    // The witness still follows the honest log.
    let out = honest.append(&entries(8, 1), &mut [&mut w]).unwrap();
    assert!(out.refusals.is_empty());
}

#[test]
fn a_result_is_logged_only_with_its_bytes_published() {
    let d = dir("results");
    let mut log = Log::create(&d, log_key()).unwrap();
    let reconciler = IssuerKey::from_seed(&[2; 32]);
    let result = br#"{"verdict":"complete-unvalidated"}"#.to_vec();
    let sig = sign_in_domain(&reconciler, RESULT_DOMAIN, &result).unwrap();
    let entry = Entry::result(&result, reconciler.id(), &sig).unwrap();
    assert!(matches!(
        log.append(core::slice::from_ref(&entry), &mut []),
        Err(StoreError::Io(..))
    ));
    let digest = log.publish_result(&result).unwrap();
    log.append(&[entry], &mut []).unwrap();
    let reader = LogDir::new(&d);
    assert_eq!(reader.result(&digest).unwrap(), result);
    let logged = reader.entry(0, 1).unwrap();
    logged.check_result(&result).unwrap();
}

/// A cosigner that refuses, standing in for a witness that is down.
struct Down;

impl Cosigner for Down {
    fn name(&self) -> String {
        "down".into()
    }
    fn add_checkpoint(&mut self, _: &str) -> Result<String, WitnessError> {
        Err(WitnessError::BadRequest("unavailable"))
    }
}

#[test]
fn a_witness_that_is_down_does_not_stop_the_log() {
    let d = dir("down");
    let state = d.join("witness-state");
    let mut w = witness(&state);
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    let out = log
        .append(&entries(0, 2), &mut [&mut Down, &mut w])
        .unwrap();
    assert_eq!(
        out.refusals,
        vec![("down".into(), "bad request: unavailable".into())]
    );
    assert!(open(&out.checkpoint, &policy()).is_ok());
}
