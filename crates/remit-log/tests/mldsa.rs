//! ML-DSA-44 witness cosignatures (c2sp.org/tlog-cosignature, type 0x06) against the
//! reference Go implementation: the same seed gives the same key, and each side verifies
//! the other's cosignatures (Go's direction is recorded in conformance/RESULTS.md).

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use remit_log::{
    Checkpoint, CheckpointError, KeyKind, Note, NoteError, NoteSigner, TrustPolicy, VerifierKey,
    Witness, consistency_proof, leaf_hash, open, root,
};
use serde_json::Value;

fn vectors() -> Value {
    let path = format!(
        "{}/tests/vectors/c2sp-go-mldsa.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_owned()
}

fn seed(hex: &str) -> [u8; 32] {
    (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn witness() -> NoteSigner {
    let v = vectors();
    NoteSigner::ml_dsa_witness_from_seed(&s(&v, "witness_name"), &seed(&s(&v, "witness_seed_hex")))
        .unwrap()
}

fn log_key() -> NoteSigner {
    let log_seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
    NoteSigner::from_seed("log.example.com/remit-test", KeyKind::Log, &log_seed).unwrap()
}

fn policy() -> TrustPolicy {
    TrustPolicy {
        log: log_key().verifier_key().clone(),
        witnesses: vec![witness().verifier_key().clone()],
        quorum: 1,
    }
}

#[test]
fn the_same_seed_gives_the_same_key_and_key_id_as_the_reference() {
    let v = vectors();
    assert_eq!(witness().verifier_key().to_vkey(), s(&v, "witness_vkey"));
    let parsed = VerifierKey::parse(&s(&v, "witness_vkey")).unwrap();
    assert_eq!(parsed.kind(), KeyKind::Witness);
    assert_eq!(parsed.public_key().len(), 1312);
    assert_eq!(log_key().verifier_key().to_vkey(), s(&v, "log_vkey"));
}

#[test]
fn a_checkpoint_cosigned_by_the_reference_opens() {
    let v = vectors();
    let trusted = open(&s(&v, "cosigned"), &policy()).unwrap();
    assert_eq!(trusted.checkpoint.size(), 8);
    assert_eq!(trusted.cosignatures.len(), 1);
    assert!(trusted.cosignatures[0].time.unwrap() > 1_700_000_000);
}

#[test]
fn a_cosignature_made_here_verifies_and_nothing_altered_does() {
    let v = vectors();
    let body = s(&v, "body");
    let log_line = log_key().sign(&body, 0).unwrap();
    let pq_line = witness().sign(&body, 1_790_000_000).unwrap();
    let note = format!("{body}\n{log_line}{pq_line}");
    let trusted = open(&note, &policy()).unwrap();
    assert_eq!(trusted.cosignatures[0].time, Some(1_790_000_000));
    // Written for the reference verifier to check (conformance/RESULTS.md).
    let out = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("remit-mldsa-note.txt");
    std::fs::write(out, &note).unwrap();

    // Another checkpoint under the same signature: refused.
    let other = Checkpoint::new("log.example.com/remit-test", 9, [1; 32])
        .unwrap()
        .body();
    let moved = format!("{other}\n{}{pq_line}", log_key().sign(&other, 0).unwrap());
    assert!(matches!(
        open(&moved, &policy()),
        Err(CheckpointError::Note(NoteError::BadSignature(_)))
    ));
    // A changed timestamp: the time is signed.
    let mut raw =
        remit_log::base64::decode(pq_line.trim_end().rsplit(' ').next().unwrap()).unwrap();
    raw[11] ^= 1;
    let bad = format!(
        "{body}\n{log_line}\u{2014} {} {}\n",
        s(&v, "witness_name"),
        remit_log::base64::encode(&raw)
    );
    assert!(open(&bad, &policy()).is_err());
    // A truncated signature.
    raw.truncate(raw.len() - 1);
    let short = format!(
        "{body}\n{log_line}\u{2014} {} {}\n",
        s(&v, "witness_name"),
        remit_log::base64::encode(&raw)
    );
    assert!(open(&short, &policy()).is_err());
    // Only checkpoints can be cosigned with ML-DSA: the message is built from one.
    assert!(witness().sign("not a checkpoint\n", 1).is_err());
    // The Ed25519 note parser and a note with both kinds of witness together.
    assert_eq!(Note::parse(&note).unwrap().signatures().len(), 2);
}

#[test]
fn a_post_quantum_witness_follows_a_log() {
    let leaves: Vec<_> = (0u64..20).map(|i| leaf_hash(&i.to_be_bytes())).collect();
    let mut w = Witness::new(witness(), vec![log_key().verifier_key().clone()], "").unwrap();
    let mut old = 0usize;
    for size in [3usize, 8, 20] {
        let body = Checkpoint::new(
            "log.example.com/remit-test",
            size as u64,
            root(&leaves[..size]),
        )
        .unwrap()
        .body();
        let signed = format!("{body}\n{}", log_key().sign(&body, 0).unwrap());
        let proof: String = consistency_proof(&leaves[..size], old)
            .unwrap()
            .iter()
            .map(|h| remit_log::base64::encode(h) + "\n")
            .collect();
        let line = w
            .add_checkpoint(&format!("old {old}\n{proof}\n{signed}"), 1_790_000_000)
            .unwrap();
        assert_eq!(
            open(&format!("{signed}{line}"), &policy())
                .unwrap()
                .cosignatures
                .len(),
            1
        );
        old = size;
    }
}
