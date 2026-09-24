//! SPEC section 9.1 (entries) and the witness of section 9.2, which must cosign exactly
//! the checkpoints tlog-witness allows and refuse every other with the status it assigns.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use remit_core::{IssuerKey, RESULT_DOMAIN, SignedWarrant, Warrant, WarrantSpec, sign_in_domain};
use remit_log::{
    Checkpoint, Entry, EntryError, KeyKind, MAX_ENTRY_BYTES, NoteSigner, TrustPolicy, Witness,
    WitnessError, base64, consistency_proof, empty_root, leaf_hash, open, root,
};

fn signed(grants: &[(&[&str], &[&str])]) -> SignedWarrant {
    let key = IssuerKey::from_seed(&[1; 32]);
    let w = Warrant::new(&WarrantSpec {
        issuer: key.id().as_str(),
        subject: "agent",
        purpose: "log tests",
        not_before: 1_790_000_000,
        not_after: 1_790_003_600,
        grants,
        parent: None,
        max_depth: 0,
    })
    .unwrap();
    key.sign(&w).unwrap()
}

const S3: &[(&[&str], &[&str])] = &[(&["s3:GetObject"], &["arn:aws:s3:::reports/*"])];

#[test]
fn a_warrant_entry_round_trips_and_nothing_else_decodes() {
    let entry = Entry::warrant(signed(S3)).unwrap();
    let bytes = entry.encode();
    assert_eq!(&bytes[..9], b"REMITLv1\x01");
    assert_eq!(Entry::decode(&bytes).unwrap(), entry);
    assert_eq!(entry.leaf_hash(), leaf_hash(&bytes));

    // Every single-byte change is refused or decodes to something else entirely.
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 0x40;
        assert!(Entry::decode(&bad).is_err(), "byte {i}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Entry::decode(&longer).is_err());
    assert!(Entry::decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(Entry::decode(b"REMITLv1").is_err());
    assert!(Entry::decode(b"REMITLv1\x03").is_err());
}

#[test]
fn a_warrant_too_large_to_log_is_refused() {
    let pattern = format!("arn:aws:s3:::{}", "a".repeat(2000));
    let patterns: Vec<&str> = vec![pattern.as_str()];
    let grants: Vec<(&[&str], &[&str])> = (0..40)
        .map(|_| (&["s3:GetObject"][..], patterns.as_slice()))
        .collect();
    let big = signed(&grants);
    assert!(big.to_transport().len() > MAX_ENTRY_BYTES);
    assert_eq!(Entry::warrant(big).unwrap_err(), EntryError::TooLarge);
}

#[test]
fn a_result_entry_commits_to_the_bytes_and_the_signature() {
    let reconciler = IssuerKey::from_seed(&[2; 32]);
    let result = br#"{"verdict":"complete"}"#;
    let sig = sign_in_domain(&reconciler, RESULT_DOMAIN, result).unwrap();
    let entry = Entry::result(result, reconciler.id(), &sig).unwrap();
    let bytes = entry.encode();
    assert_eq!(bytes.len(), 9 + 32 + 32 + 64);
    let decoded = Entry::decode(&bytes).unwrap();
    assert_eq!(decoded, entry);
    assert_eq!(decoded.check_result(result), Ok(()));
    assert!(
        decoded
            .check_result(br#"{"verdict":"incomplete"}"#)
            .is_err()
    );

    // Not logged at all when the signature is not the reconciler's over these bytes.
    let other = IssuerKey::from_seed(&[3; 32]);
    assert_eq!(
        Entry::result(result, other.id(), &sig).unwrap_err(),
        EntryError::BadSignature
    );
    assert!(Entry::result(b"{}", reconciler.id(), &sig).is_err());
    // A warrant entry is not a result.
    assert!(
        Entry::warrant(signed(S3))
            .unwrap()
            .check_result(result)
            .is_err()
    );
}

// --- the witness --------------------------------------------------------------------

const ORIGIN: &str = "log.example.com/remit-test";

struct Log {
    key: NoteSigner,
    leaves: Vec<[u8; 32]>,
}

impl Log {
    fn new() -> Self {
        Self {
            key: NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[4; 32]).unwrap(),
            leaves: Vec::new(),
        }
    }
    fn grow(&mut self, n: usize) {
        let start = self.leaves.len();
        self.leaves
            .extend((start..start + n).map(|i| leaf_hash(&i.to_be_bytes())));
    }
    fn checkpoint(&self, size: usize) -> String {
        let body = Checkpoint::new(ORIGIN, size as u64, root(&self.leaves[..size]))
            .unwrap()
            .body();
        format!("{body}\n{}", self.key.sign(&body, 0).unwrap())
    }
    fn request(&self, old: usize, size: usize) -> String {
        let proof: String = consistency_proof(&self.leaves[..size], old)
            .unwrap()
            .iter()
            .map(|h| base64::encode(h) + "\n")
            .collect();
        format!("old {old}\n{proof}\n{}", self.checkpoint(size))
    }
}

fn witness(log: &Log, state: &str) -> Witness {
    Witness::new(
        NoteSigner::from_seed("witness.example.com/w1", KeyKind::Witness, &[5; 32]).unwrap(),
        vec![log.key.verifier_key().clone()],
        state,
    )
    .unwrap()
}

#[test]
fn a_witness_follows_a_growing_log_and_its_cosignatures_open() {
    let mut log = Log::new();
    let mut w = witness(&log, "");
    let policy = TrustPolicy {
        log: log.key.verifier_key().clone(),
        witnesses: vec![
            NoteSigner::from_seed("witness.example.com/w1", KeyKind::Witness, &[5; 32])
                .unwrap()
                .verifier_key()
                .clone(),
        ],
        quorum: 1,
    };
    let mut old = 0;
    for step in [0, 1, 1, 3, 4, 7, 16, 100] {
        log.grow(step);
        let size = log.leaves.len();
        let line = w
            .add_checkpoint(&log.request(old, size), 1_790_000_000)
            .unwrap();
        let cosigned = format!("{}{line}", log.checkpoint(size));
        let trusted = open(&cosigned, &policy).unwrap();
        assert_eq!(trusted.checkpoint.size(), size as u64);
        assert_eq!(w.latest(ORIGIN).unwrap().0, size as u64);
        old = size;
    }
    // The state survives a restart and the witness carries on from it.
    let mut restarted = witness(&log, &w.state_text());
    log.grow(5);
    let size = log.leaves.len();
    assert!(
        restarted
            .add_checkpoint(&log.request(old, size), 1_790_000_100)
            .is_ok()
    );
}

#[test]
fn a_witness_refuses_what_tlog_witness_refuses() {
    let mut log = Log::new();
    log.grow(10);
    let mut w = witness(&log, "");
    w.add_checkpoint(&log.request(0, 6), 1).unwrap();

    // A fork: another history of the same length, and one that rewrites a cosigned leaf.
    let mut fork = Log::new();
    fork.grow(10);
    fork.leaves[2] = leaf_hash(b"rewritten");
    let status = |w: &mut Witness, req: &str| w.add_checkpoint(req, 2).unwrap_err().status();
    assert_eq!(status(&mut w, &fork.request(6, 10)), 422);
    assert_eq!(status(&mut w, &fork.request(6, 6)), 422);

    // The old size must be the last cosigned one, and is returned when it is not.
    assert_eq!(
        w.add_checkpoint(&log.request(5, 10), 2).unwrap_err(),
        WitnessError::Conflict(6)
    );
    assert_eq!(status(&mut w, &log.request(0, 10)), 409);
    // An old size above the checkpoint's.
    let shrink = log.request(6, 6).replacen("old 6", "old 7", 1);
    assert_eq!(status(&mut w, &shrink), 400);
    // Not signed by the log, or signed by a key for another origin.
    let stranger = NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[6; 32]).unwrap();
    let body = Checkpoint::new(ORIGIN, 10, root(&log.leaves))
        .unwrap()
        .body();
    let unsigned = format!("old 6\n\n{body}\n{}", stranger.sign(&body, 0).unwrap());
    assert_eq!(status(&mut w, &unsigned), 403);
    let elsewhere = NoteSigner::from_seed("other.example.com/log", KeyKind::Log, &[4; 32]).unwrap();
    let body = Checkpoint::new("other.example.com/log", 1, [0; 32])
        .unwrap()
        .body();
    let unknown = format!("old 0\n\n{body}\n{}", elsewhere.sign(&body, 0).unwrap());
    assert_eq!(status(&mut w, &unknown), 404);
    // A tampered proof.
    let good = log.request(6, 10);
    let first_proof = good.lines().nth(1).unwrap().to_owned();
    let flipped = if first_proof.starts_with('A') {
        "B"
    } else {
        "A"
    };
    let bad = good.replacen(&first_proof, &format!("{flipped}{}", &first_proof[1..]), 1);
    assert_eq!(status(&mut w, &bad), 422);
    // Malformed requests.
    for bad in [
        good.replacen("old 6", "old 06", 1),
        good.replacen("old 6", "old", 1),
        good.replacen("old 6\n", "old 6\nnot-base64\n", 1),
        good.replacen("\n\n", "\n", 1),
    ] {
        assert_eq!(status(&mut w, &bad), 400, "{bad}");
    }
    let too_many = format!(
        "old 6\n{}\n{}",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n".repeat(64),
        log.checkpoint(10)
    );
    assert_eq!(status(&mut w, &too_many), 400);

    // None of that moved the witness; the honest next checkpoint is still cosigned.
    assert_eq!(w.latest(ORIGIN).unwrap().0, 6);
    assert!(w.add_checkpoint(&good, 3).is_ok());
    assert_eq!(w.latest(ORIGIN).unwrap().0, 10);
}

#[test]
fn the_empty_tree_is_the_only_tree_of_size_zero() {
    let log = Log::new();
    let mut w = witness(&log, "");
    let body = Checkpoint::new(ORIGIN, 0, [9; 32]).unwrap().body();
    let req = format!("old 0\n\n{body}\n{}", log.key.sign(&body, 0).unwrap());
    assert_eq!(w.add_checkpoint(&req, 1).unwrap_err().status(), 422);
    let body = Checkpoint::new(ORIGIN, 0, empty_root()).unwrap().body();
    let req = format!("old 0\n\n{body}\n{}", log.key.sign(&body, 0).unwrap());
    assert!(w.add_checkpoint(&req, 1).is_ok());
    // A proof from the empty tree is refused.
    let mut log = Log::new();
    log.grow(3);
    let req = format!(
        "old 0\n{}\n\n{}",
        base64::encode(&[1; 32]),
        log.checkpoint(3)
    );
    assert_eq!(w.add_checkpoint(&req, 1).unwrap_err().status(), 422);
    // And a cosignature needs a time.
    assert!(w.add_checkpoint(&log.request(0, 3), 0).is_err());
}
