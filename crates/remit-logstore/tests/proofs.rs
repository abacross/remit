//! SPEC section 9.3: a chain is proven logged only when every link is included in a
//! checkpoint the verifier's policy trusts.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use remit_core::{IssuerKey, SignedWarrant, Warrant, WarrantSpec};
use remit_log::{Entry, KeyKind, LoggedProof, NoteSigner, ProofFileError, TrustPolicy};
use remit_logstore::{LocalWitness, Log, LogDir};

const ORIGIN: &str = "log.example.com/remit-test";

fn log_key() -> NoteSigner {
    NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[4; 32]).unwrap()
}
fn witness_key() -> NoteSigner {
    NoteSigner::from_seed("witness.example.com/w1", KeyKind::Witness, &[5; 32]).unwrap()
}
fn clock() -> u64 {
    1_790_000_000
}

fn policy_text(quorum: usize) -> String {
    format!(
        "# who this broker trusts\nlog {}\nwitness {}\nquorum {quorum}\n",
        log_key().verifier_key().to_vkey(),
        witness_key().verifier_key().to_vkey()
    )
}

/// A two-link chain: a root warrant to an agent key, and its delegation.
fn chain(seed: u8) -> Vec<SignedWarrant> {
    let root = IssuerKey::from_seed(&[seed; 32]);
    let agent = IssuerKey::from_seed(&[seed.wrapping_add(100); 32]);
    let parent = Warrant::new(&WarrantSpec {
        issuer: root.id().as_str(),
        subject: agent.id().as_str(),
        purpose: "proof tests",
        not_before: 1_790_000_000,
        not_after: 1_790_003_600,
        grants: &[(&["s3:Get*"], &["arn:aws:s3:::reports/*"])],
        parent: None,
        max_depth: 1,
    })
    .unwrap();
    let child = Warrant::new(&WarrantSpec {
        issuer: agent.id().as_str(),
        subject: "sub-agent",
        purpose: "proof tests",
        not_before: 1_790_000_000,
        not_after: 1_790_003_600,
        grants: &[(&["s3:GetObject"], &["arn:aws:s3:::reports/2026/*"])],
        parent: Some(parent.id().clone()),
        max_depth: 0,
    })
    .unwrap();
    vec![root.sign(&parent).unwrap(), agent.sign(&child).unwrap()]
}

fn logged(name: &str, links: &[SignedWarrant]) -> (PathBuf, LogDir) {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    let mut w = LocalWitness::open(
        witness_key(),
        vec![log_key().verifier_key().clone()],
        &d.join("witness-state"),
        clock,
    )
    .unwrap();
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    // Unrelated entries first, so indices are not trivially zero.
    let noise: Vec<Entry> = chain(50)
        .into_iter()
        .map(|l| Entry::warrant(l).unwrap())
        .collect();
    log.append(&noise, &mut [&mut w]).unwrap();
    let entries: Vec<Entry> = links
        .iter()
        .map(|l| Entry::warrant(l.clone()).unwrap())
        .collect();
    log.append(&entries, &mut [&mut w]).unwrap();
    (d.join("log"), LogDir::new(&d.join("log")))
}

fn prove(dir: &LogDir, links: &[SignedWarrant]) -> LoggedProof {
    let checkpoint = dir.checkpoint(log_key().verifier_key()).unwrap();
    let size = checkpoint.size();
    let proofs = links
        .iter()
        .map(|l| {
            let i = dir
                .find(&Entry::warrant(l.clone()).unwrap(), size)
                .unwrap()
                .unwrap();
            (i, dir.inclusion_proof(i, size).unwrap())
        })
        .collect();
    LoggedProof {
        links: proofs,
        checkpoint: dir.checkpoint_text().unwrap(),
    }
}

#[test]
fn a_logged_chain_is_proven_and_the_proof_travels_as_text() {
    let links = chain(1);
    let (_, dir) = logged("proof-ok", &links);
    let proof = prove(&dir, &links);
    assert_eq!(proof.links[0].0, 2);
    let policy = TrustPolicy::parse(&policy_text(1)).unwrap();
    let parsed = LoggedProof::parse(&proof.encode()).unwrap();
    assert_eq!(parsed, proof);
    let trusted = parsed.verify(&links, &policy).unwrap();
    assert_eq!(trusted.checkpoint.size(), 4);
}

#[test]
fn nothing_else_is_proven() {
    let links = chain(1);
    let (_, dir) = logged("proof-bad", &links);
    let proof = prove(&dir, &links);
    let policy = TrustPolicy::parse(&policy_text(1)).unwrap();

    // Another chain, the same chain shortened, or links swapped.
    assert_eq!(
        proof.verify(&chain(2), &policy).unwrap_err(),
        ProofFileError::NotLogged(0)
    );
    assert_eq!(
        proof.verify(&links[..1], &policy).unwrap_err(),
        ProofFileError::WrongLinks
    );
    let swapped = vec![links[1].clone(), links[0].clone()];
    assert!(proof.verify(&swapped, &policy).is_err());
    // A wrong index.
    let mut shifted = proof.clone();
    shifted.links[1].0 = 2;
    assert_eq!(
        shifted.verify(&links, &policy).unwrap_err(),
        ProofFileError::NotLogged(1)
    );
    // A checkpoint the policy does not trust: one more witness than signed it.
    let other_witness =
        NoteSigner::from_seed("witness.example.com/w2", KeyKind::Witness, &[7; 32]).unwrap();
    let strict = TrustPolicy::parse(&format!(
        "log {}\nwitness {}\nwitness {}\nquorum 2\n",
        log_key().verifier_key().to_vkey(),
        witness_key().verifier_key().to_vkey(),
        other_witness.verifier_key().to_vkey()
    ))
    .unwrap();
    assert!(matches!(
        proof.verify(&links, &strict),
        Err(ProofFileError::Checkpoint(_))
    ));
    // A chain that was never logged, proven against a real checkpoint.
    let never = chain(3);
    let forged = LoggedProof {
        links: vec![(0, proof.links[0].1.clone()), (1, proof.links[1].1.clone())],
        checkpoint: proof.checkpoint.clone(),
    };
    assert!(forged.verify(&never, &policy).is_err());
}

#[test]
fn proof_files_have_one_form() {
    let links = chain(1);
    let (_, dir) = logged("proof-form", &links);
    let text = prove(&dir, &links).encode();
    for bad in [
        text.replacen("remit-logged/v1", "remit-logged/v2", 1),
        text.replacen("\n2 ", "\n02 ", 1),
        text.replacen("\n2 ", "\n-2 ", 1),
        text.replacen("\n\n", "\n", 1),
        text.replacen("\n2 ", "\n2  ", 1),
    ] {
        assert!(LoggedProof::parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn policies_have_one_form() {
    assert_eq!(TrustPolicy::parse(&policy_text(1)).unwrap().quorum, 1);
    assert_eq!(TrustPolicy::parse(&policy_text(0)).unwrap().quorum, 0);
    let log = log_key().verifier_key().to_vkey();
    let witness = witness_key().verifier_key().to_vkey();
    for bad in [
        policy_text(2),                                  // more than the witnesses
        format!("witness {witness}\nquorum 1\n"),        // no log
        format!("log {log}\nwitness {witness}\n"),       // no quorum
        format!("log {log}\nlog {log}\nquorum 0\n"),     // two logs
        format!("log {witness}\nquorum 0\n"),            // a witness key as the log
        format!("log {log}\nwitness {log}\nquorum 1\n"), // a log key as a witness
        format!("log {log}\nquorum one\n"),
        format!("log {log}\nquorum 0\nmirror x\n"),
        format!("log {log}\nwitness {witness}\nwitness {witness}\nquorum 2\n"), // one witness twice
    ] {
        assert!(TrustPolicy::parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn the_log_establishes_only_warrants_whose_whole_chain_is_logged_and_trusted() {
    let trusted = chain(1);
    let untrusted_root = chain(2);
    let orphan = chain(3);
    let mut links = trusted.clone();
    links.push(untrusted_root[0].clone());
    links.push(orphan[1].clone()); // its parent is never logged
    links.push(trusted[1].clone()); // logged twice, counted once
    let (_, dir) = logged("establish", &links);
    let policy = TrustPolicy::parse(&policy_text(1)).unwrap();
    let roots = [remit_core::KeyId::parse(trusted[0].warrant().issuer().as_str()).unwrap()];

    let got = remit_logstore::logged_warrants(&dir, &policy, &roots).unwrap();
    let ids: Vec<_> = got.warrants.iter().map(|w| w.id().clone()).collect();
    assert_eq!(
        ids,
        vec![
            trusted[0].warrant().id().clone(),
            trusted[1].warrant().id().clone()
        ]
    );
    // The noise chain (root 50, two links), the untrusted root, and the orphan.
    assert_eq!(got.refused.len(), 4, "{:#?}", got.refused);
    assert!(got.refused.iter().any(|r| r.contains("is not logged")));
    assert_eq!(got.checkpoint.checkpoint.size(), 7);

    // Nothing is established from a checkpoint the policy does not trust.
    let other =
        NoteSigner::from_seed("witness.example.com/w2", KeyKind::Witness, &[7; 32]).unwrap();
    let strict = TrustPolicy::parse(&format!(
        "log {}\nwitness {}\nwitness {}\nquorum 2\n",
        log_key().verifier_key().to_vkey(),
        witness_key().verifier_key().to_vkey(),
        other.verifier_key().to_vkey()
    ))
    .unwrap();
    assert!(remit_logstore::logged_warrants(&dir, &strict, &roots).is_err());
}
