//! Signed notes, checkpoints and cosignatures against the specification's own example and
//! against vectors made by the reference Go implementations (tests/vectors), then every
//! way a note or checkpoint can be wrong.

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
    base64, open,
};
use serde_json::Value;

const DASH: char = '\u{2014}';

fn vectors() -> Value {
    let path = format!("{}/tests/vectors/c2sp-go.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn seed(hex: &str) -> [u8; 32] {
    (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_owned()
}

struct Keys {
    log: NoteSigner,
    witness: NoteSigner,
}

fn keys() -> Keys {
    let v = vectors();
    Keys {
        log: NoteSigner::from_seed(
            "log.example.com/remit-test",
            KeyKind::Log,
            &seed(&s(&v, "log_seed_hex")),
        )
        .unwrap(),
        witness: NoteSigner::from_seed(
            "witness.example.com/w1",
            KeyKind::Witness,
            &seed(&s(&v, "witness_seed_hex")),
        )
        .unwrap(),
    }
}

fn policy(k: &Keys, quorum: usize) -> TrustPolicy {
    TrustPolicy {
        log: k.log.verifier_key().clone(),
        witnesses: vec![k.witness.verifier_key().clone()],
        quorum,
    }
}

#[test]
fn the_signed_note_specification_example() {
    let vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
    let key = VerifierKey::parse(vkey).unwrap();
    assert_eq!(key.id(), 0x530d_903a);
    assert_eq!(key.to_vkey(), vkey);
    let note = format!(
        "This is an example message.\n\n{DASH} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
    );
    let parsed = Note::parse(&note).unwrap();
    assert_eq!(parsed.text(), "This is an example message.\n");
    assert_eq!(parsed.verify(&[key]).unwrap().len(), 1);
    assert_eq!(parsed.to_string(), note);
}

#[test]
fn keys_and_signatures_match_the_reference_implementation_byte_for_byte() {
    let v = vectors();
    let k = keys();
    assert_eq!(k.log.verifier_key().to_vkey(), s(&v, "log_vkey"));
    assert_eq!(k.witness.verifier_key().to_vkey(), s(&v, "witness_vkey"));
    assert_eq!(
        VerifierKey::parse(&s(&v, "witness_vkey")).unwrap().kind(),
        KeyKind::Witness
    );

    let body = s(&v, "body");
    let log_line = k.log.sign(&body, 0).unwrap();
    assert_eq!(format!("{body}\n{log_line}"), s(&v, "signed"));

    // The cosignature carries its time; signing at the same time gives the same bytes.
    let cosigned = Note::parse(&s(&v, "cosigned")).unwrap();
    let time = u64::from_be_bytes(cosigned.signatures()[1].signature[..8].try_into().unwrap());
    let witness_line = k.witness.sign(&body, time).unwrap();
    assert_eq!(
        format!("{body}\n{log_line}{witness_line}"),
        s(&v, "cosigned")
    );
}

#[test]
fn a_reference_checkpoint_opens_under_a_quorum_and_not_above_it() {
    let v = vectors();
    let k = keys();
    let trusted = open(&s(&v, "cosigned"), &policy(&k, 1)).unwrap();
    assert_eq!(trusted.checkpoint.size(), 8);
    assert_eq!(trusted.checkpoint.origin(), "log.example.com/remit-test");
    assert_eq!(trusted.checkpoint.body(), s(&v, "body"));
    assert_eq!(trusted.cosignatures.len(), 1);
    assert!(trusted.cosignatures[0].time.unwrap() > 1_700_000_000);

    assert!(open(&s(&v, "signed"), &policy(&k, 0)).is_ok());
    assert_eq!(
        open(&s(&v, "signed"), &policy(&k, 1)).unwrap_err(),
        CheckpointError::Quorum { need: 1, got: 0 }
    );
    assert_eq!(
        open(&s(&v, "cosigned"), &policy(&k, 2)).unwrap_err(),
        CheckpointError::Quorum { need: 2, got: 1 }
    );
}

fn signed(k: &Keys, body: &str) -> String {
    format!(
        "{body}\n{}{}",
        k.log.sign(body, 0).unwrap(),
        k.witness.sign(body, 1_790_000_000).unwrap()
    )
}

#[test]
fn a_changed_note_is_rejected() {
    let k = keys();
    let body = Checkpoint::new("log.example.com/remit-test", 8, [7; 32])
        .unwrap()
        .body();
    let good = signed(&k, &body);
    assert!(open(&good, &policy(&k, 1)).is_ok());

    // Any changed byte of the text or of either signature.
    let bytes = good.as_bytes();
    for i in 0..bytes.len() {
        let mut bad = bytes.to_vec();
        bad[i] ^= 0x01;
        if let Ok(bad) = String::from_utf8(bad) {
            assert!(open(&bad, &policy(&k, 1)).is_err(), "byte {i}");
        }
    }

    // A known key whose signature fails rejects the note, even beside a good one.
    let other =
        NoteSigner::from_seed("log.example.com/remit-test", KeyKind::Log, &[9; 32]).unwrap();
    let forged_body = Checkpoint::new("log.example.com/remit-test", 9, [7; 32])
        .unwrap()
        .body();
    let forged_line = other.sign(&forged_body, 0).unwrap();
    assert_eq!(
        open(&format!("{forged_body}\n{forged_line}"), &policy(&k, 0)).unwrap_err(),
        CheckpointError::Note(NoteError::NoTrustedSignature),
        "an unknown key is ignored, so nothing trusted signed"
    );
    // A known witness's signature over something else, beside the good ones: rejected,
    // not skipped.
    let other_body = Checkpoint::new("log.example.com/remit-test", 9, [8; 32])
        .unwrap()
        .body();
    let misplaced = k.witness.sign(&other_body, 5).unwrap();
    assert_eq!(
        open(&format!("{good}{misplaced}"), &policy(&k, 1)).unwrap_err(),
        CheckpointError::Note(NoteError::BadSignature("witness.example.com/w1".into()))
    );
}

#[test]
fn only_the_log_can_sign_a_checkpoint_and_only_for_its_origin() {
    let k = keys();
    let body = Checkpoint::new("log.example.com/remit-test", 8, [7; 32])
        .unwrap()
        .body();
    // Cosigned but not signed by the log.
    let only_witness = format!("{body}\n{}", k.witness.sign(&body, 1).unwrap());
    assert_eq!(
        open(&only_witness, &policy(&k, 1)).unwrap_err(),
        CheckpointError::NotSignedByLog
    );
    // Signed by the log key, for another origin.
    let elsewhere = Checkpoint::new("other.example.com/log", 8, [7; 32])
        .unwrap()
        .body();
    assert_eq!(
        open(&signed(&k, &elsewhere), &policy(&k, 1)).unwrap_err(),
        CheckpointError::WrongOrigin
    );
    // A witness key and a log key cannot stand in for each other.
    let swapped = TrustPolicy {
        log: k.witness.verifier_key().clone(),
        witnesses: vec![k.log.verifier_key().clone()],
        quorum: 0,
    };
    assert!(open(&signed(&k, &body), &swapped).is_err());
}

#[test]
fn one_witness_counts_once() {
    let k = keys();
    let body = Checkpoint::new("log.example.com/remit-test", 8, [7; 32])
        .unwrap()
        .body();
    let twice = format!("{}{}", signed(&k, &body), k.witness.sign(&body, 2).unwrap());
    assert_eq!(open(&twice, &policy(&k, 1)).unwrap().cosignatures.len(), 1);
    assert!(open(&twice, &policy(&k, 2)).is_err());

    // The same public key under a second name is still one witness.
    let seed_hex = s(&vectors(), "witness_seed_hex");
    let alias = NoteSigner::from_seed(
        "witness.example.com/alias",
        KeyKind::Witness,
        &seed(&seed_hex),
    )
    .unwrap();
    let both = format!("{}{}", signed(&k, &body), alias.sign(&body, 3).unwrap());
    let mut p = policy(&k, 2);
    p.witnesses.push(alias.verifier_key().clone());
    assert_eq!(
        open(&both, &p).unwrap_err(),
        CheckpointError::Quorum { need: 2, got: 1 }
    );
}

#[test]
fn checkpoint_bodies_have_one_form() {
    let root = base64::encode(&[7; 32]);
    let good = format!("log.example.com/x\n8\n{root}\n");
    assert_eq!(Checkpoint::parse(&good).unwrap().body(), good);
    assert_eq!(
        Checkpoint::parse(&format!("o\n0\n{root}\n"))
            .unwrap()
            .size(),
        0
    );
    for bad in [
        format!("log.example.com/x\n08\n{root}\n"),
        format!("log.example.com/x\n+8\n{root}\n"),
        format!("log.example.com/x\n\n{root}\n"),
        format!("log.example.com/x\n8 \n{root}\n"),
        format!("log.example.com/x\n18446744073709551616\n{root}\n"),
        format!("log.example.com/x\n8\n{root}"),
        format!("log.example.com/x\n8\n{root}\nextension\n"),
        format!("log.example.com/x\n8\n{}\n", base64::encode(&[7; 31])),
        format!("log.example.com/x\n8\n{}\n", root.trim_end_matches('=')),
        format!("\n8\n{root}\n"),
        format!("log example\n8\n{root}\n"),
        format!("log+example\n8\n{root}\n"),
        format!("log.example.com/x\r\n8\n{root}\n"),
    ] {
        assert!(Checkpoint::parse(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn notes_have_one_form() {
    let k = keys();
    let body = "log.example.com/remit-test\n1\nAAAA\n";
    let line = k.log.sign(body, 0).unwrap();
    assert!(Note::parse(&format!("{body}\n{line}")).is_ok());
    let sig = line.trim_end_matches('\n');
    for bad in [
        format!("{body}{line}"),                            // no blank line
        format!("{body}\n"),                                // no signatures
        format!("{body}\n{sig}"),                           // no final newline
        format!("{body}\n{line}\n"),                        // an empty signature line
        format!("{body}\n{}", line.replacen(DASH, "-", 1)), // a hyphen for the dash
        format!("{body}\n{}", line.replacen(' ', "  ", 1)), // two spaces
        format!("{}\n{line}", body.replace('\n', "\r\n")),  // carriage returns
        format!("x\u{7}\n\n{line}"),                        // a control character
    ] {
        assert!(Note::parse(&bad).is_err(), "{bad:?}");
    }
    let many = format!("{body}\n{}", line.repeat(65));
    assert_eq!(Note::parse(&many).unwrap_err(), NoteError::TooLarge);
    assert!(Note::parse(&format!("{body}\n{}", line.repeat(64))).is_ok());
    assert_eq!(
        Note::parse(&"x".repeat(200_000)).unwrap_err(),
        NoteError::TooLarge
    );
    // Signing refuses text that could not be a note.
    assert!(k.log.sign("no newline", 0).is_err());
    assert!(k.witness.sign(body, u64::MAX).is_err());
}

#[test]
fn verifier_keys_have_one_form() {
    let good = keys().log.verifier_key().to_vkey();
    assert!(VerifierKey::parse(&good).is_ok());
    let (name, rest) = good.split_once('+').unwrap();
    let (id, material) = rest.split_once('+').unwrap();
    for bad in [
        format!("{name}+{}+{material}", id.to_uppercase()),
        format!("{name}+0{id}+{material}"),
        format!("{name}+00000000+{material}"),
        format!("{name}+{id}+{material}+extra"),
        format!("{name}+{id}+{material}=="),
        format!("{name}+{id}"),
        format!("+{id}+{material}"),
        format!("{name}+{id}+{}", material.replacen('A', "B", 1)),
        format!("{name}+{id}+{}", base64::encode(&[0x02; 33])),
    ] {
        assert!(VerifierKey::parse(&bad).is_err(), "{bad}");
    }
}
