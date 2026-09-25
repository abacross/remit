//! SPEC section 6.7 against digest chains signed by an independent implementation
//! (tests/fixtures/trail/gen.py, Python's `cryptography`): a whole chain validates, and
//! every way the record could be incomplete or altered is named.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::collections::HashMap;

use remit_aws::parse_iso8601;
use remit_reconcile::trail::{DigestFile, TrailKey, ValidatedTrail, validate};
use serde_json::Value;

struct Fixture {
    key: TrailKey,
    digests: Vec<DigestFile>,
    logs: HashMap<(String, String), Vec<u8>>,
}

fn b64(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut n, mut out) = (0u32, 0, Vec::new());
    for c in s.bytes().filter(|&c| c != b'=') {
        bits = (bits << 6) | A.iter().position(|&a| a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

/// The fixture; only the newest digest of each region carries its S3-metadata signature,
/// as when validating offline; older ones' signatures come from their successors.
fn fixture() -> Fixture {
    let path = format!(
        "{}/tests/fixtures/trail/trail.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let key = TrailKey {
        fingerprint: v["key"]["fingerprint"].as_str().unwrap().into(),
        der: b64(v["key"]["der_b64"].as_str().unwrap()),
    };
    let all = v["digests"].as_array().unwrap();
    let digests = all
        .iter()
        .enumerate()
        .map(|(i, d)| DigestFile {
            bucket: d["bucket"].as_str().unwrap().into(),
            object: d["object"].as_str().unwrap().into(),
            bytes: d["text"].as_str().unwrap().as_bytes().to_vec(),
            signature_hex: (i % 4 == 3).then(|| d["signature"].as_str().unwrap().into()),
        })
        .collect();
    let logs = v["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                (
                    l["bucket"].as_str().unwrap().into(),
                    l["object"].as_str().unwrap().into(),
                ),
                l["text"].as_str().unwrap().as_bytes().to_vec(),
            )
        })
        .collect();
    Fixture { key, digests, logs }
}

fn t(s: &str) -> u64 {
    parse_iso8601(s).unwrap()
}

fn regions() -> Vec<String> {
    vec!["us-east-1".into(), "us-west-2".into()]
}

fn run(f: &Fixture, from: &str, to: &str) -> ValidatedTrail {
    validate(
        &f.digests,
        &f.logs,
        std::slice::from_ref(&f.key),
        &regions(),
        t(from),
        t(to),
    )
}

fn has(v: &ValidatedTrail, needle: &str) -> bool {
    v.problems.iter().any(|p| p.contains(needle))
}

#[test]
fn a_whole_signed_chain_validates() {
    let f = fixture();
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(v.problems.is_empty(), "{:#?}", v.problems);
    assert_eq!(v.coverage.len(), 2);
    for c in &v.coverage {
        assert_eq!((c.digests, c.log_files), (4, 3), "{c:?}");
        assert_eq!(
            (c.start, c.end),
            (t("2026-09-24T10:01:31Z"), t("2026-09-24T14:01:31Z"))
        );
    }
    // Two events per log file, three log files per region.
    assert_eq!(v.records.len(), 12);
}

#[test]
fn a_window_the_chain_does_not_reach_is_not_covered() {
    let f = fixture();
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T15:00:00Z");
    assert!(has(&v, "not the whole of"), "{:#?}", v.problems);
    let v = run(&f, "2026-09-24T09:00:00Z", "2026-09-24T12:00:00Z");
    assert!(has(&v, "not the whole of"));
    let v = validate(
        &f.digests,
        &f.logs,
        std::slice::from_ref(&f.key),
        &["eu-west-1".into()],
        t("2026-09-24T11:00:00Z"),
        t("2026-09-24T12:00:00Z"),
    );
    assert!(has(&v, "eu-west-1: no digest files"));
}

#[test]
fn an_altered_or_missing_log_file_is_named() {
    let mut f = fixture();
    let key = f.logs.keys().next().unwrap().clone();
    let bytes = f.logs.get_mut(&key).unwrap();
    let at = bytes.iter().position(|&b| b == b'L').unwrap(); // in "ListBuckets"
    bytes[at] = b'D';
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(
        has(&v, "its hash is not the one its digest records"),
        "{:#?}",
        v.problems
    );
    let mut f = fixture();
    let key = f.logs.keys().next().unwrap().clone();
    f.logs.remove(&key);
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(has(&v, "listed in a digest but not provided"));
    assert!(v.coverage.len() < 2);
}

#[test]
fn an_edited_digest_breaks_its_signature_and_its_link() {
    let mut f = fixture();
    // Drop one log file from the second us-east-1 digest's list: what an attacker hiding
    // a log file would have to do.
    let d = &mut f.digests[1];
    let mut json: Value = serde_json::from_slice(&d.bytes).unwrap();
    json["logFiles"].as_array_mut().unwrap().pop();
    d.bytes = serde_json::to_vec(&json).unwrap();
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(has(&v, "signature does not verify"), "{:#?}", v.problems);
    assert!(has(&v, "does not chain to"));
}

#[test]
fn a_missing_hour_is_a_gap() {
    let mut f = fixture();
    f.digests.remove(2);
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(has(&v, "the record has a gap"), "{:#?}", v.problems);
    assert!(has(&v, "does not chain to"));
}

#[test]
fn a_digest_away_from_its_recorded_location_is_refused() {
    let mut f = fixture();
    f.digests[3].object = f.digests[3].object.replace("2026/09/24", "2026/09/25");
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(
        has(&v, "not at the location it records"),
        "{:#?}",
        v.problems
    );
}

#[test]
fn signatures_need_a_known_key_and_must_agree() {
    let f = fixture();
    let stranger = TrailKey {
        fingerprint: "0".repeat(32),
        der: f.key.der.clone(),
    };
    let v = validate(
        &f.digests,
        &f.logs,
        &[stranger],
        &regions(),
        t("2026-09-24T10:30:00Z"),
        t("2026-09-24T13:30:00Z"),
    );
    assert!(has(&v, "no public key with fingerprint"));
    // The newest digest's signature is only in S3 metadata; without it, it is unverified.
    let mut f2 = fixture();
    f2.digests[3].signature_hex = None;
    let v = run(&f2, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(has(&v, "no signature"));
    // Metadata that disagrees with the successor's record of it.
    let mut f3 = fixture();
    let other = f3.digests[1].signature_hex.clone();
    f3.digests[0].signature_hex = Some(other.unwrap_or_else(|| "ab".repeat(256)));
    let v = run(&f3, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(has(&v, "differs from the one its successor records"));
    // A signature from another key entirely.
    let mut f4 = fixture();
    f4.digests[3].signature_hex = Some("00".repeat(256));
    let v = run(&f4, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(has(&v, "signature does not verify"));
}

#[test]
fn a_restarted_chain_inside_the_window_is_named() {
    let mut f = fixture();
    let d = &mut f.digests[2];
    let mut json: Value = serde_json::from_slice(&d.bytes).unwrap();
    for k in [
        "previousDigestS3Bucket",
        "previousDigestS3Object",
        "previousDigestHashValue",
        "previousDigestHashAlgorithm",
        "previousDigestSignature",
    ] {
        json[k] = Value::Null;
    }
    d.bytes = serde_json::to_vec(&json).unwrap();
    let v = run(&f, "2026-09-24T10:30:00Z", "2026-09-24T13:30:00Z");
    assert!(
        has(&v, "validation was restarted here"),
        "{:#?}",
        v.problems
    );
}
