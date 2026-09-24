//! SPEC sections 3.5 and 3.6: the canonical encoding and the identifier, pinned.
//!
//! The expected values were computed by this crate and checked independently with
//! Python's hashlib and base64 (2026-09-24). A change to either is a change to every
//! warrant identifier and every signature, and must come with a new SPEC version.

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;

use remit_core::{Warrant, WarrantId, WarrantSpec};

const GOLDEN_BYTES: &str = "52454d49545776310001000000096b65793a616c6963650000000c6167656e743a72756e6e65720000001a72656164207468652053657074656d626572207265706f727473000000006ab13b80000000006ab1499000000001000000020000000c73333a4765744f626a6563740000000d73333a4c6973744275636b6574000000020000001461726e3a6177733a73333a3a3a7265706f7274730000001661726e3a6177733a73333a3a3a7265706f7274732f2a000000000000000001";
const GOLDEN_ID: &str = "rw1-cjsm42jvx5b4getm3ejycmwypj2vywry";

fn golden(purpose: &str, grants: &[(&[&str], &[&str])]) -> Warrant {
    Warrant::new(&WarrantSpec {
        issuer: "key:alice",
        subject: "agent:runner",
        purpose,
        not_before: 1_790_000_000,
        not_after: 1_790_003_600,
        grants,
        parent: None,
        max_depth: 1,
    })
    .unwrap()
}

const GRANTS: &[(&[&str], &[&str])] = &[(
    &["s3:GetObject", "s3:ListBucket"],
    &["arn:aws:s3:::reports", "arn:aws:s3:::reports/*"],
)];

#[test]
fn encoding_and_identifier_match_the_golden_vector() {
    let w = golden("read the September reports", GRANTS);
    let hex = w
        .canonical_bytes()
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
    assert_eq!(hex, GOLDEN_BYTES);
    assert_eq!(w.id().as_str(), GOLDEN_ID);
}

#[test]
fn identifier_fits_aws_source_identity() {
    // STS: 2 to 64 characters of [\w+=,.@-], not beginning with "aws:".
    let id = golden("x", GRANTS).id();
    let s = id.as_str();
    assert!((2..=64).contains(&s.len()));
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
    );
    assert!(!s.starts_with("aws:"));
    assert_eq!(WarrantId::parse(s).unwrap(), id);
}

#[test]
fn every_field_changes_the_identifier_and_order_matters() {
    let base = golden("read the September reports", GRANTS).id();
    assert_ne!(golden("read the October reports", GRANTS).id(), base);
    let reordered: &[(&[&str], &[&str])] = &[(
        &["s3:ListBucket", "s3:GetObject"],
        &["arn:aws:s3:::reports", "arn:aws:s3:::reports/*"],
    )];
    // Same authority, different text: a different warrant (SPEC section 3.6).
    assert_ne!(golden("read the September reports", reordered).id(), base);
}
