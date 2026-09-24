//! SPEC section 5: the strict decoder, signed warrants and chains.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use remit_core::{
    ChainError, IssuerKey, KeyId, SignatureError, SignedWarrant, Warrant, WarrantSpec, verify_chain,
};

fn key(n: u8) -> IssuerKey {
    IssuerKey::from_seed(&[n; 32])
}

fn warrant(
    issuer: &str,
    subject: &str,
    grants: &[(&[&str], &[&str])],
    window: (u64, u64),
    parent: Option<remit_core::WarrantId>,
    depth: u64,
) -> Warrant {
    Warrant::new(&WarrantSpec {
        issuer,
        subject,
        purpose: "signature tests",
        not_before: window.0,
        not_after: window.1,
        grants,
        parent,
        max_depth: depth,
    })
    .unwrap()
}

const S3: &[(&[&str], &[&str])] = &[(&["s3:*"], &["arn:aws:s3:::reports/*"])];
const S3_READ: &[(&[&str], &[&str])] = &[(&["s3:Get*"], &["arn:aws:s3:::reports/2026/*"])];
const WIDER: &[(&[&str], &[&str])] = &[(&["s3:*"], &["arn:aws:s3:::*"])];

// --- the decoder -------------------------------------------------------------------

fn pattern() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(&['a', 'b', ':', '/', '?', '*'][..]),
        1..6,
    )
    .prop_map(|v| v.into_iter().collect())
}

fn any_warrant() -> impl Strategy<Value = Warrant> {
    (
        proptest::collection::vec(
            (
                proptest::collection::vec(pattern(), 1..3),
                proptest::collection::vec(pattern(), 1..3),
            ),
            1..4,
        ),
        "[ -~]{0,40}",
        0u64..u64::MAX / 2,
        1u64..1000,
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(|(grants, purpose, start, len, has_parent, depth)| {
            let owned: Vec<(Vec<&str>, Vec<&str>)> = grants
                .iter()
                .map(|(a, r)| {
                    (
                        a.iter().map(String::as_str).collect(),
                        r.iter().map(String::as_str).collect(),
                    )
                })
                .collect();
            let refs: Vec<(&[&str], &[&str])> = owned
                .iter()
                .map(|(a, r)| (a.as_slice(), r.as_slice()))
                .collect();
            let parent = has_parent.then(|| warrant("key:p", "key:q", S3, (1, 2), None, 0).id());
            Warrant::new(&WarrantSpec {
                issuer: "key:issuer",
                subject: "agent:subject",
                purpose: &purpose,
                not_before: start,
                not_after: start + len,
                grants: &refs,
                parent,
                max_depth: depth,
            })
            .unwrap()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn every_valid_warrant_round_trips(w in any_warrant()) {
        let bytes = w.canonical_bytes();
        prop_assert_eq!(Warrant::from_canonical_bytes(&bytes).unwrap(), w);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = Warrant::from_canonical_bytes(&bytes);
        let _ = SignedWarrant::from_transport(&bytes);
    }

    #[test]
    fn a_mutated_encoding_is_refused_or_is_exactly_canonical(
        w in any_warrant(), at in any::<prop::sample::Index>(), value in any::<u8>(), cut in any::<prop::sample::Index>(),
    ) {
        let mut bytes = w.canonical_bytes();
        let i = at.index(bytes.len());
        bytes[i] = value;
        if let Ok(decoded) = Warrant::from_canonical_bytes(&bytes) {
            // Accepted only if these bytes are themselves the one canonical spelling.
            prop_assert_eq!(decoded.canonical_bytes(), bytes.clone());
        }
        let truncated = &w.canonical_bytes()[..cut.index(bytes.len())];
        prop_assert!(Warrant::from_canonical_bytes(truncated).is_err());
        let mut extended = w.canonical_bytes();
        extended.push(0);
        prop_assert!(Warrant::from_canonical_bytes(&extended).is_err());
    }
}

// --- keys and signatures -------------------------------------------------------------

#[test]
fn the_library_signs_rfc8032_test_1_correctly() {
    use ed25519_dalek::{Signer as _, SigningKey};

    // RFC 8032 section 7.1, TEST 1: the empty message.
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let key = SigningKey::from_bytes(&seed.clone().try_into().unwrap());
    assert_eq!(key.verifying_key().as_bytes().as_slice(), public.as_slice());
    assert_eq!(key.sign(b"").to_bytes().as_slice(), signature.as_slice());
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn key_identifiers_have_one_spelling() {
    let id = key(1).id().clone();
    assert_eq!(id.as_str().len(), 60);
    assert_eq!(KeyId::parse(id.as_str()).unwrap(), id);
    assert!(KeyId::parse(&id.as_str().to_uppercase()).is_err());
    assert!(KeyId::parse(&id.as_str().replace("ed25519:", "ED25519:")).is_err());
    assert!(KeyId::parse("ed25519:").is_err());
}

#[test]
fn sign_verify_and_any_tampered_byte_is_rejected() {
    let alice = key(1);
    let w = warrant(alice.id().as_str(), "agent:runner", S3, (100, 200), None, 0);
    let signed = alice.sign(&w).unwrap();
    let transport = signed.to_transport();
    assert_eq!(
        SignedWarrant::from_transport(&transport).unwrap().warrant(),
        &w
    );
    for i in 0..transport.len() {
        let mut t = transport.clone();
        t[i] ^= 0x01;
        assert!(
            SignedWarrant::from_transport(&t).is_err(),
            "byte {i} flipped and still accepted"
        );
    }
}

#[test]
fn a_key_signs_only_what_it_issues_and_a_forged_issuer_fails() {
    let (alice, mallory) = (key(1), key(2));
    let alices = warrant(alice.id().as_str(), "agent:runner", S3, (100, 200), None, 0);
    assert!(matches!(
        mallory.sign(&alices),
        Err(SignatureError::WrongSigner { .. })
    ));

    // Mallory signs her own warrant, then swaps in Alice's name: the bytes change, so the
    // signature no longer verifies under either key.
    let hers = warrant(
        mallory.id().as_str(),
        "agent:runner",
        S3,
        (100, 200),
        None,
        0,
    );
    let signed = mallory.sign(&hers).unwrap().to_transport();
    let sig: [u8; 64] = signed[signed.len() - 64..].try_into().unwrap();
    assert_eq!(
        SignedWarrant::verify(&alices.canonical_bytes(), &sig),
        Err(SignatureError::BadSignature)
    );
}

// --- chains ------------------------------------------------------------------------

struct Fixture {
    root: IssuerKey,
    agent: IssuerKey,
    helper: IssuerKey,
}

fn fixture() -> Fixture {
    Fixture {
        root: key(10),
        agent: key(11),
        helper: key(12),
    }
}

fn chain(
    f: &Fixture,
    child_grants: &[(&[&str], &[&str])],
    child_issuer: &IssuerKey,
) -> Vec<SignedWarrant> {
    let root_w = warrant(
        f.root.id().as_str(),
        f.agent.id().as_str(),
        S3,
        (100, 200),
        None,
        1,
    );
    let child_w = warrant(
        child_issuer.id().as_str(),
        f.helper.id().as_str(),
        child_grants,
        (120, 180),
        Some(root_w.id()),
        0,
    );
    vec![
        f.root.sign(&root_w).unwrap(),
        child_issuer.sign(&child_w).unwrap(),
    ]
}

#[test]
fn a_valid_chain_confers_its_last_warrant() {
    let f = fixture();
    let links = chain(&f, S3_READ, &f.agent);
    let leaf = verify_chain(&links, &[f.root.id().clone()]).unwrap();
    assert_eq!(leaf.subject().as_str(), f.helper.id().as_str());
}

#[test]
fn every_rule_of_section_5_3_is_enforced() {
    let f = fixture();
    let roots = [f.root.id().clone()];
    let good = chain(&f, S3_READ, &f.agent);

    assert_eq!(verify_chain(&[], &roots), Err(ChainError::Empty));
    assert!(matches!(
        verify_chain(&good, &[key(99).id().clone()]),
        Err(ChainError::UntrustedRoot(_))
    ));
    // A delegated warrant cannot stand as a root.
    assert_eq!(
        verify_chain(&good[1..], &[f.agent.id().clone()]),
        Err(ChainError::RootHasParent)
    );
    // Links out of order break the parent link.
    let reversed = vec![good[1].clone(), good[0].clone()];
    assert!(verify_chain(&reversed, &roots).is_err());
    // A child that widens its parent.
    let wider = chain(&f, WIDER, &f.agent);
    assert!(matches!(
        verify_chain(&wider, &roots),
        Err(ChainError::Attenuation { index: 1, .. })
    ));
    // A child issued by someone other than the parent's subject.
    let usurped = chain(&f, S3_READ, &f.helper);
    assert!(matches!(
        verify_chain(&usurped, &roots),
        Err(ChainError::Attenuation { index: 1, .. })
    ));
}
