//! SPEC section 4, the attenuation theorem: if a child is accepted as an attenuation of
//! its parent, every request the child permits is permitted by the parent.
//!
//! Two kinds of child are generated. Random children test that nothing unsound is ever
//! accepted. Children derived from the parent by narrowing each pattern test that the
//! check is not so conservative that the theorem holds vacuously: every one of them must
//! be accepted, because narrowing is exactly what delegation is for.

#![allow(
    // Test code: a panic is how a test reports failure, and the helpers index into
    // fixed, known-good test data (ADR 0002 keeps these lints for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use remit_core::{Request, Warrant, WarrantSpec, check_attenuation};

const PARENT_SUBJECT: &str = "agent:parent";
const CHILD_SUBJECT: &str = "agent:child";

fn pattern() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(&['a', 'b', '?', '*'][..]), 1..5)
        .prop_map(|v| v.into_iter().collect())
}

type Grants = Vec<(Vec<String>, Vec<String>)>;

fn grants() -> impl Strategy<Value = Grants> {
    proptest::collection::vec(
        (
            proptest::collection::vec(pattern(), 1..3),
            proptest::collection::vec(pattern(), 1..3),
        ),
        1..4,
    )
}

/// Narrows a pattern: each `*` becomes empty, one literal, `?`, or stays; each `?` becomes
/// a literal or stays. Every such rewrite matches a subset of what the original matched.
fn narrow(p: &str, choices: &[u8]) -> String {
    let mut out = String::new();
    for (i, c) in p.chars().enumerate() {
        let k = choices.get(i).copied().unwrap_or(0) % 4;
        match (c, k) {
            ('*', 0) => {}
            ('*', 1) => out.push('a'),
            ('*', 2) => out.push('?'),
            ('?', 0 | 1) => out.push('b'),
            (other, _) => out.push(other),
        }
    }
    if out.is_empty() { p.to_owned() } else { out }
}

fn build(
    issuer: &str,
    subject: &str,
    g: &Grants,
    window: (u64, u64),
    parent: Option<remit_core::WarrantId>,
    depth: u64,
) -> Option<Warrant> {
    let owned: Vec<(Vec<&str>, Vec<&str>)> = g
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
    Warrant::new(&WarrantSpec {
        issuer,
        subject,
        purpose: "property test",
        not_before: window.0,
        not_after: window.1,
        grants: &refs,
        parent,
        max_depth: depth,
    })
    .ok()
}

fn names() -> Vec<String> {
    let mut out = Vec::new();
    for len in 1..=4 {
        for bits in 0..(1u32 << len) {
            out.push(
                (0..len)
                    .map(|i| if bits >> i & 1 == 1 { 'a' } else { 'b' })
                    .collect(),
            );
        }
    }
    out
}

fn assert_theorem(parent: &Warrant, child: &Warrant) -> Result<(), TestCaseError> {
    let names = names();
    for t in [
        child.not_before(),
        u64::midpoint(child.not_before(), child.not_after()),
        child.not_after(),
    ] {
        for action in &names {
            for resource in &names {
                let as_child = Request::new(CHILD_SUBJECT, action, resource, t).unwrap();
                if child.permits(&as_child) {
                    let as_parent = Request::new(PARENT_SUBJECT, action, resource, t).unwrap();
                    prop_assert!(
                        parent.permits(&as_parent),
                        "THEOREM BROKEN: child permits ({}, {}, {}) and the parent does not",
                        action,
                        resource,
                        t
                    );
                }
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    #[test]
    fn random_children_never_exceed_their_parent(
        pg in grants(), cg in grants(),
        pw in (0u64..100, 100u64..200), cw in (0u64..150, 50u64..250),
        pdepth in 0u64..3, cdepth in 0u64..3,
    ) {
        let parent = build("key:root", PARENT_SUBJECT, &pg, pw, None, pdepth).unwrap();
        if cw.0 >= cw.1 { return Ok(()); }
        let child = build(PARENT_SUBJECT, CHILD_SUBJECT, &cg, cw, Some(parent.id()), cdepth).unwrap();
        if check_attenuation(&parent, &child).is_ok() {
            assert_theorem(&parent, &child)?;
        }
    }

    #[test]
    fn narrowed_children_are_accepted_and_obey_the_theorem(
        pg in grants(),
        choices in proptest::collection::vec(any::<u8>(), 64),
        pw in (0u64..100, 100u64..200),
        trim in (0u64..10, 0u64..10),
    ) {
        let parent = build("key:root", PARENT_SUBJECT, &pg, pw, None, 2).unwrap();
        let cg: Grants = pg.iter().map(|(a, r)| (
            a.iter().map(|p| narrow(p, &choices)).collect(),
            r.iter().map(|p| narrow(p, &choices[8..])).collect(),
        )).collect();
        let cw = (pw.0 + trim.0, pw.1 - trim.1);
        // Trimming both ends of a narrow window can empty it, which Warrant::new rightly refuses.
        prop_assume!(cw.0 < cw.1);
        let child = build(PARENT_SUBJECT, CHILD_SUBJECT, &cg, cw, Some(parent.id()), 1).unwrap();
        prop_assert_eq!(check_attenuation(&parent, &child), Ok(()));
        assert_theorem(&parent, &child)?;
    }
}

#[test]
fn each_rule_is_enforced() {
    let g: Grants = vec![(vec!["s3:*".into()], vec!["arn:aws:s3:::b/*".into()])];
    let parent = build("key:root", PARENT_SUBJECT, &g, (100, 200), None, 1).unwrap();
    let ok = |c: Option<Warrant>| check_attenuation(&parent, &c.unwrap());

    // Rule 1: a child may not keep the parent's depth.
    assert!(
        ok(build(
            PARENT_SUBJECT,
            CHILD_SUBJECT,
            &g,
            (100, 200),
            Some(parent.id()),
            1
        ))
        .is_err()
    );
    // Rule 2: nor outlive it.
    assert!(
        ok(build(
            PARENT_SUBJECT,
            CHILD_SUBJECT,
            &g,
            (100, 201),
            Some(parent.id()),
            0
        ))
        .is_err()
    );
    // Rule 3: nor widen a grant.
    let wider: Grants = vec![(vec!["s3:*".into()], vec!["arn:aws:s3:::*".into()])];
    assert!(
        ok(build(
            PARENT_SUBJECT,
            CHILD_SUBJECT,
            &wider,
            (100, 200),
            Some(parent.id()),
            0
        ))
        .is_err()
    );
    // Rule 4: only the parent's subject may delegate.
    assert!(
        ok(build(
            "agent:someone-else",
            CHILD_SUBJECT,
            &g,
            (100, 200),
            Some(parent.id()),
            0
        ))
        .is_err()
    );
    // And the child must name this parent.
    assert!(
        ok(build(
            PARENT_SUBJECT,
            CHILD_SUBJECT,
            &g,
            (100, 200),
            None,
            0
        ))
        .is_err()
    );
    // A child that follows every rule is accepted.
    assert!(
        ok(build(
            PARENT_SUBJECT,
            CHILD_SUBJECT,
            &g,
            (120, 180),
            Some(parent.id()),
            0
        ))
        .is_ok()
    );
}
