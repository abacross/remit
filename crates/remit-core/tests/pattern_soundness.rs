//! SPEC section 3.3 and section 4: matching is exact, and containment is sound.
//!
//! Both are checked against brute force over a small alphabet: exhaustively for every
//! pattern up to three symbols, and by property testing for longer ones. A containment
//! answer of `true` that brute force contradicts is a security defect (SPEC section 4).

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
use remit_core::{ActionPattern, ResourcePattern};

/// Every string over `alphabet` of length 0 to `max`.
fn all_strings(alphabet: &[char], max: usize) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..max {
        let mut next = Vec::new();
        for s in &frontier {
            for &c in alphabet {
                let mut t = s.clone();
                t.push(c);
                next.push(t);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

/// The reference matcher: obviously correct, exponential, only for tests.
fn reference(pattern: &[u8], name: &[u8], fold: bool) -> bool {
    let eq = |a: u8, b: u8| {
        if fold {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    match (pattern.first(), name.first()) {
        // An exhausted pattern matches only an exhausted name.
        (None, n) => n.is_none(),
        (Some(b'*'), _) => {
            reference(&pattern[1..], name, fold)
                || (!name.is_empty() && reference(pattern, &name[1..], fold))
        }
        // A non-star needs a character; the name has run out.
        (Some(_), None) => false,
        (Some(b'?'), Some(_)) => reference(&pattern[1..], &name[1..], fold),
        (Some(&p), Some(&n)) => eq(p, n) && reference(&pattern[1..], &name[1..], fold),
    }
}

const NAMES_MAX: usize = 7;

#[test]
fn exhaustive_short_patterns_match_and_contain_soundly() {
    let patterns: Vec<String> = all_strings(&['a', 'b', '?', '*'], 3)
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect();
    let names = all_strings(&['a', 'b'], NAMES_MAX);
    let parsed: Vec<ResourcePattern> = patterns
        .iter()
        .map(|p| ResourcePattern::new(p).expect("valid"))
        .collect();

    for (p, text) in parsed.iter().zip(&patterns) {
        for n in &names {
            assert_eq!(
                p.matches(n),
                reference(text.as_bytes(), n.as_bytes(), false),
                "match {text:?} against {n:?}"
            );
        }
    }

    let mut contained = 0usize;
    for outer in &parsed {
        for inner in &parsed {
            if outer.contains(inner) {
                contained += 1;
                for n in &names {
                    assert!(
                        !inner.matches(n) || outer.matches(n),
                        "UNSOUND: {outer} claims to contain {inner}, but {n:?} matches only the inner"
                    );
                }
            }
        }
    }
    // The test is only meaningful if containment is often true: guard against a checker
    // that is sound because it always says no.
    assert!(
        contained > patterns.len() * 3,
        "only {contained} containments; checker too weak"
    );
}

#[test]
fn containment_is_reflexive_for_every_short_pattern() {
    for text in all_strings(&['a', 'b', '?', '*'], 4)
        .into_iter()
        .filter(|p| !p.is_empty())
    {
        let p = ResourcePattern::new(&text).expect("valid");
        assert!(p.contains(&p), "{text} does not contain itself");
    }
}

fn pattern_text(alphabet: &'static [char]) -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(alphabet), 1..8)
        .prop_map(|v| v.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn longer_patterns_contain_soundly(
        outer in pattern_text(&['a', 'b', '?', '*']),
        inner in pattern_text(&['a', 'b', '?', '*']),
    ) {
        let (o, i) = (ResourcePattern::new(&outer).unwrap(), ResourcePattern::new(&inner).unwrap());
        if o.contains(&i) {
            for n in all_strings(&['a', 'b'], NAMES_MAX) {
                prop_assert!(!i.matches(&n) || o.matches(&n),
                    "UNSOUND: {} contains {} but {:?} matches only the inner", outer, inner, n);
            }
        }
    }

    #[test]
    fn action_patterns_ignore_case_soundly(
        outer in pattern_text(&['a', 'A', 'b', '?', '*']),
        inner in pattern_text(&['a', 'A', 'b', '?', '*']),
    ) {
        let (o, i) = (ActionPattern::new(&outer).unwrap(), ActionPattern::new(&inner).unwrap());
        for n in all_strings(&['a', 'A', 'b'], 4) {
            prop_assert_eq!(o.matches(&n), reference(outer.as_bytes(), n.as_bytes(), true));
        }
        if o.contains(&i) {
            for n in all_strings(&['a', 'A', 'b'], 5) {
                prop_assert!(!i.matches(&n) || o.matches(&n),
                    "UNSOUND: {} contains {} but {:?} matches only the inner", outer, inner, n);
            }
        }
    }
}
