//! SPEC section 8.2 and 8.3: the compiled session policy is the warrant's grants, verbatim,
//! narrowed to its window, and nothing else; anything AWS would read differently is refused.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use remit_aws::{CompileError, MAX_POLICY_CHARS, compile_session_policy, iso8601, parse_iso8601};
use remit_core::{Warrant, WarrantSpec};
use serde_json::{Value, json};

#[test]
fn iso8601_matches_python() {
    // Computed with Python's datetime.fromtimestamp(s, timezone.utc), 2026-09-24.
    for (s, expected) in [
        (0, "1970-01-01T00:00:00Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (1_790_000_000, "2026-09-21T14:13:20Z"),
        (1_790_003_600, "2026-09-21T15:13:20Z"),
        (4_102_444_799, "2099-12-31T23:59:59Z"),
        (253_402_300_799, "9999-12-31T23:59:59Z"),
    ] {
        assert_eq!(iso8601(s), expected, "{s}");
    }
}

/// A slow, obviously correct reference: count days from 1970 one year and month at a time.
fn naive(seconds: u64) -> String {
    let leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let mut days = seconds / 86_400;
    let rem = seconds % 86_400;
    let mut year = 1970;
    while days >= if leap(year) { 366 } else { 365 } {
        days -= if leap(year) { 366 } else { 365 };
        year += 1;
    }
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= lengths[month] {
        days -= lengths[month];
        month += 1;
    }
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        days + 1,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

proptest! {
    #[test]
    fn iso8601_agrees_with_day_counting(s in 0u64..7_258_118_400) { // up to year 2200
        prop_assert_eq!(iso8601(s), naive(s));
    }
}

fn warrant(
    grants: &[(&[&str], &[&str])],
    window: (u64, u64),
) -> Result<Warrant, remit_core::WarrantError> {
    Warrant::new(&WarrantSpec {
        issuer: "key:alice",
        subject: "agent:runner",
        purpose: "compile tests",
        not_before: window.0,
        not_after: window.1,
        grants,
        parent: None,
        max_depth: 0,
    })
}

fn action() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_owned()),
        ("[a-z0-9-]{1,8}", "[A-Za-z*?\"\\\\]{1,10}").prop_map(|(s, n)| format!("{s}:{n}")),
    ]
}

fn resource() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_owned()),
        (
            "[a-z0-9]{1,6}",
            "[a-z0-9*?-]{0,6}",
            "[0-9*]{0,6}",
            "[a-z0-9/:*?\"\\\\.-]{0,16}"
        )
            .prop_map(|(svc, region, account, rest)| format!(
                "arn:aws:{svc}:{region}:{account}:{rest}"
            )),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// SPEC 8.3, part 1: parsing the compiled policy gives back exactly the warrant.
    #[test]
    fn the_policy_is_the_warrant_verbatim_and_nothing_else(
        grants in proptest::collection::vec(
            (proptest::collection::vec(action(), 1..3), proptest::collection::vec(resource(), 1..3)), 1..4),
        start in 0u64..4_000_000_000, len in 1u64..1_000_000,
    ) {
        let owned: Vec<(Vec<&str>, Vec<&str>)> = grants.iter()
            .map(|(a, r)| (a.iter().map(String::as_str).collect(), r.iter().map(String::as_str).collect()))
            .collect();
        let refs: Vec<(&[&str], &[&str])> = owned.iter().map(|(a, r)| (a.as_slice(), r.as_slice())).collect();
        let w = warrant(&refs, (start, start + len)).unwrap();
        let policy = match compile_session_policy(&w) {
            Ok(p) => p,
            Err(CompileError::TooLong(n)) => { prop_assert!(n > MAX_POLICY_CHARS); return Ok(()); }
            Err(e) => return Err(TestCaseError::fail(format!("valid-shape warrant refused: {e}"))),
        };
        prop_assert!(policy.len() <= MAX_POLICY_CHARS);
        let v: Value = serde_json::from_str(&policy).unwrap();
        let window = json!({
            "DateGreaterThanEquals": {"aws:CurrentTime": iso8601(start)},
            "DateLessThanEquals": {"aws:CurrentTime": iso8601(start + len)},
        });
        let expected: Vec<Value> = grants.iter().map(|(a, r)| json!({
            "Effect": "Allow", "Action": a, "Resource": r, "Condition": window,
        })).collect();
        prop_assert_eq!(v, json!({"Version": "2012-10-17", "Statement": expected}));
    }
}

#[test]
fn everything_aws_would_read_differently_is_refused() {
    let refused =
        |a: &str, r: &str| compile_session_policy(&warrant(&[(&[a], &[r])], (1, 2)).unwrap());
    // Policy variables, in either list.
    assert!(matches!(
        refused("s3:GetObject", "arn:aws:s3:::b/${aws:username}/*"),
        Err(CompileError::PolicyVariable(_))
    ));
    assert!(matches!(
        refused("s3:${x}", "*"),
        Err(CompileError::PolicyVariable(_))
    ));
    // A wildcard in the service segment of an ARN, or in the action's service prefix.
    assert!(matches!(
        refused("s3:GetObject", "arn:aws:s*:::b"),
        Err(CompileError::ResourceShape(_))
    ));
    assert!(matches!(
        refused("s*:GetObject", "*"),
        Err(CompileError::ActionShape(_))
    ));
    // Something that is not an ARN, and an action with no name.
    assert!(matches!(
        refused("s3:GetObject", "reports/*"),
        Err(CompileError::ResourceShape(_))
    ));
    assert!(matches!(
        refused("s3:", "*"),
        Err(CompileError::ActionShape(_))
    ));
    // Over the limit is a refusal, never a shorter, different policy.
    // Three valid 800-byte patterns: each within a pattern's limit, together over AWS's.
    let long = format!("arn:aws:s3:::{}", "x".repeat(787));
    let many = warrant(
        &[(
            &["s3:GetObject"],
            &[long.as_str(), long.as_str(), long.as_str()],
        )],
        (1, 2),
    )
    .unwrap();
    assert!(
        matches!(compile_session_policy(&many), Err(CompileError::TooLong(n)) if n > MAX_POLICY_CHARS)
    );
}

#[test]
fn a_typical_warrant_compiles_to_the_expected_policy() {
    let w = warrant(
        &[(&["s3:GetObject"], &["arn:aws:s3:::reports/*"])],
        (1_790_000_000, 1_790_003_600),
    )
    .unwrap();
    assert_eq!(
        compile_session_policy(&w).unwrap(),
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"],"Condition":{"DateGreaterThanEquals":{"aws:CurrentTime":"2026-09-21T14:13:20Z"},"DateLessThanEquals":{"aws:CurrentTime":"2026-09-21T15:13:20Z"}}}]}"#
    );
}

proptest! {
    #[test]
    fn parsing_undoes_formatting(s in 0u64..253_402_300_799) {
        prop_assert_eq!(parse_iso8601(&iso8601(s)), Some(s));
    }
}

#[test]
fn parsing_refuses_anything_else() {
    for bad in [
        "2026-02-30T00:00:00Z",
        "2026-09-24T20:03:40.123Z",
        "2026-09-24T20:03:40+00:00",
        "2026-9-24T20:03:40Z",
        "1969-12-31T23:59:59Z",
        "2026-09-24 20:03:40Z",
        "",
    ] {
        assert_eq!(parse_iso8601(bad), None, "{bad}");
    }
    assert_eq!(parse_iso8601("2026-09-24T20:03:40Z"), Some(1_790_280_220));
}
