//! SPEC section 6 against the first live session (2026-09-24): the real events reconcile
//! clean, and each way they could have gone wrong, made by editing one field of a real
//! event, is caught.
//!
//! Fixtures are real `CloudTrail` events with the account number, key ids and address
//! replaced by AWS's documentation placeholders, and the real warrant chain.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use remit_core::{KeyId, Warrant, decode_chain, verify_chain};
use remit_reconcile::{
    Event, EventSource, Input, Kind, ManagedRole, Report, Verdict, reconcile, trust_policy_problems,
};
use serde_json::{Value, json};

const ROLE: &str = "arn:aws:iam::111122223333:role/remit-agent-readonly";

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn warrant() -> Warrant {
    let path = format!(
        "{}/tests/fixtures/live-warrant.chain",
        env!("CARGO_MANIFEST_DIR")
    );
    let links = decode_chain(&std::fs::read(path).unwrap()).unwrap();
    // The chain was signed by a throwaway test root; trust it for the test.
    let root = KeyId::parse(links[0].warrant().issuer().as_str()).unwrap();
    verify_chain(&links, &[root]).unwrap().clone()
}

fn recorded() -> Vec<Value> {
    vec![
        fixture("broker-assume-role.json"),
        fixture("managed-get-bucket-location.json"),
        fixture("unmanaged-describe-stacks.json"),
    ]
}

/// The recorded events, with the session's duration as the corrected broker (which keeps
/// a 60 s margin) would have passed it, then `edit` applied.
fn events(mut edit: impl FnMut(&mut Vec<Value>)) -> Vec<Event> {
    let mut raw = recorded();
    raw[0]["requestParameters"]["durationSeconds"] = json!(3566 - 60);
    edit(&mut raw);
    raw.iter().map(|v| Event::from_json(v).unwrap()).collect()
}

fn run(events: &[Event], trust: &Value, now_offset: u64) -> Report {
    let w = warrant();
    let roles = [ManagedRole {
        arn: ROLE.to_owned(),
        trust_problems: trust_policy_problems(trust),
    }];
    let warrants = [w.clone()];
    reconcile(&Input {
        warrants: &warrants,
        roles: &roles,
        events,
        from: w.not_before(),
        to: w.not_after(),
        now: w.not_after() + now_offset,
        settle_seconds: 900,
        source: EventSource::EventHistory,
        regions: &["us-east-1".to_owned(), "us-west-2".to_owned()],
        record_problems: &[],
    })
}

fn kinds(r: &Report) -> Vec<Kind> {
    r.findings.iter().map(|f| f.kind).collect()
}

#[test]
fn the_first_live_session_outlived_its_warrant_by_one_second_and_was_caught() {
    // As recorded: the broker planned 3,566 s from its own clock; AWS logged AssumeRole a
    // second later, so the session ended one second after the warrant. The session policy's
    // time condition still bounded every action, but the invariant was broken, and this is
    // the finding that led to the broker's 60 s margin.
    let raw: Vec<Event> = recorded()
        .iter()
        .map(|v| Event::from_json(v).unwrap())
        .collect();
    let r = run(&raw, &fixture("trust-policy.json"), 3600);
    assert_eq!(kinds(&r), vec![Kind::SessionMismatch]);
    assert!(r.findings[0].detail.contains("session outlives"));
}

#[test]
fn the_live_session_with_the_margin_reconciles_clean() {
    let r = run(&events(|_| {}), &fixture("trust-policy.json"), 3600);
    assert_eq!(r.findings, vec![], "{}", r.to_json().unwrap());
    // Event history carries no integrity evidence, so the verdict says so.
    assert_eq!(r.verdict, Verdict::CompleteUnvalidated);
    let id = warrant().id().as_str().to_owned();
    assert_eq!(r.sessions_per_warrant.get(&id), Some(&1));
    assert_eq!(r.actions_per_warrant.get(&id), Some(&1));
    assert_eq!(
        r.unmanaged.get("arn:aws:iam::111122223333:user/admin"),
        Some(&1)
    );
}

#[test]
fn an_unsettled_window_is_provisional() {
    let r = run(&events(|_| {}), &fixture("trust-policy.json"), 60);
    assert_eq!(r.verdict, Verdict::Provisional);
    // The report says which settling period its verdict assumed.
    assert!(r.to_json().unwrap().contains("\"settle_seconds\": 900"));
}

#[test]
fn a_broader_policy_under_a_real_warrant_id_is_caught() {
    let r = run(
        &events(|e| {
            let p = e[0]["requestParameters"]["policy"]
                .as_str()
                .unwrap()
                .replace("s3:GetBucketLocation", "s3:*");
            e[0]["requestParameters"]["policy"] = json!(p);
        }),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::SessionMismatch]);
    assert_eq!(r.verdict, Verdict::Incomplete);
}

#[test]
fn a_session_that_outlives_its_warrant_is_caught() {
    let r = run(
        &events(|e| e[0]["requestParameters"]["durationSeconds"] = json!(7200)),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::SessionMismatch]);
}

#[test]
fn managed_actions_without_a_known_warrant_are_caught() {
    let r = run(
        &events(|e| {
            e[1]["userIdentity"]["sessionContext"]
                .as_object_mut()
                .unwrap()
                .remove("sourceIdentity");
        }),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::UnwarrantedEvent]);
    let r = run(
        &events(|e| {
            e[1]["userIdentity"]["sessionContext"]["sourceIdentity"] =
                json!("rw1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::UnwarrantedEvent]);
}

#[test]
fn an_action_outside_the_window_or_the_warrant_is_caught() {
    let r = run(
        &events(|e| e[1]["eventTime"] = json!("2026-09-25T09:00:00Z")),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::OutOfWindowEvent]);
    let r = run(
        &events(|e| e[1]["eventName"] = json!("GetBucketVersioning")),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::OutsideWarrantEvent]);
}

#[test]
fn a_refused_attempt_is_reported_but_does_not_fail_the_run() {
    let r = run(
        &events(|e| {
            e[1]["eventName"] = json!("GetBucketVersioning");
            e[1]["errorCode"] = json!("AccessDenied");
        }),
        &fixture("trust-policy.json"),
        3600,
    );
    assert_eq!(kinds(&r), vec![Kind::RefusedAttempt]);
    assert_eq!(r.verdict, Verdict::CompleteUnvalidated);
}

#[test]
fn a_trust_policy_that_admits_sessions_without_a_warrant_fails_the_run() {
    let real = fixture("trust-policy.json");
    assert!(trust_policy_problems(&real).is_empty());

    let mut no_condition = real.clone();
    no_condition["Statement"][0]
        .as_object_mut()
        .unwrap()
        .remove("Condition");
    let mut anyone = real.clone();
    anyone["Statement"][0]["Principal"] = json!({"AWS": "*"});
    let mut split = real.clone();
    split["Statement"] = json!([
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:user/admin"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:user/admin"}, "Action": "sts:SetSourceIdentity",
         "Condition": {"StringLike": {"sts:SourceIdentity": "rw1-*"}}}
    ]);
    let mut loose = real;
    loose["Statement"][0]["Condition"]["StringLike"]["sts:SourceIdentity"] = json!(["rw1-*", "*"]);

    for (name, policy) in [
        ("no condition", no_condition),
        ("anyone", anyone),
        ("split", split),
        ("loose", loose),
    ] {
        assert!(!trust_policy_problems(&policy).is_empty(), "{name} passed");
        let r = run(&events(|_| {}), &policy, 3600);
        assert!(kinds(&r).contains(&Kind::TrustPolicy), "{name}");
        assert_eq!(r.verdict, Verdict::Incomplete, "{name}");
    }
}

#[test]
fn only_a_validated_record_without_problems_is_complete() {
    static GAP: std::sync::LazyLock<[String; 1]> =
        std::sync::LazyLock::new(|| ["us-east-1: no digest covers 11:01 to 12:01".to_owned()]);
    let w = warrant();
    let roles = [ManagedRole {
        arn: ROLE.to_owned(),
        trust_problems: trust_policy_problems(&fixture("trust-policy.json")),
    }];
    let warrants = [w.clone()];
    let evs = events(|_| {});
    let regions = ["us-east-1".to_owned()];
    let input = |source, problems: &'static [String]| Input {
        warrants: &warrants,
        roles: &roles,
        events: &evs,
        from: w.not_before(),
        to: w.not_after(),
        now: w.not_after() + 7200,
        settle_seconds: 900,
        source,
        regions: &regions,
        record_problems: problems,
    };
    assert_eq!(
        reconcile(&input(EventSource::EventHistory, &[])).verdict,
        Verdict::CompleteUnvalidated
    );
    assert_eq!(
        reconcile(&input(EventSource::ValidatedTrail, &[])).verdict,
        Verdict::Complete
    );
    let r = reconcile(&input(EventSource::ValidatedTrail, &*GAP));
    assert_eq!(r.verdict, Verdict::Incomplete);
    assert_eq!(kinds(&r), vec![Kind::RecordGap]);
}
