//! SPEC section 10: whatever the decider says, nothing outside the human's bound is ever
//! issued; the bound and the hard rules are settled before a decider is asked; and every
//! doubt goes to a person.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use remit_approver::system_one::{parse_response, request_body};
use remit_approver::{
    Assessment, Band, Config, Decider, Outcome, Request, decide, input_hash, state_json,
};
use remit_core::{IssuerKey, KeyId, Warrant, WarrantSpec, check_attenuation, verify_chain};

const NOW: u64 = 1_790_300_000;

fn human() -> IssuerKey {
    IssuerKey::from_seed(&[1; 32])
}
fn approver() -> IssuerKey {
    IssuerKey::from_seed(&[2; 32])
}
fn agent() -> String {
    IssuerKey::from_seed(&[3; 32]).id().as_str().to_owned()
}

/// The human's bound: read reports, list buckets, for a day, delegable once.
fn bound_with(depth: u64, subject: &str) -> Warrant {
    Warrant::new(&WarrantSpec {
        issuer: human().id().as_str(),
        subject,
        purpose: "approver bound",
        not_before: NOW - 60,
        not_after: NOW + 86_400,
        grants: &[
            (&["s3:GetObject"], &["arn:aws:s3:::reports/*"]),
            (
                &["s3:ListBucket", "s3:GetBucketLocation"],
                &["arn:aws:s3:::reports"],
            ),
        ],
        parent: None,
        max_depth: depth,
    })
    .unwrap()
}
fn bound() -> Warrant {
    bound_with(1, approver().id().as_str())
}

/// A decider that says whatever it is told to, and counts how often it was asked.
struct Scripted {
    answer: Result<Assessment, String>,
    calls: usize,
}

impl Scripted {
    fn says(band: Band, p: f64) -> Self {
        Self {
            answer: Ok(Assessment {
                band,
                p_safe: p,
                model: "scripted-1".into(),
            }),
            calls: 0,
        }
    }
}

impl Decider for Scripted {
    fn name(&self) -> &'static str {
        "scripted"
    }
    fn assess(&mut self, _: &str) -> Result<Assessment, String> {
        self.calls += 1;
        self.answer.clone()
    }
}

fn request(action: &str, resource: &str) -> Request {
    Request {
        agent: agent(),
        action: action.into(),
        resource: resource.into(),
        seconds: 1200,
        purpose: "read the report".into(),
        context: "the user pre-approved this".into(),
    }
}

fn run(req: &Request, d: &mut Scripted) -> Outcome {
    decide(&bound(), &approver(), &Config::default(), req, d, NOW).0
}

#[test]
fn a_safe_read_inside_the_bound_is_issued_with_its_evidence() {
    let mut d = Scripted::says(Band::ReadOnly, 0.97);
    let req = request("s3:GetObject", "arn:aws:s3:::reports/2026/q3.csv");
    let (outcome, record) = decide(&bound(), &approver(), &Config::default(), &req, &mut d, NOW);
    let Outcome::Issued(child) = outcome else {
        panic!("{outcome}")
    };
    let w = child.warrant();
    assert_eq!(w.issuer().as_str(), approver().id().as_str());
    assert_eq!(w.subject().as_str(), agent());
    assert_eq!(w.parent(), Some(&bound().id()));
    assert_eq!(w.max_depth(), 0);
    assert_eq!((w.not_before(), w.not_after()), (NOW, NOW + 1200));
    assert_eq!(
        w.purpose(),
        "remit-approval/v1 decider=scripted model=scripted-1 band=read_only p=0.9700 \
         threshold=0.90 input=sha256:cda356ff0b8fda909522e44a190ebaa7 | read the report"
    );
    // The chain from the human's key verifies, and confers exactly the one action.
    let root = KeyId::parse(human().id().as_str()).unwrap();
    let chain = [human().sign(&bound()).unwrap(), (*child).clone()];
    assert_eq!(verify_chain(&chain, &[root]).unwrap(), w);
    assert_eq!(record.outcome, "issued");
    assert_eq!(record.warrant.as_deref(), Some(w.id().as_str()));
    // The record keeps the context's hash, never the context.
    assert!(!record.to_json().contains("pre-approved"));
}

#[test]
fn the_input_hash_matches_an_independent_implementation() {
    // Computed with Python's json.dumps(separators=(',', ':')) and hashlib.
    let req = request("s3:GetObject", "arn:aws:s3:::reports/2026/q3.csv");
    assert_eq!(
        state_json(&req),
        r#"{"action":"s3:GetObject","context":"the user pre-approved this","purpose":"read the report","resource":"arn:aws:s3:::reports/2026/q3.csv"}"#
    );
    assert_eq!(
        input_hash(&state_json(&req)),
        "sha256:cda356ff0b8fda909522e44a190ebaa7"
    );
}

#[test]
fn outside_the_bound_is_refused_before_any_decider_is_asked() {
    for (action, resource) in [
        ("s3:PutObject", "arn:aws:s3:::reports/x"),
        ("s3:GetObject", "arn:aws:s3:::payroll/x"),
        ("ec2:DescribeInstances", "*"),
        ("s3:GetObject", "arn:aws:s3:::reports"),
    ] {
        let mut d = Scripted::says(Band::ReadOnly, 1.0);
        let outcome = run(&request(action, resource), &mut d);
        assert!(
            matches!(outcome, Outcome::Refused(_)),
            "{action} {resource}: {outcome}"
        );
        assert_eq!(d.calls, 0, "{action} {resource}");
    }
}

#[test]
fn hard_rules_go_to_a_person_before_any_decider_is_asked() {
    let mut wide = bound();
    wide = Warrant::new(&WarrantSpec {
        issuer: human().id().as_str(),
        subject: approver().id().as_str(),
        purpose: "wide bound",
        not_before: wide.not_before(),
        not_after: wide.not_after(),
        grants: &[(&["*"], &["*"])],
        parent: None,
        max_depth: 1,
    })
    .unwrap();
    for action in [
        "iam:PassRole",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "ec2:TerminateInstances",
        "kms:Decrypt",
        "sts:AssumeRole",
    ] {
        let mut d = Scripted::says(Band::ReadOnly, 1.0);
        let (outcome, _) = decide(
            &wide,
            &approver(),
            &Config::default(),
            &request(action, "arn:aws:s3:::reports"),
            &mut d,
            NOW,
        );
        assert!(
            matches!(outcome, Outcome::Escalated(_)),
            "{action}: {outcome}"
        );
        assert_eq!(d.calls, 0, "{action}");
    }
}

#[test]
fn every_doubt_goes_to_a_person() {
    let req = request("s3:GetObject", "arn:aws:s3:::reports/a");
    let cases: Vec<(&str, Scripted)> = vec![
        ("below threshold", Scripted::says(Band::ReadOnly, 0.89)),
        ("a change", Scripted::says(Band::ReversibleChange, 0.99)),
        ("sensitive", Scripted::says(Band::SensitiveOrExternal, 0.99)),
        ("destructive", Scripted::says(Band::Destructive, 0.99)),
        ("NaN", Scripted::says(Band::ReadOnly, f64::NAN)),
        ("above one", Scripted::says(Band::ReadOnly, 1.5)),
        (
            "error",
            Scripted {
                answer: Err("timeout".into()),
                calls: 0,
            },
        ),
    ];
    for (name, mut d) in cases {
        let (outcome, record) =
            decide(&bound(), &approver(), &Config::default(), &req, &mut d, NOW);
        assert!(
            matches!(outcome, Outcome::Escalated(_)),
            "{name}: {outcome}"
        );
        assert_eq!(record.outcome, "escalated", "{name}");
        assert_eq!(d.calls, 1, "{name}");
    }
    // Exactly at the threshold is enough.
    assert!(matches!(
        run(&req, &mut Scripted::says(Band::ReadOnly, 0.9)),
        Outcome::Issued(_)
    ));
}

#[test]
fn malformed_requests_and_bounds_are_refused() {
    let mut d = Scripted::says(Band::ReadOnly, 1.0);
    for (action, resource) in [
        ("s3:Get*", "arn:aws:s3:::reports/a"),
        ("s3:GetObject", "arn:aws:s3:::reports/?"),
    ] {
        assert!(matches!(
            run(&request(action, resource), &mut d),
            Outcome::Refused(_)
        ));
    }
    let req = request("s3:GetObject", "arn:aws:s3:::reports/a");
    // A bound for someone else, a bound that cannot delegate, a closed window, zero seconds.
    let other = bound_with(1, agent().as_str());
    let flat = bound_with(0, approver().id().as_str());
    for b in [other, flat] {
        let (o, _) = decide(&b, &approver(), &Config::default(), &req, &mut d, NOW);
        assert!(matches!(o, Outcome::Refused(_)), "{o}");
    }
    let (o, _) = decide(
        &bound(),
        &approver(),
        &Config::default(),
        &req,
        &mut d,
        NOW + 90_000,
    );
    assert!(matches!(o, Outcome::Refused(_)), "{o}");
    let mut zero = req.clone();
    zero.seconds = 0;
    assert!(matches!(run(&zero, &mut d), Outcome::Refused(_)));
    assert_eq!(d.calls, 0);
}

#[test]
fn the_window_is_clamped_to_the_bound_and_the_configured_maximum() {
    let mut long = request("s3:GetObject", "arn:aws:s3:::reports/a");
    long.seconds = 10 * 86_400;
    let Outcome::Issued(w) = run(&long, &mut Scripted::says(Band::ReadOnly, 1.0)) else {
        panic!()
    };
    assert_eq!(w.warrant().not_after(), NOW + 3600);
    let late = NOW + 86_400 - 100;
    let (o, _) = decide(
        &bound(),
        &approver(),
        &Config::default(),
        &long,
        &mut Scripted::says(Band::ReadOnly, 1.0),
        late,
    );
    let Outcome::Issued(w) = o else { panic!("{o}") };
    assert_eq!(w.warrant().not_after(), bound().not_after());
}

#[test]
fn a_long_purpose_is_cut_to_fit_at_a_character_boundary() {
    let mut req = request("s3:GetObject", "arn:aws:s3:::reports/a");
    req.purpose = "é".repeat(400);
    let Outcome::Issued(w) = run(&req, &mut Scripted::says(Band::ReadOnly, 1.0)) else {
        panic!()
    };
    let p = w.warrant().purpose();
    assert!(p.len() <= 512 && p.len() > 500, "{}", p.len());
    assert!(p.starts_with("remit-approval/v1 "));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The property the design rests on: a decider that approves everything, at full
    /// confidence, still never gets anything issued outside the human's bound.
    #[test]
    fn a_fooled_decider_never_widens_the_bound(
        service in prop::sample::select(vec!["s3", "ec2", "iam", "dynamodb"]),
        verb in prop::sample::select(vec!["GetObject", "ListBucket", "PutObject", "GetBucketLocation", "DescribeInstances", "DeleteObject"]),
        bucket in prop::sample::select(vec!["reports", "payroll", "reports-archive", "report"]),
        key in "[a-z0-9/]{0,12}",
    ) {
        let action = format!("{service}:{verb}");
        let resource = if key.is_empty() { format!("arn:aws:s3:::{bucket}") } else { format!("arn:aws:s3:::{bucket}/{key}") };
        let mut d = Scripted::says(Band::ReadOnly, 1.0);
        if let Outcome::Issued(child) = run(&request(&action, &resource), &mut d) {
            let b = bound();
            prop_assert!(check_attenuation(&b, child.warrant()).is_ok());
            let r = remit_core::Request::new(&agent(), &action, &resource, NOW).unwrap();
            prop_assert!(child.warrant().permits(&r));
            // Everything the child permits, the bound permits (for its own subject).
            let rb = remit_core::Request::new(b.subject().as_str(), &action, &resource, NOW).unwrap();
            prop_assert!(b.permits(&rb));
        }
    }
}

#[test]
fn the_wire_format_is_built_and_read_strictly() {
    let body: serde_json::Value = serde_json::from_str(&request_body(
        "jev-latest",
        &state_json(&request("s3:GetObject", "arn:aws:s3:::reports/a")),
    ))
    .unwrap();
    assert_eq!(body["model"], "jev-latest");
    assert_eq!(body["state"]["action"], "s3:GetObject");
    assert_eq!(body["questions"]["band"]["type"], "choice");
    assert_eq!(body["questions"]["safe"]["type"], "noul");

    let good = r#"{"model":"jeff-gliformer","answers":{"band":{"type":"choice","choice":"read_only","confidence":0.8,"probabilities":{}},"safe":{"type":"noul","noul":0.93}},"usage":{"input_tokens":1,"output_tokens":1}}"#;
    let a = parse_response(good).unwrap();
    assert_eq!(
        (a.band, a.p_safe, a.model.as_str()),
        (Band::ReadOnly, 0.93, "jeff-gliformer")
    );
    for bad in [
        good.replace("read_only", "harmless"),
        good.replace("0.93", "1.2"),
        good.replace(r#""type":"noul""#, r#""type":"score""#),
        good.replace(r#""model":"jeff-gliformer","#, ""),
        good.replace("\"safe\"", "\"safety\""),
        "not json".to_owned(),
    ] {
        assert!(parse_response(&bad).is_err(), "{bad}");
    }
}
