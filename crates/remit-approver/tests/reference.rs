//! Risk bands from AWS's own service reference: they follow AWS's flags, text cannot move
//! them, and the reads AWS does not flag as sensitive are caught by the hard rules first.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use remit_approver::reference::{Referenced, ServiceReference};
use remit_approver::{Assessment, Band, Config, Decider, Outcome, Request, decide};
use remit_core::{IssuerKey, Warrant, WarrantSpec};

const NOW: u64 = 1_790_300_000;

fn reference() -> ServiceReference {
    let mut r = ServiceReference::new();
    for s in ["s3", "sts", "secretsmanager"] {
        let path = format!(
            "{}/tests/fixtures/service-reference/{s}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        assert!(
            r.add_service(&std::fs::read_to_string(path).unwrap())
                .unwrap()
                > 0
        );
    }
    r
}

fn approver() -> IssuerKey {
    IssuerKey::from_seed(&[2; 32])
}

/// A wide bound, so that only bands, rules and thresholds decide.
fn bound() -> Warrant {
    Warrant::new(&WarrantSpec {
        issuer: IssuerKey::from_seed(&[1; 32]).id().as_str(),
        subject: approver().id().as_str(),
        purpose: "wide bound",
        not_before: NOW - 60,
        not_after: NOW + 86_400,
        grants: &[(&["*"], &["*"])],
        parent: None,
        max_depth: 1,
    })
    .unwrap()
}

fn request(action: &str, context: &str) -> Request {
    Request {
        agent: IssuerKey::from_seed(&[3; 32]).id().as_str().to_owned(),
        action: action.into(),
        resource: "arn:aws:s3:::example-bucket".into(),
        seconds: 900,
        purpose: "demo".into(),
        context: context.into(),
    }
}

#[test]
fn every_action_in_the_fixtures_carries_its_flags() {
    let r = reference();
    assert!(r.len() > 180, "{}", r.len());
}

#[test]
fn bands_follow_awss_flags_whatever_the_case() {
    let r = reference();
    for (action, band) in [
        ("s3:GetObject", Band::ReadOnly),
        ("s3:GetBucketLocation", Band::ReadOnly),
        ("s3:ListBucket", Band::ReadOnly),
        ("S3:getobject", Band::ReadOnly),
        ("s3:PutObject", Band::ReversibleChange),
        ("s3:PutObjectTagging", Band::ReversibleChange),
        ("s3:DeleteBucket", Band::Destructive),
        ("s3:PutBucketPolicy", Band::SensitiveOrExternal),
        ("sts:AssumeRole", Band::ReversibleChange),
        ("secretsmanager:GetSecretValue", Band::ReadOnly),
    ] {
        assert_eq!(r.band(action), Some(band), "{action}");
    }
    assert_eq!(r.band("s3:NoSuchAction"), None);
    assert_eq!(r.band("ec2:DescribeInstances"), None, "not loaded");
}

fn run(req: &Request, d: &mut dyn Decider) -> Outcome {
    decide(&bound(), &approver(), &Config::default(), req, d, NOW).0
}

#[test]
fn reads_are_approved_and_writes_go_to_a_person_without_any_model() {
    let r = reference();
    let mut d = Referenced::new(&r, None);
    let Outcome::Issued(w) = run(&request("s3:GetBucketLocation", ""), &mut d) else {
        panic!()
    };
    assert!(w.warrant().purpose().starts_with(
        "remit-approval/v1 decider=aws-reference model=aws-service-reference band=read_only p=1.0000"
    ));
    for action in ["s3:PutObject", "s3:PutObjectTagging"] {
        assert!(
            matches!(run(&request(action, ""), &mut d), Outcome::Escalated(_)),
            "{action}"
        );
    }
    // Not in the loaded reference: nobody knows what it does, so a person decides.
    assert!(matches!(
        run(&request("ec2:DescribeInstances", ""), &mut d),
        Outcome::Escalated(_)
    ));
}

#[test]
fn secret_reads_go_to_a_person_although_aws_calls_them_reads() {
    let r = reference();
    let mut d = Referenced::new(&r, None);
    for action in [
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParametersByPath",
    ] {
        let outcome = run(&request(action, ""), &mut d);
        assert!(
            matches!(&outcome, Outcome::Escalated(why) if why.contains("hard rule")),
            "{action}: {outcome}"
        );
    }
}

/// A model that says whatever it is told to.
struct Says(Band, f64);
impl Decider for Says {
    fn name(&self) -> &'static str {
        "model"
    }
    fn assess(&mut self, _: &str) -> Result<Assessment, String> {
        Ok(Assessment {
            band: self.0,
            p_safe: self.1,
            model: "m-1".into(),
        })
    }
}

#[test]
fn a_models_band_is_overruled_and_only_its_probability_counts() {
    let r = reference();
    // The model calls a write a read: AWS says it is a change, so a person decides.
    let mut liar = Says(Band::ReadOnly, 1.0);
    let mut d = Referenced::new(&r, Some(&mut liar));
    assert!(matches!(
        run(&request("s3:PutObject", ""), &mut d),
        Outcome::Escalated(_)
    ));
    // The model's doubt about a read still sends it to a person.
    let mut doubtful = Says(Band::Destructive, 0.3);
    let mut d = Referenced::new(&r, Some(&mut doubtful));
    assert!(matches!(
        run(&request("s3:GetObject", ""), &mut d),
        Outcome::Escalated(_)
    ));
    // And its confidence in a read approves it, recording both sources.
    let mut sure = Says(Band::Destructive, 0.95);
    let mut d = Referenced::new(&r, Some(&mut sure));
    let Outcome::Issued(w) = run(&request("s3:GetObject", ""), &mut d) else {
        panic!()
    };
    assert!(w.warrant().purpose().contains(
        "decider=aws-reference+model model=aws-service-reference+m-1 band=read_only p=0.9500"
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Without a model, nothing an agent writes in the context changes the outcome.
    #[test]
    fn context_cannot_move_the_reference(context in ".{0,200}") {
        let r = reference();
        for action in ["s3:GetObject", "s3:PutObject", "s3:DeleteBucket", "s3:PutBucketPolicy"] {
            let mut d = Referenced::new(&r, None);
            let plain = run(&request(action, ""), &mut d);
            let mut d = Referenced::new(&r, None);
            let injected = run(&request(action, &context), &mut d);
            prop_assert_eq!(std::mem::discriminant(&plain), std::mem::discriminant(&injected), "{}", action);
        }
    }
}
