//! Emits conformance cases for `conformance/iam-simulator.py`: warrants compiled to
//! session policies, and requests chosen to probe where AWS and Remit could disagree
//! (wildcards within and across ARN segments, `?`, and resource case), each with Remit's
//! own decision. One JSON object per line on stdout. Deterministic for a given seed.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use remit_aws::compile_session_policy;
use remit_core::{Request, Warrant, WarrantSpec};
use serde_json::json;

const T0: u64 = 1_790_000_000;
const T1: u64 = 1_790_003_600;

/// Grants that exercise the interesting matching rules.
const GRANTS: &[(&str, &str)] = &[
    ("s3:GetObject", "arn:aws:s3:::reports/*"),
    ("s3:Get*", "arn:aws:s3:::reports/*/2026/*"),
    ("s3:GetObject", "arn:aws:s3:::rep?rts/a*"),
    (
        "dynamodb:Query",
        "arn:aws:dynamodb:us-east-1:*:table/orders",
    ),
    ("dynamodb:*", "arn:aws:dynamodb:*:111122223333:table/*"),
    ("sqs:SendMessage", "arn:aws:sqs:us-*:111122223333:jobs-*"),
    (
        "lambda:InvokeFunction",
        "arn:aws:lambda:us-east-1:111122223333:function:agent*",
    ),
    ("iam:*AccessKey*", "arn:aws:iam::111122223333:user/*"),
];

/// Requests near each grant: exact, case-flipped, segment-crossing, and plainly outside.
fn probes(action: &str, resource: &str) -> Vec<(String, String)> {
    let concrete = resource.replace('*', "x/y:z").replace('?', "e");
    let simple = resource.replace('*', "q").replace('?', "e");
    let get = action.replace('*', "Object");
    let mut out = vec![
        (get.clone(), simple.clone()),
        (get.clone(), concrete.clone()),
        (get.to_lowercase(), simple.clone()),
        (get.to_uppercase(), simple.clone()),
        (get.clone(), simple.to_uppercase()),
        (get.clone(), flip_case_after_colons(&simple)),
        (get.clone(), format!("{simple}:extra:segments")),
        (get.clone(), simple.replace("111122223333", "444455556666")),
        ("s3:DeleteBucket".to_owned(), simple.clone()),
        (get, "arn:aws:s3:::someone-else/key".to_owned()),
    ];
    out.dedup();
    out
}

fn flip_case_after_colons(s: &str) -> String {
    let (head, tail) = s.rsplit_once(':').unwrap_or(("", s));
    let flipped: String = tail
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    if head.is_empty() {
        flipped
    } else {
        format!("{head}:{flipped}")
    }
}

fn main() {
    for (action, resource) in GRANTS {
        let actions = [*action];
        let resources = [*resource];
        let grants: &[(&[&str], &[&str])] = &[(&actions, &resources)];
        let w = Warrant::new(&WarrantSpec {
            issuer: "key:conformance",
            subject: "agent:probe",
            purpose: "IAM simulator conformance",
            not_before: T0,
            not_after: T1,
            grants,
            parent: None,
            max_depth: 0,
        })
        .unwrap();
        let policy = compile_session_policy(&w).unwrap();
        for (a, r) in probes(action, resource) {
            for (t, label) in [(T0 + 60, "inside"), (T1 + 60, "after")] {
                let Ok(req) = Request::new("agent:probe", &a, &r, t) else {
                    continue;
                };
                println!(
                    "{}",
                    json!({"policy": policy, "action": a, "resource": r, "time": remit_aws::iso8601(t),
                           "window": label, "remit_permits": w.permits(&req)})
                );
            }
        }
    }
}
