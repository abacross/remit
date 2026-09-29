//! The one configuration fact the claim depends on, re-checked every run (SPEC section 6,
//! assumption 1): a managed role admits sessions only with a warrant-form source identity.
//!
//! The check is conservative: any statement that could let someone assume the role
//! without a `sts:SourceIdentity` condition limited to `rw1-*`, or let anyone but a broker
//! assume it at all, fails it, including shapes the check does not recognize. A failure
//! makes the run incomplete.

use remit_core::ActionPattern;
use serde_json::Value;

/// The actions that create a session on a role.
const ASSUME: [&str; 3] = [
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
];

fn as_list(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(other) => vec![other],
        None => Vec::new(),
    }
}

/// Whether a statement's actions reach any way of assuming the role, read with the same
/// wildcards IAM uses (`sts:Assume*`, `sts:Assume?ole`). An action that is not text, or
/// that Remit cannot read as a pattern, is taken to reach it.
fn grants_assume(statement: &Value) -> bool {
    as_list(statement.get("Action")).iter().any(|a| {
        a.as_str()
            .and_then(|s| ActionPattern::new(s).ok())
            .is_none_or(|p| ASSUME.iter().any(|action| p.matches(action)))
    }) || statement.get("NotAction").is_some()
}

/// The principals a statement names that are not brokers, as text.
fn non_brokers(statement: &Value, brokers: &[String]) -> Vec<String> {
    match statement.get("Principal") {
        Some(Value::Object(kinds)) => kinds
            .iter()
            .flat_map(|(kind, values)| {
                as_list(Some(values))
                    .into_iter()
                    .filter(move |v| {
                        kind != "AWS" || !v.as_str().is_some_and(|a| brokers.iter().any(|b| b == a))
                    })
                    .map(move |v| format!("{kind} {v}"))
            })
            .collect(),
        Some(other) => vec![other.to_string()],
        None => vec!["no principal".to_owned()],
    }
}

fn requires_warrant_identity(statement: &Value) -> bool {
    let Some(conditions) = statement.get("Condition").and_then(Value::as_object) else {
        return false;
    };
    conditions.iter().any(|(operator, keys)| {
        let op = operator.to_ascii_lowercase();
        (op == "stringlike" || op == "stringequals")
            && keys.as_object().is_some_and(|keys| {
                keys.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("sts:SourceIdentity")
                        && !as_list(Some(v)).is_empty()
                        && as_list(Some(v)).iter().all(|p| {
                            p.as_str()
                                .is_some_and(|p| p == "rw1-*" || p.starts_with("rw1-"))
                        })
                })
            })
    })
}

/// Checks a trust policy document against the brokers' ARNs. Returns the reasons it fails,
/// empty if it holds.
#[must_use]
pub fn trust_policy_problems(document: &Value, brokers: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    let statements = as_list(document.get("Statement"));
    if statements.is_empty() {
        problems.push("no statements".to_owned());
    }
    for (i, st) in statements.iter().enumerate() {
        let allow = st.get("Effect").and_then(Value::as_str) == Some("Allow");
        if !allow || !grants_assume(st) {
            continue;
        }
        if st.get("NotAction").is_some() || st.get("NotPrincipal").is_some() {
            problems.push(format!("statement {i} uses NotAction or NotPrincipal"));
            continue;
        }
        let others = non_brokers(st, brokers);
        if !others.is_empty() {
            problems.push(format!(
                "statement {i} lets {} assume the role, which is not a broker",
                others.join(", ")
            ));
        }
        if !requires_warrant_identity(st) {
            problems.push(format!(
                "statement {i} allows assuming the role without requiring a source identity of the form rw1-*"
            ));
        }
    }
    problems
}
