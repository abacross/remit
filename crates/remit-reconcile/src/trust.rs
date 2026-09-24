//! The one configuration fact the claim depends on, re-checked every run (SPEC section 6,
//! assumption 1): a managed role admits sessions only with a warrant-form source identity.
//!
//! The check is conservative: any statement that could let someone assume the role
//! without a `sts:SourceIdentity` condition limited to `rw1-*` fails it, including
//! shapes the check does not recognize. A failure makes the run incomplete.

use serde_json::Value;

fn as_list(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(other) => vec![other],
        None => Vec::new(),
    }
}

fn grants_assume(statement: &Value) -> bool {
    as_list(statement.get("Action")).iter().any(|a| {
        a.as_str().is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            s == "*" || s == "sts:*" || s.starts_with("sts:assumerole")
        })
    }) || statement.get("NotAction").is_some()
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

/// Checks a trust policy document. Returns the reasons it fails, empty if it holds.
#[must_use]
pub fn trust_policy_problems(document: &Value) -> Vec<String> {
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
        let principal_is_anyone = st.get("Principal").is_some_and(|p| {
            p.as_str() == Some("*")
                || as_list(p.get("AWS"))
                    .iter()
                    .any(|a| a.as_str() == Some("*"))
        });
        if principal_is_anyone {
            problems.push(format!("statement {i} lets any principal assume the role"));
        }
        if !requires_warrant_identity(st) {
            problems.push(format!(
                "statement {i} allows assuming the role without requiring a source identity of the form rw1-*"
            ));
        }
    }
    problems
}
