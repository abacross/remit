//! The Remit broker as an AWS Lambda function (SPEC section 8.4).
//!
//! Its configuration is the function's own environment, set when it is deployed by the
//! people who issue warrants (`deploy/aws/broker-service.yaml`): the trusted root keys,
//! the log's trust policy, the roles it may assume and their longest session. A caller
//! sends a [`BrokerRequest`] and gets either a session or a refusal that says why; every
//! decision is written to the function's log without any credential.

#![forbid(unsafe_code)]

use lambda_runtime::{Error, LambdaEvent, service_fn};
use remit_broker::service::{BrokerRequest, ServiceConfig, authorize};
use serde_json::{Value, json};

/// Reads the deployed configuration; a function that cannot read it refuses everything.
fn config() -> Result<ServiceConfig, String> {
    let var = |name: &str| std::env::var(name).map_err(|_| format!("{name} is not set"));
    ServiceConfig::from_settings(
        &var("REMIT_TRUSTED_ROOTS")?,
        &var("REMIT_LOG_POLICY_BASE64")?,
        &var("REMIT_ROLES")?,
        &var("REMIT_ROLE_MAX_SECONDS")?,
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One line per decision in the function's log, never a credential.
fn record(decision: &str, detail: &Value) {
    println!("{}", json!({"decision": decision, "detail": detail}));
}

async fn handle(
    event: LambdaEvent<Value>,
    cfg: &Result<ServiceConfig, String>,
    sts: &aws_sdk_sts::Client,
) -> Result<Value, Error> {
    let refuse = |reason: String| {
        record("refused", &json!({"reason": reason}));
        Ok(json!({"refused": reason}))
    };
    let cfg = match cfg {
        Ok(c) => c,
        Err(e) => return refuse(format!("the broker is not configured: {e}")),
    };
    let req: BrokerRequest = match serde_json::from_value(event.payload) {
        Ok(r) => r,
        Err(e) => return refuse(format!("malformed request: {e}")),
    };
    let ok = match authorize(&req, cfg, now()) {
        Ok(ok) => ok,
        Err(e) => return refuse(e.to_string()),
    };
    let creds = match remit_broker::assume(sts, &ok.role, &ok.plan).await {
        Ok(c) => c,
        Err(e) => return refuse(e.to_string()),
    };
    record(
        "issued",
        &json!({
            "warrant": ok.plan.warrant_id.as_str(),
            "subject": ok.plan.subject,
            "role": ok.role,
            "duration_seconds": ok.plan.duration_seconds,
            "access_key_id": creds.access_key_id,
            "logged": format!("{} at size {}", ok.logged_origin, ok.logged_size),
        }),
    );
    Ok(json!({
        "warrant_id": ok.plan.warrant_id.as_str(),
        "subject": ok.plan.subject,
        "duration_seconds": ok.plan.duration_seconds,
        "access_key_id": creds.access_key_id,
        "secret_access_key": creds.secret_access_key,
        "session_token": creds.session_token,
        "expires_at": creds.expires_at,
        "logged_origin": ok.logged_origin,
        "logged_size": ok.logged_size,
    }))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let aws = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    remit_broker::refuse_endpoint_overrides(&aws, &["STS"])?;
    let sts = aws_sdk_sts::Client::new(&aws);
    let cfg = config();
    if let Err(e) = &cfg {
        record("misconfigured", &json!({"reason": e}));
    }
    lambda_runtime::run(service_fn(|event| handle(event, &cfg, &sts))).await
}
