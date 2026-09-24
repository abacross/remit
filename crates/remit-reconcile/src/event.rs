//! The parts of a `CloudTrail` event the reconciler reads (SPEC sections 6.2 and 6.5).
//!
//! Parsing is deliberately narrow: only the fields the classification needs are read,
//! and an event missing one of the fields every event has (identifier, time, source,
//! name) is refused as malformed rather than guessed at.

use core::fmt;

use remit_aws::parse_iso8601;
use serde_json::Value;

/// A `CloudTrail` event, reduced to what reconciliation uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `eventID`.
    pub id: String,
    /// `eventTime`, in UTC seconds.
    pub time: u64,
    /// `eventSource`, for example `s3.amazonaws.com`.
    pub source: String,
    /// `eventName`, for example `GetBucketLocation`.
    pub name: String,
    /// `errorCode`, when the call failed.
    pub error_code: Option<String>,
    /// `userIdentity.type`.
    pub identity_type: String,
    /// `userIdentity.arn`, when present.
    pub identity_arn: Option<String>,
    /// `userIdentity.sessionContext.sessionIssuer.arn`: the role, for a role session.
    pub session_issuer_arn: Option<String>,
    /// `userIdentity.sessionContext.sourceIdentity`.
    pub source_identity: Option<String>,
    /// `requestParameters`, kept whole for the session-creation checks.
    pub request_parameters: Value,
    /// Every `resources[].ARN`.
    pub resources: Vec<String>,
}

/// Why an event was refused as malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedEvent(pub String);

impl fmt::Display for MalformedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed event: {}", self.0)
    }
}

impl std::error::Error for MalformedEvent {}

fn text(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(str::to_owned)
}

impl Event {
    /// Reads one event from its JSON.
    ///
    /// # Errors
    ///
    /// A missing or unparseable `eventID`, `eventTime`, `eventSource`, `eventName` or
    /// `userIdentity.type`.
    pub fn from_json(v: &Value) -> Result<Self, MalformedEvent> {
        let need = |path: &[&str]| {
            text(v, path).ok_or_else(|| MalformedEvent(format!("no {}", path.join("."))))
        };
        let time_text = need(&["eventTime"])?;
        let time = parse_iso8601(&time_text)
            .ok_or_else(|| MalformedEvent(format!("eventTime {time_text:?}")))?;
        let resources = v
            .get("resources")
            .and_then(Value::as_array)
            .map(|rs| {
                rs.iter()
                    .filter_map(|r| r.get("ARN").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            id: need(&["eventID"])?,
            time,
            source: need(&["eventSource"])?,
            name: need(&["eventName"])?,
            error_code: text(v, &["errorCode"]),
            identity_type: need(&["userIdentity", "type"])?,
            identity_arn: text(v, &["userIdentity", "arn"]),
            session_issuer_arn: text(
                v,
                &["userIdentity", "sessionContext", "sessionIssuer", "arn"],
            ),
            source_identity: text(v, &["userIdentity", "sessionContext", "sourceIdentity"]),
            request_parameters: v.get("requestParameters").cloned().unwrap_or(Value::Null),
            resources,
        })
    }

    /// The IAM-style action this event records: the source without `.amazonaws.com`, a
    /// colon, and the event name (SPEC section 6.5).
    #[must_use]
    pub fn action(&self) -> String {
        let service = self
            .source
            .strip_suffix(".amazonaws.com")
            .unwrap_or(&self.source);
        format!("{service}:{}", self.name)
    }

    /// A request parameter as text.
    #[must_use]
    pub fn param(&self, key: &str) -> Option<&str> {
        self.request_parameters.get(key).and_then(Value::as_str)
    }

    /// A request parameter as an unsigned integer.
    #[must_use]
    pub fn param_u64(&self, key: &str) -> Option<u64> {
        self.request_parameters.get(key).and_then(Value::as_u64)
    }
}
