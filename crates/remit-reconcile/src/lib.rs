//! The Remit reconciler (SPEC section 6).
//!
//! [`reconcile`] joins the provider's own record to warrants in both directions and
//! returns a [`Report`]: a verdict that is qualified rather than upgraded, every finding
//! with the event it concerns, and what the run could not see. It is pure; fetching events
//! and trust policies is the caller's job, and the caller states where they came from.

#![forbid(unsafe_code)]

pub mod authorize;
pub mod event;
pub mod trail;
pub mod trust;

use std::collections::{BTreeMap, BTreeSet};

use remit_aws::compile_session_policy;
use remit_core::{Request, Warrant};
use serde::Serialize;

pub use event::{Event, MalformedEvent};
pub use trust::trust_policy_problems;

/// A managed role: its ARN, and the problems found in its trust policy as observed.
#[derive(Debug, Clone)]
pub struct ManagedRole {
    /// The role's ARN.
    pub arn: String,
    /// [`trust_policy_problems`] of its trust policy at the time of the run.
    pub trust_problems: Vec<String>,
}

/// Where the events came from, which decides what the verdict may say (SPEC 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventSource {
    /// `CloudTrail` event history (`LookupEvents`): complete for management events, but
    /// with no integrity evidence.
    EventHistory,
    /// Trail log files whose digests validated.
    ValidatedTrail,
}

/// The default settling period (SPEC section 6, assumption 5): two hours. AWS says
/// `CloudTrail` "typically delivers logs within an average of about 5 minutes of an API
/// call. This time is not guaranteed."; the first live session's refused call took between
/// 25 and 85 minutes to appear in event history (conformance/RESULTS.md).
pub const DEFAULT_SETTLE_SECONDS: u64 = 7200;

/// Everything a run takes (SPEC 6.1).
#[derive(Debug)]
pub struct Input<'a> {
    /// Warrants whose chains verified against the trusted roots.
    pub warrants: &'a [Warrant],
    /// The managed roles.
    pub roles: &'a [ManagedRole],
    /// The events in the window.
    pub events: &'a [Event],
    /// Start of the window, UTC seconds.
    pub from: u64,
    /// End of the window.
    pub to: u64,
    /// When the run happens.
    pub now: u64,
    /// How long after the window closes events are assumed delivered (assumption 5).
    pub settle_seconds: u64,
    /// Where the events came from.
    pub source: EventSource,
    /// The regions the events were gathered from; the verdict speaks for these only.
    pub regions: &'a [String],
    /// Problems found validating the record itself (SPEC 6.7): each fails the run.
    pub record_problems: &'a [String],
    /// The broker principals' ARNs: the only callers that may create a managed session.
    pub brokers: &'a [String],
    /// Session creations from before `from`, back as far as a session can last, so that a
    /// session already open when the window starts is joined to its creation.
    pub earlier: &'a [Event],
}

/// What kind of finding (SPEC sections 6.2 and 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A session on a managed role that does not match its warrant exactly.
    SessionMismatch,
    /// A managed action with no known warrant identifier.
    UnwarrantedEvent,
    /// A managed action outside its warrant's window.
    OutOfWindowEvent,
    /// A managed action by a session whose creation the run did not see and check, so
    /// nothing shows the broker made it under its warrant's policy.
    UnseenSession,
    /// A managed action the cross-check finds outside its warrant.
    OutsideWarrantEvent,
    /// A managed role whose trust policy does not require a warrant identity.
    TrustPolicy,
    /// Information: a managed action that failed; nothing was done.
    RefusedAttempt,
    /// Information: a managed action whose resource could not be determined.
    Undetermined,
    /// The record itself is incomplete or altered: a digest or log file that does not
    /// verify, a gap between digests, a region or hour not covered (SPEC 6.7).
    RecordGap,
}

impl Kind {
    fn fails_the_run(self) -> bool {
        !matches!(self, Self::RefusedAttempt | Self::Undetermined)
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    /// What kind.
    pub kind: Kind,
    /// The event, or the role for a trust-policy finding.
    pub subject: String,
    /// Why, in words.
    pub detail: String,
}

/// The verdict (SPEC 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Complete, from validated evidence, after the settling period.
    Complete,
    /// Complete, but the events carry no integrity evidence.
    CompleteUnvalidated,
    /// No failure found, but the window has not settled.
    Provisional,
    /// At least one failure.
    Incomplete,
}

/// A log checkpoint, as a result names it (SPEC 9.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogPosition {
    /// The log's origin.
    pub origin: String,
    /// Its size.
    pub size: u64,
    /// Its root, in base64.
    pub root: String,
}

/// The result of a run (SPEC 6.6).
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Format of this document.
    pub format: &'static str,
    /// Start of the window, ISO 8601.
    pub from: String,
    /// End of the window.
    pub to: String,
    /// When the run happened.
    pub run_at: String,
    /// Where the events came from.
    pub source: EventSource,
    /// The settling period the verdict assumed (assumption 5).
    pub settle_seconds: u64,
    /// The regions covered; the verdict speaks for these only (SPEC 6.1).
    pub regions: Vec<String>,
    /// Inputs refused before reconciliation, such as a chain that did not verify; filled by
    /// the caller, which is where they are refused.
    pub refused_inputs: Vec<String>,
    /// The log checkpoint the warrants were established at (SPEC 9.4); filled by the
    /// caller, which read the log.
    pub log: Option<LogPosition>,
    /// For a validated trail, what each region's verified digest chain covers (SPEC 6.7);
    /// filled by the caller, which validated it.
    pub record_coverage: Vec<trail::Coverage>,
    /// The managed roles and whether each trust policy held.
    pub roles: BTreeMap<String, bool>,
    /// The verdict.
    pub verdict: Verdict,
    /// Every finding, sorted.
    pub findings: Vec<Finding>,
    /// Managed actions per warrant identifier.
    pub actions_per_warrant: BTreeMap<String, u64>,
    /// The same actions per warrant identifier, counted by action (`service:Name`), refused
    /// ones included: what each warrant was used for. Resource names are left to the cloud
    /// record, so that a published report discloses no more than its warrants do (SPEC 6.6).
    pub actions_by_warrant: BTreeMap<String, BTreeMap<String, u64>>,
    /// Sessions created per warrant identifier.
    pub sessions_per_warrant: BTreeMap<String, u64>,
    /// Events by principals Remit does not manage, per principal: outside the claim, and
    /// counted so that its coverage is visible. An AWS service acting as itself is named
    /// `AWSService:<service>`.
    pub unmanaged: BTreeMap<String, u64>,
    /// Calls an AWS service made for a managed session, per service and action: outside the
    /// claim (SPEC section 6, assumption 4), and counted so that they are seen.
    pub on_behalf: BTreeMap<String, BTreeMap<String, u64>>,
    /// Events considered in total.
    pub events: u64,
}

impl Report {
    /// The document to sign: JSON, written once; the signature covers these exact bytes.
    ///
    /// # Errors
    ///
    /// Only if serialization fails, which the types here cannot cause.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn increment(map: &mut BTreeMap<String, u64>, key: &str) {
    let n = map.entry(key.to_owned()).or_insert(0);
    *n = n.saturating_add(1);
}

/// Runs the reconciliation (SPEC sections 6.2 to 6.4).
#[must_use]
pub fn reconcile(input: &Input<'_>) -> Report {
    let by_id: BTreeMap<String, &Warrant> = input
        .warrants
        .iter()
        .map(|w| (w.id().as_str().to_owned(), w))
        .collect();
    let managed: BTreeSet<String> = input
        .roles
        .iter()
        .map(|r| r.arn.to_ascii_lowercase())
        .collect();
    let mut findings = Vec::new();
    let mut actions = BTreeMap::new();
    let mut by_action = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    let mut unmanaged = BTreeMap::new();
    let mut on_behalf = BTreeMap::new();
    let mut add = |kind, subject: &str, detail: String| {
        findings.push(Finding {
            kind,
            subject: subject.to_owned(),
            detail,
        });
    };

    for role in input.roles {
        for p in &role.trust_problems {
            add(Kind::TrustPolicy, &role.arn, p.clone());
        }
    }
    for p in input.record_problems {
        add(Kind::RecordGap, "cloud record", p.clone());
    }

    let seen_keys = check_sessions(input, &managed, &by_id, &mut sessions, &mut add);

    for e in input.events {
        match classify(e, &managed) {
            Class::Creation => continue,
            Class::Unmanaged(who) => {
                increment(&mut unmanaged, &who);
                continue;
            }
            Class::OnBehalf(service) => {
                increment(
                    on_behalf.entry(service.to_owned()).or_default(),
                    &e.action(),
                );
                continue;
            }
            Class::Managed => {}
        }
        if !e
            .access_key_id
            .as_deref()
            .is_some_and(|k| seen_keys.contains(k))
        {
            add(
                Kind::UnseenSession,
                &e.id,
                format!(
                    "{} by a session whose creation is not in the record",
                    e.action()
                ),
            );
        }
        check_action(e, &by_id, &mut actions, &mut by_action, &mut add);
    }

    findings.sort();
    let verdict = verdict(input, &findings);
    Report {
        format: "remit-reconciliation/1",
        from: remit_aws::iso8601(input.from),
        to: remit_aws::iso8601(input.to),
        run_at: remit_aws::iso8601(input.now),
        source: input.source,
        settle_seconds: input.settle_seconds,
        regions: input.regions.to_vec(),
        refused_inputs: Vec::new(),
        log: None,
        record_coverage: Vec::new(),
        roles: input
            .roles
            .iter()
            .map(|r| (r.arn.clone(), r.trust_problems.is_empty()))
            .collect(),
        verdict,
        findings,
        actions_per_warrant: actions,
        actions_by_warrant: by_action,
        sessions_per_warrant: sessions,
        unmanaged,
        on_behalf,
        events: u64::try_from(input.events.len()).unwrap_or(u64::MAX),
    }
}

/// The verdict for these findings (SPEC 6.4).
fn verdict(input: &Input<'_>, findings: &[Finding]) -> Verdict {
    let settled = input.to.saturating_add(input.settle_seconds) <= input.now;
    if findings.iter().any(|f| f.kind.fails_the_run()) {
        Verdict::Incomplete
    } else if !settled {
        Verdict::Provisional
    } else if input.source == EventSource::EventHistory {
        Verdict::CompleteUnvalidated
    } else {
        Verdict::Complete
    }
}

/// Checks every session creation a managed action may join to, and returns the keys
/// their sessions' calls carry. A creation from before the window is checked only if the
/// window uses it.
fn check_sessions(
    input: &Input<'_>,
    managed: &BTreeSet<String>,
    by_id: &BTreeMap<String, &Warrant>,
    sessions: &mut BTreeMap<String, u64>,
    add: &mut impl FnMut(Kind, &str, String),
) -> BTreeSet<String> {
    let used: BTreeSet<&str> = input
        .events
        .iter()
        .filter_map(|e| e.access_key_id.as_deref())
        .collect();
    let earlier = input
        .earlier
        .iter()
        .filter(|e| e.created_key.as_deref().is_some_and(|k| used.contains(k)));
    let mut seen = BTreeSet::new();
    for e in earlier.chain(input.events) {
        if creates_managed_session(e, managed) {
            check_session(e, by_id, input.brokers, sessions, add);
            seen.extend(e.created_key.clone());
        }
    }
    seen
}

/// Which class of SPEC 6.2 an event is in.
enum Class<'e> {
    /// A session creation on a managed role, checked on its own.
    Creation,
    /// A managed action.
    Managed,
    /// A call a service made for a managed session, as a consequence of a call the session
    /// made and the cross-check judged; it carries a key of the service's, not the session's.
    OnBehalf(&'e str),
    /// Activity by a principal Remit does not manage, named.
    Unmanaged(String),
}

fn classify<'e>(e: &'e Event, managed: &BTreeSet<String>) -> Class<'e> {
    if creates_managed_session(e, managed) {
        return Class::Creation;
    }
    let managed_role = e.identity_type == "AssumedRole"
        && e.session_issuer_arn
            .as_deref()
            .is_some_and(|r| managed.contains(&r.to_ascii_lowercase()));
    // AWS carries a source identity through role chaining, so a warrant's identifier on a
    // session of any role is the warrant's work, whatever role it reached.
    let warrant_shaped = e
        .source_identity
        .as_deref()
        .is_some_and(|si| si.starts_with("rw1-"));
    if !managed_role && !warrant_shaped {
        return Class::Unmanaged(match (&e.identity_arn, &e.invoked_by) {
            (Some(arn), _) => arn.clone(),
            (None, Some(service)) => format!("{}:{service}", e.identity_type),
            (None, None) => e.identity_type.clone(),
        });
    }
    e.made_by_service().map_or(Class::Managed, Class::OnBehalf)
}

/// The parameters the broker passes to `AssumeRole`, and no others (SPEC 8.2).
const BROKER_PARAMETERS: [&str; 5] = [
    "durationSeconds",
    "policy",
    "roleArn",
    "roleSessionName",
    "sourceIdentity",
];

/// Whether an event creates a session on a managed role. The role is taken from what AWS
/// recorded as the resource and the assumed-role user, and from the requested ARN, any of
/// which is enough: a request that spells the ARN differently still names the role.
fn creates_managed_session(e: &Event, managed: &BTreeSet<String>) -> bool {
    if e.source != "sts.amazonaws.com" || !e.name.starts_with("AssumeRole") {
        return false;
    }
    let named = |arn: &str| managed.contains(&arn.to_ascii_lowercase());
    e.role_resources.iter().any(|r| named(r))
        || e.param("roleArn").is_some_and(named)
        || e.assumed_role_user
            .as_deref()
            .and_then(role_of_assumed_user)
            .is_some_and(|r| named(&r))
}

/// `arn:aws:sts::A:assumed-role/NAME/SESSION` as the role `arn:aws:iam::A:role/NAME`. The
/// assumed-role ARN drops the role's path, so a role with a path is recognized by its
/// resource or requested ARN instead.
fn role_of_assumed_user(arn: &str) -> Option<String> {
    let rest = arn.strip_prefix("arn:")?;
    let (partition, rest) = rest.split_once(':')?;
    let rest = rest.strip_prefix("sts::")?;
    let (account, rest) = rest.split_once(':')?;
    let rest = rest.strip_prefix("assumed-role/")?;
    let (name, _session) = rest.split_once('/')?;
    Some(format!("arn:{partition}:iam::{account}:role/{name}"))
}

/// Who created the session, how, and with what: only a broker, only `AssumeRole`, and only
/// the parameters the broker passes.
fn check_origin(e: &Event, brokers: &[String], add: &mut impl FnMut(Kind, &str, String)) {
    if e.name != "AssumeRole" {
        add(
            Kind::SessionMismatch,
            &e.id,
            format!(
                "session created by {}, which the broker never calls",
                e.name
            ),
        );
    }
    let caller = e.identity_arn.as_deref().unwrap_or(&e.identity_type);
    // A broker is a user, or a role whose sessions call STS: a broker service runs as its
    // function's execution role, recorded as a session of that role.
    let issuer = (e.identity_type == "AssumedRole")
        .then_some(e.session_issuer_arn.as_deref())
        .flatten();
    if !brokers
        .iter()
        .any(|b| b == caller || Some(b.as_str()) == issuer)
    {
        add(
            Kind::SessionMismatch,
            &e.id,
            format!("session created by {caller}, which is not a broker"),
        );
    }
    let extra: Vec<&str> = e
        .request_parameters
        .as_object()
        .map(|o| {
            o.keys()
                .map(String::as_str)
                .filter(|k| !BROKER_PARAMETERS.contains(k))
                .collect()
        })
        .unwrap_or_default();
    if !extra.is_empty() {
        add(
            Kind::SessionMismatch,
            &e.id,
            format!(
                "session created with {}, which the broker never passes",
                extra.join(", ")
            ),
        );
    }
}

fn check_session(
    e: &Event,
    by_id: &BTreeMap<String, &Warrant>,
    brokers: &[String],
    sessions: &mut BTreeMap<String, u64>,
    add: &mut impl FnMut(Kind, &str, String),
) {
    if let Some(code) = &e.error_code {
        add(
            Kind::RefusedAttempt,
            &e.id,
            format!("{} refused: {code}", e.action()),
        );
        return;
    }
    check_origin(e, brokers, add);
    let Some(si) = e.param("sourceIdentity") else {
        add(
            Kind::SessionMismatch,
            &e.id,
            "session created with no source identity".into(),
        );
        return;
    };
    increment(sessions, si);
    let Some(w) = by_id.get(si) else {
        add(
            Kind::SessionMismatch,
            &e.id,
            format!("source identity {si} names no known warrant"),
        );
        return;
    };
    if e.param("roleSessionName") != Some(si) {
        add(
            Kind::SessionMismatch,
            &e.id,
            "role session name is not the warrant identifier".into(),
        );
    }
    match compile_session_policy(w) {
        Ok(expected) if e.param("policy") == Some(expected.as_str()) => {}
        Ok(_) => add(
            Kind::SessionMismatch,
            &e.id,
            format!("the session policy passed is not the one compiled from {si}"),
        ),
        Err(err) => add(
            Kind::SessionMismatch,
            &e.id,
            format!("{si} does not compile: {err}"),
        ),
    }
    if e.time < w.not_before() || e.time > w.not_after() {
        add(
            Kind::SessionMismatch,
            &e.id,
            format!("session created outside {si}'s window"),
        );
    }
    match e.param_u64("durationSeconds") {
        Some(d) if e.time.saturating_add(d) <= w.not_after() => {}
        Some(_) => add(
            Kind::SessionMismatch,
            &e.id,
            format!("session outlives {si}"),
        ),
        None => add(
            Kind::SessionMismatch,
            &e.id,
            "no session duration recorded".into(),
        ),
    }
}

fn check_action(
    e: &Event,
    by_id: &BTreeMap<String, &Warrant>,
    actions: &mut BTreeMap<String, u64>,
    by_action: &mut BTreeMap<String, BTreeMap<String, u64>>,
    add: &mut impl FnMut(Kind, &str, String),
) {
    let Some(si) = e.source_identity.as_deref() else {
        add(
            Kind::UnwarrantedEvent,
            &e.id,
            format!("{} by a managed role with no source identity", e.action()),
        );
        return;
    };
    increment(actions, si);
    increment(by_action.entry(si.to_owned()).or_default(), &e.action());
    let Some(w) = by_id.get(si) else {
        add(
            Kind::UnwarrantedEvent,
            &e.id,
            format!("{} under {si}, which names no known warrant", e.action()),
        );
        return;
    };
    if e.time < w.not_before() || e.time > w.not_after() {
        add(
            Kind::OutOfWindowEvent,
            &e.id,
            format!("{} outside {si}'s window", e.action()),
        );
    }
    if let Some(code) = &e.error_code {
        add(
            Kind::RefusedAttempt,
            &e.id,
            format!("{} refused: {code}", e.action()),
        );
        return;
    }
    let authorizing = e.authorizing_actions();
    if authorizing.is_empty() {
        return;
    }
    if e.resources.is_empty() {
        // With no resource to check, the question left is whether any grant names the
        // action at all. If none does, the work was outside the warrant whatever it touched.
        let named = w.grants().iter().any(|g| {
            g.actions()
                .iter()
                .any(|p| authorizing.iter().any(|a| p.matches(a)))
        });
        if named {
            add(
                Kind::Undetermined,
                &e.id,
                format!("{}: the event names no resource", e.action()),
            );
        } else {
            add(
                Kind::OutsideWarrantEvent,
                &e.id,
                format!("{} is not granted by {si} on any resource", e.action()),
            );
        }
        return;
    }
    let subject = w.subject().as_str();
    // Time has its own finding above; the cross-check asks only about action and resource,
    // so one fault is reported once.
    let at = e.time.clamp(w.not_before(), w.not_after());
    for resource in &e.resources {
        // An S3 object event may also list the object's bucket, which is where the object
        // is, not something the call was authorized on.
        let container = e.source == "s3.amazonaws.com"
            && e.resources.iter().any(|other| {
                other
                    .strip_prefix(resource.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            });
        if container {
            continue;
        }
        let permitted = authorizing
            .iter()
            .any(|action| Request::new(subject, action, resource, at).is_ok_and(|r| w.permits(&r)));
        if !permitted {
            add(
                Kind::OutsideWarrantEvent,
                &e.id,
                format!("{} on {resource} is not permitted by {si}", e.action()),
            );
        }
    }
}
