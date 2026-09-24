//! The Remit reconciler (SPEC section 6).
//!
//! [`reconcile`] joins the provider's own record to warrants in both directions and
//! returns a [`Report`]: a verdict that is qualified rather than upgraded, every finding
//! with the event it concerns, and what the run could not see. It is pure; fetching events
//! and trust policies is the caller's job, and the caller states where they came from.

#![forbid(unsafe_code)]

pub mod event;
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
    /// A managed action the cross-check finds outside its warrant.
    OutsideWarrantEvent,
    /// A managed role whose trust policy does not require a warrant identity.
    TrustPolicy,
    /// Information: a managed action that failed; nothing was done.
    RefusedAttempt,
    /// Information: a managed action whose resource could not be determined.
    Undetermined,
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
    /// The managed roles and whether each trust policy held.
    pub roles: BTreeMap<String, bool>,
    /// The verdict.
    pub verdict: Verdict,
    /// Every finding, sorted.
    pub findings: Vec<Finding>,
    /// Managed actions per warrant identifier.
    pub actions_per_warrant: BTreeMap<String, u64>,
    /// Sessions created per warrant identifier.
    pub sessions_per_warrant: BTreeMap<String, u64>,
    /// Events by principals Remit does not manage, per principal: outside the claim, and
    /// counted so that its coverage is visible.
    pub unmanaged: BTreeMap<String, u64>,
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
    let managed: BTreeSet<&str> = input.roles.iter().map(|r| r.arn.as_str()).collect();
    let mut findings = Vec::new();
    let mut actions = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    let mut unmanaged = BTreeMap::new();
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

    for e in input.events {
        let is_session_creation = e.source == "sts.amazonaws.com"
            && e.name == "AssumeRole"
            && e.param("roleArn").is_some_and(|r| managed.contains(r));
        let is_managed_action = e.identity_type == "AssumedRole"
            && e.session_issuer_arn
                .as_deref()
                .is_some_and(|r| managed.contains(r));

        if is_session_creation {
            check_session(e, &by_id, &mut sessions, &mut add);
        } else if is_managed_action {
            check_action(e, &by_id, &mut actions, &mut add);
        } else {
            let who = e
                .identity_arn
                .clone()
                .unwrap_or_else(|| e.identity_type.clone());
            increment(&mut unmanaged, &who);
        }
    }

    findings.sort();
    let failed = findings.iter().any(|f| f.kind.fails_the_run());
    let settled = input.to.saturating_add(input.settle_seconds) <= input.now;
    let verdict = if failed {
        Verdict::Incomplete
    } else if !settled {
        Verdict::Provisional
    } else if input.source == EventSource::EventHistory {
        Verdict::CompleteUnvalidated
    } else {
        Verdict::Complete
    };
    Report {
        format: "remit-reconciliation/1",
        from: remit_aws::iso8601(input.from),
        to: remit_aws::iso8601(input.to),
        run_at: remit_aws::iso8601(input.now),
        source: input.source,
        roles: input
            .roles
            .iter()
            .map(|r| (r.arn.clone(), r.trust_problems.is_empty()))
            .collect(),
        verdict,
        findings,
        actions_per_warrant: actions,
        sessions_per_warrant: sessions,
        unmanaged,
        events: u64::try_from(input.events.len()).unwrap_or(u64::MAX),
    }
}

fn check_session(
    e: &Event,
    by_id: &BTreeMap<String, &Warrant>,
    sessions: &mut BTreeMap<String, u64>,
    add: &mut impl FnMut(Kind, &str, String),
) {
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
    if e.resources.is_empty() {
        add(
            Kind::Undetermined,
            &e.id,
            format!("{}: the event names no resource", e.action()),
        );
        return;
    }
    let subject = w.subject().as_str();
    // Time has its own finding above; the cross-check asks only about action and resource,
    // so one fault is reported once.
    let at = e.time.clamp(w.not_before(), w.not_after());
    for resource in &e.resources {
        let permitted =
            Request::new(subject, &e.action(), resource, at).is_ok_and(|r| w.permits(&r));
        if !permitted {
            add(
                Kind::OutsideWarrantEvent,
                &e.id,
                format!("{} on {resource} is not permitted by {si}", e.action()),
            );
        }
    }
}
