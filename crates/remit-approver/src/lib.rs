//! Remit approvers (SPEC section 10).
//!
//! An approver decides, one request at a time, whether an agent may take one action
//! without a person, and records a yes as a child of the warrant a human gave it. The
//! order is fixed and every doubt falls towards a person: form, then the bound (checked
//! before any decider is asked), then hard rules, then the decider, then the threshold.
//! Whatever the decider says, the attenuation theorem keeps every issued warrant inside
//! the human's bound.
//!
//! [`system_one`] builds and reads the System One wire format shared by `TypeSafe`'s Jev
//! and the self-hosted jeff, without doing any I/O; the caller sends the request.

#![forbid(unsafe_code)]

pub mod reference;
pub mod system_one;

use core::fmt;

use remit_core::{
    ActionPattern, IssuerKey, MAX_PURPOSE, SignedWarrant, Warrant, WarrantSpec, check_attenuation,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The risk bands a decider chooses among (SPEC section 10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// Reads only.
    ReadOnly,
    /// Changes something that can be undone.
    ReversibleChange,
    /// Touches secrets, money, people or anything outside the account.
    SensitiveOrExternal,
    /// Cannot be undone.
    Destructive,
}

impl Band {
    /// Every band, in order of increasing risk.
    pub const ALL: [Self; 4] = [
        Self::ReadOnly,
        Self::ReversibleChange,
        Self::SensitiveOrExternal,
        Self::Destructive,
    ];

    /// The band's name on the wire and in evidence.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReversibleChange => "reversible_change",
            Self::SensitiveOrExternal => "sensitive_or_external",
            Self::Destructive => "destructive",
        }
    }

    /// Parses a band's name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.as_str() == name)
    }
}

/// What a decider said about one request.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// The risk band it chose.
    pub band: Band,
    /// Its probability that the action is safe to take without a person.
    pub p_safe: f64,
    /// The model it reports having used.
    pub model: String,
}

/// Something that judges requests: a model, rules, anything.
pub trait Decider {
    /// A short name for evidence, such as `jeff` or `jev`.
    fn name(&self) -> &str;

    /// Judges the state shown to it (SPEC section 10.5), given also as its exact JSON.
    ///
    /// # Errors
    ///
    /// Anything that went wrong; the approver escalates.
    fn assess(&mut self, state_json: &str) -> Result<Assessment, String>;
}

/// A request from an agent (SPEC section 10.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The requesting agent: the child warrant's subject.
    pub agent: String,
    /// One concrete action, such as `s3:GetObject`.
    pub action: String,
    /// One concrete resource.
    pub resource: String,
    /// How long the agent asks for, in seconds.
    pub seconds: u64,
    /// The agent's own reason.
    pub purpose: String,
    /// Untrusted context shown to the decider, never parsed by the approver.
    pub context: String,
}

/// An approver's configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Action patterns that always go to a person.
    pub hard_rules: Vec<ActionPattern>,
    /// The bands that may be approved without a person.
    pub allowed_bands: Vec<Band>,
    /// The lowest probability of safety that may be approved.
    pub threshold: f64,
    /// The longest window an approval may have.
    pub max_seconds: u64,
}

impl Default for Config {
    /// Read-only actions only, at 0.9 or above, for at most an hour. IAM, KMS, STS,
    /// Organizations, any delete, put-policy or termination, and reads of secrets go to a
    /// person: AWS's service reference classes `secretsmanager:GetSecretValue` and
    /// `ssm:GetParameter` as plain reads, with no flag at all.
    fn default() -> Self {
        let rules = [
            "iam:*",
            "kms:*",
            "sts:*",
            "organizations:*",
            "*:Delete*",
            "*:Put*Policy*",
            "*:Terminate*",
            "secretsmanager:GetSecretValue",
            "secretsmanager:BatchGetSecretValue",
            "ssm:GetParameter*",
        ];
        Self {
            hard_rules: rules
                .iter()
                .filter_map(|r| ActionPattern::new(r).ok())
                .collect(),
            allowed_bands: vec![Band::ReadOnly],
            threshold: 0.9,
            max_seconds: 3600,
        }
    }
}

/// What the approver decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Approved: the signed child warrant.
    Issued(Box<SignedWarrant>),
    /// A person must decide; the reason says why.
    Escalated(String),
    /// Can never be approved under this bound; the reason says why.
    Refused(String),
}

/// The record every decision leaves, allowed or not (SPEC section 10.3).
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// The time of the decision.
    pub at: u64,
    /// The agent.
    pub agent: String,
    /// The action.
    pub action: String,
    /// The resource.
    pub resource: String,
    /// `issued`, `escalated` or `refused`.
    pub outcome: &'static str,
    /// Why, for anything but an issue.
    pub reason: String,
    /// The input hash of SPEC section 10.5.
    pub input: String,
    /// The decider's assessment, when it was asked and answered.
    pub assessment: Option<Assessment>,
    /// The issued warrant's identifier.
    pub warrant: Option<String>,
}

impl Record {
    /// One line of JSON, for the approver's decision log. The context is not included,
    /// only its hash within `input`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut m = Map::new();
        m.insert("at".into(), self.at.into());
        m.insert("agent".into(), self.agent.clone().into());
        m.insert("action".into(), self.action.clone().into());
        m.insert("resource".into(), self.resource.clone().into());
        m.insert("outcome".into(), self.outcome.into());
        m.insert("reason".into(), self.reason.clone().into());
        m.insert("input".into(), self.input.clone().into());
        if let Some(a) = &self.assessment {
            m.insert("band".into(), a.band.as_str().into());
            m.insert("p_safe".into(), a.p_safe.into());
            m.insert("model".into(), a.model.clone().into());
        }
        if let Some(w) = &self.warrant {
            m.insert("warrant".into(), w.clone().into());
        }
        Value::Object(m).to_string()
    }
}

/// The state shown to the decider: `action`, `context`, `purpose`, `resource`, in that
/// order, without whitespace (SPEC section 10.5).
#[must_use]
pub fn state_json(request: &Request) -> String {
    // Keys are inserted in the specified order, which is also sorted order, so the result
    // is the same whichever map serde_json was built with.
    let mut m = Map::new();
    m.insert("action".into(), request.action.clone().into());
    m.insert("context".into(), request.context.clone().into());
    m.insert("purpose".into(), request.purpose.clone().into());
    m.insert("resource".into(), request.resource.clone().into());
    Value::Object(m).to_string()
}

/// `sha256:` and the first 16 bytes of SHA-256 of the state, in lowercase hex.
#[must_use]
pub fn input_hash(state: &str) -> String {
    let digest = Sha256::digest(state.as_bytes());
    let hex: String = digest
        .iter()
        .take(16)
        .flat_map(|b| [b >> 4, b & 0x0f].map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0')))
        .collect();
    format!("sha256:{hex}")
}

/// A value safe inside a space-separated `key=value` evidence field.
fn token(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._:/@+-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if t.is_empty() { "_".into() } else { t }
}

/// The evidence line of SPEC section 10.5.
#[must_use]
pub fn evidence(decider: &str, a: &Assessment, threshold: f64, input: &str) -> String {
    format!(
        "remit-approval/v1 decider={} model={} band={} p={:.4} threshold={threshold:.2} input={input}",
        token(decider),
        token(&a.model),
        a.band.as_str(),
        a.p_safe
    )
}

/// The child's purpose: the evidence, ` | `, and the agent's purpose, cut at a character
/// boundary to fit [`MAX_PURPOSE`] bytes.
fn child_purpose(evidence: &str, agent_purpose: &str) -> String {
    let mut out = format!("{evidence} | {agent_purpose}");
    if out.len() > MAX_PURPOSE {
        let mut end = MAX_PURPOSE;
        while !out.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        out.truncate(end);
    }
    out
}

fn is_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

/// Decides one request under `bound`, a warrant from a human whose subject is `key`
/// (SPEC section 10.3), and returns the outcome and the record to keep.
pub fn decide(
    bound: &Warrant,
    key: &IssuerKey,
    config: &Config,
    request: &Request,
    decider: &mut dyn Decider,
    now: u64,
) -> (Outcome, Record) {
    let state = state_json(request);
    let input = input_hash(&state);
    let (outcome, assessment) =
        run_stages(bound, key, config, request, decider, now, &state, &input);
    let (kind, reason, warrant) = match &outcome {
        Outcome::Issued(w) => (
            "issued",
            String::new(),
            Some(w.warrant().id().as_str().to_owned()),
        ),
        Outcome::Escalated(why) => ("escalated", why.clone(), None),
        Outcome::Refused(why) => ("refused", why.clone(), None),
    };
    let record = Record {
        at: now,
        agent: request.agent.clone(),
        action: request.action.clone(),
        resource: request.resource.clone(),
        outcome: kind,
        reason,
        input,
        assessment,
        warrant,
    };
    (outcome, record)
}

/// Steps 1 and 2: form and bound. Returns the child's window, or the refusal.
fn check_form_and_bound(
    bound: &Warrant,
    key: &IssuerKey,
    config: &Config,
    request: &Request,
    now: u64,
) -> Result<(u64, u64), Outcome> {
    let refuse = |why: &str| Err(Outcome::Refused(why.to_owned()));
    if bound.subject().as_str() != key.id().as_str() {
        return refuse("the bound is not addressed to this approver's key");
    }
    if bound.max_depth() < 1 {
        return refuse("the bound does not allow delegation (max_depth 0)");
    }
    if is_pattern(&request.action) || is_pattern(&request.resource) {
        return refuse("action and resource must be concrete names, not patterns");
    }
    if request.seconds == 0 || !config.threshold.is_finite() {
        return refuse("malformed request or configuration");
    }
    let not_before = now.max(bound.not_before());
    let not_after = now
        .saturating_add(request.seconds.min(config.max_seconds))
        .min(bound.not_after());
    if not_after <= not_before {
        return refuse("the bound's window has closed");
    }
    let probe = child(bound, key, request, (not_before, not_after), "")
        .map_err(|e| Outcome::Refused(format!("not a valid request: {e}")))?;
    check_attenuation(bound, &probe)
        .map_err(|e| Outcome::Refused(format!("outside the bound: {e}")))?;
    Ok((not_before, not_after))
}

/// Steps 4 and 5: the decider and the threshold. Returns the assessment if it approves.
fn judge(
    config: &Config,
    decider: &mut dyn Decider,
    state: &str,
) -> (Result<(), Outcome>, Option<Assessment>) {
    let escalate = |why: String| Err(Outcome::Escalated(why));
    let a = match decider.assess(state) {
        Ok(a) if a.p_safe.is_finite() && (0.0..=1.0).contains(&a.p_safe) => a,
        Ok(_) => {
            return (
                escalate("the decider's probability is not in [0, 1]".into()),
                None,
            );
        }
        Err(e) => return (escalate(format!("the decider failed: {e}")), None),
    };
    let verdict = if !config.allowed_bands.contains(&a.band) {
        escalate(format!(
            "band {} is not approved without a person",
            a.band.as_str()
        ))
    } else if a.p_safe < config.threshold {
        escalate(format!(
            "p {:.4} is below the threshold {:.2}",
            a.p_safe, config.threshold
        ))
    } else {
        Ok(())
    };
    (verdict, Some(a))
}

fn child(
    bound: &Warrant,
    key: &IssuerKey,
    request: &Request,
    (not_before, not_after): (u64, u64),
    purpose: &str,
) -> Result<Warrant, remit_core::WarrantError> {
    Warrant::new(&WarrantSpec {
        issuer: key.id().as_str(),
        subject: &request.agent,
        purpose,
        not_before,
        not_after,
        grants: &[(&[request.action.as_str()], &[request.resource.as_str()])],
        parent: Some(bound.id().clone()),
        max_depth: 0,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the stages of one decision, in SPEC order"
)]
fn run_stages(
    bound: &Warrant,
    key: &IssuerKey,
    config: &Config,
    request: &Request,
    decider: &mut dyn Decider,
    now: u64,
    state: &str,
    input: &str,
) -> (Outcome, Option<Assessment>) {
    // 1 and 2: form, then the bound, before any decider is asked.
    let window = match check_form_and_bound(bound, key, config, request, now) {
        Ok(w) => w,
        Err(o) => return (o, None),
    };
    // 3: hard rules.
    if let Some(rule) = config
        .hard_rules
        .iter()
        .find(|r| r.matches(&request.action))
    {
        let why = format!("hard rule {} always goes to a person", rule.as_str());
        return (Outcome::Escalated(why), None);
    }
    // 4 and 5: the decider and the threshold.
    let (verdict, assessment) = judge(config, decider, state);
    let Some(a) = assessment.clone().filter(|_| verdict.is_ok()) else {
        return (
            verdict
                .err()
                .unwrap_or_else(|| Outcome::Escalated("no assessment".into())),
            assessment,
        );
    };
    let line = evidence(decider.name(), &a, config.threshold, input);
    let signed = child(
        bound,
        key,
        request,
        window,
        &child_purpose(&line, &request.purpose),
    )
    .map_err(|e| Outcome::Refused(format!("not a valid request: {e}")))
    // The same check again on the warrant actually signed, not only on the probe.
    .and_then(|w| {
        check_attenuation(bound, &w)
            .map_err(|e| Outcome::Refused(format!("outside the bound: {e}")))?;
        key.sign(&w)
            .map_err(|e| Outcome::Escalated(format!("could not sign: {e}")))
    });
    match signed {
        Ok(w) => (Outcome::Issued(Box::new(w)), assessment),
        Err(o) => (o, assessment),
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issued(w) => write!(f, "issued {}", w.warrant().id()),
            Self::Escalated(why) => write!(f, "escalated: {why}"),
            Self::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}
