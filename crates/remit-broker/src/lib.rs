//! The Remit broker (SPEC section 8.1, ADR 0006).
//!
//! [`plan`] is pure: it verifies a chain against the trusted roots, compiles the leaf
//! warrant's session policy, and decides the session's length, refusing anything that
//! would not be exact. [`assume`] makes the one network call, `AssumeRole`, with the
//! warrant's identifier as `SourceIdentity`, so AWS stamps it on every action the session
//! takes and the reconciler can join `CloudTrail` back to the warrant.

#![forbid(unsafe_code)]

use core::fmt;

use remit_aws::{CompileError, compile_session_policy};
use remit_core::{ChainError, KeyId, SignedWarrant, WarrantId, verify_chain};

/// The shortest session STS issues (STS API reference, `DurationSeconds`).
pub const MIN_SESSION_SECONDS: u64 = 900;
/// The longest session STS issues.
pub const MAX_SESSION_SECONDS: u64 = 43_200;

/// Why no session was planned. Every case is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The chain is not valid for the trusted roots.
    Chain(ChainError),
    /// The warrant's window has not started.
    NotYetValid {
        /// Its first valid second.
        not_before: u64,
    },
    /// The warrant's window has ended.
    Expired {
        /// Its last valid second.
        not_after: u64,
    },
    /// Less than the shortest STS session remains; a longer session would outlive it.
    TooLittleTime {
        /// Seconds left in the window.
        remaining: u64,
    },
    /// The role allows sessions shorter than STS's minimum; it is misconfigured.
    RoleMaxTooShort(u64),
    /// The warrant cannot be compiled exactly.
    Compile(CompileError),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chain(e) => write!(f, "chain: {e}"),
            Self::NotYetValid { not_before } => write!(f, "warrant not valid until {not_before}"),
            Self::Expired { not_after } => write!(f, "warrant expired at {not_after}"),
            Self::TooLittleTime { remaining } => write!(
                f,
                "{remaining} s left in the warrant; STS sessions last at least {MIN_SESSION_SECONDS} s"
            ),
            Self::RoleMaxTooShort(s) => {
                write!(f, "role maximum session of {s} s is below STS's minimum")
            }
            Self::Compile(e) => write!(f, "compile: {e}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Everything `AssumeRole` needs, decided before any network call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlan {
    /// The leaf warrant's identifier: `SourceIdentity` and `RoleSessionName`.
    pub warrant_id: WarrantId,
    /// The compiled session policy.
    pub policy: String,
    /// Session length in seconds, within STS's range and never past the warrant's end.
    pub duration_seconds: u64,
    /// The agent the warrant authorizes.
    pub subject: String,
}

/// Plans a session for the chain's leaf warrant at `now` (SPEC section 8.1).
///
/// # Errors
///
/// An invalid chain, a time outside the window, less than 900 seconds left, a role
/// misconfigured below STS's minimum, or a warrant that cannot be compiled exactly.
pub fn plan(
    chain: &[SignedWarrant],
    roots: &[KeyId],
    now: u64,
    role_max_seconds: u64,
) -> Result<SessionPlan, PlanError> {
    let leaf = verify_chain(chain, roots).map_err(PlanError::Chain)?;
    if now < leaf.not_before() {
        return Err(PlanError::NotYetValid {
            not_before: leaf.not_before(),
        });
    }
    if now > leaf.not_after() {
        return Err(PlanError::Expired {
            not_after: leaf.not_after(),
        });
    }
    if role_max_seconds < MIN_SESSION_SECONDS {
        return Err(PlanError::RoleMaxTooShort(role_max_seconds));
    }
    let remaining = leaf.not_after().saturating_sub(now);
    if remaining < MIN_SESSION_SECONDS {
        return Err(PlanError::TooLittleTime { remaining });
    }
    let duration_seconds = remaining.min(role_max_seconds).min(MAX_SESSION_SECONDS);
    let policy = compile_session_policy(leaf).map_err(PlanError::Compile)?;
    Ok(SessionPlan {
        warrant_id: leaf.id(),
        policy,
        duration_seconds,
        subject: leaf.subject().as_str().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use remit_core::{IssuerKey, Warrant, WarrantSpec};

    fn chain(window: (u64, u64), resource: &str) -> (Vec<SignedWarrant>, KeyId) {
        let root = IssuerKey::from_seed(&[7; 32]);
        let grants: &[(&[&str], &[&str])] = &[(&["s3:GetObject"], &[resource])];
        let w = Warrant::new(&WarrantSpec {
            issuer: root.id().as_str(),
            subject: "agent:runner",
            purpose: "plan tests",
            not_before: window.0,
            not_after: window.1,
            grants,
            parent: None,
            max_depth: 0,
        })
        .unwrap();
        (vec![root.sign(&w).unwrap()], root.id().clone())
    }

    #[test]
    fn a_session_never_outlives_its_warrant() {
        let (c, root) = chain((1000, 10_000), "arn:aws:s3:::b/*");
        let p = plan(&c, std::slice::from_ref(&root), 5_000, 3_600).unwrap();
        assert_eq!(p.duration_seconds, 3_600); // the role's maximum
        let p = plan(&c, &[root], 8_000, 3_600).unwrap();
        assert_eq!(p.duration_seconds, 2_000); // what is left of the warrant
        assert_eq!(p.warrant_id, c[0].warrant().id());
    }

    #[test]
    fn every_refusal() {
        let (c, root) = chain((1000, 10_000), "arn:aws:s3:::b/*");
        let r = [root];
        assert!(matches!(
            plan(&c, &r, 999, 3_600),
            Err(PlanError::NotYetValid { .. })
        ));
        assert!(matches!(
            plan(&c, &r, 10_001, 3_600),
            Err(PlanError::Expired { .. })
        ));
        assert!(matches!(
            plan(&c, &r, 9_500, 3_600),
            Err(PlanError::TooLittleTime { remaining: 500 })
        ));
        assert!(matches!(
            plan(&c, &r, 5_000, 600),
            Err(PlanError::RoleMaxTooShort(600))
        ));
        assert!(matches!(
            plan(&c, &[], 5_000, 3_600),
            Err(PlanError::Chain(_))
        ));
        let (bad, broot) = chain((1000, 10_000), "arn:aws:s3:::b/${aws:username}");
        assert!(matches!(
            plan(&bad, &[broot], 5_000, 3_600),
            Err(PlanError::Compile(_))
        ));
    }
}

/// Short-lived credentials for one warrant's session. Never written to disk; `Debug`
/// shows only the key id.
pub struct SessionCredentials {
    /// `AWS_ACCESS_KEY_ID`.
    pub access_key_id: String,
    /// `AWS_SECRET_ACCESS_KEY`.
    pub secret_access_key: String,
    /// `AWS_SESSION_TOKEN`.
    pub session_token: String,
    /// When STS says they expire, in seconds since the epoch.
    pub expires_at: i64,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Why `AssumeRole` did not produce credentials.
#[derive(Debug)]
pub enum AssumeError {
    /// STS refused or could not be reached; the message is STS's.
    Sts(String),
    /// STS answered without credentials, which it should never do.
    NoCredentials,
}

impl fmt::Display for AssumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sts(m) => write!(f, "STS: {m}"),
            Self::NoCredentials => f.write_str("STS returned no credentials"),
        }
    }
}

impl std::error::Error for AssumeError {}

/// Makes the one network call: `AssumeRole` for `role_arn` with the plan's policy and
/// duration, and the warrant identifier as both `SourceIdentity` and `RoleSessionName`.
///
/// # Errors
///
/// Anything STS refuses, including a role whose trust policy does not allow this caller
/// to set this source identity.
pub async fn assume(
    sts: &aws_sdk_sts::Client,
    role_arn: &str,
    plan: &SessionPlan,
) -> Result<SessionCredentials, AssumeError> {
    let duration = i32::try_from(plan.duration_seconds)
        .map_err(|_| AssumeError::Sts("duration out of range".into()))?;
    let out = sts
        .assume_role()
        .role_arn(role_arn)
        .role_session_name(plan.warrant_id.as_str())
        .source_identity(plan.warrant_id.as_str())
        .policy(&plan.policy)
        .duration_seconds(duration)
        .send()
        .await
        .map_err(|e| AssumeError::Sts(aws_sdk_sts::error::DisplayErrorContext(&e).to_string()))?;
    let c = out.credentials().ok_or(AssumeError::NoCredentials)?;
    Ok(SessionCredentials {
        access_key_id: c.access_key_id().to_owned(),
        secret_access_key: c.secret_access_key().to_owned(),
        session_token: c.session_token().to_owned(),
        expires_at: c.expiration().secs(),
    })
}
