//! The broker as a service of its own (SPEC section 8.4).
//!
//! When `remit run` holds the broker's credentials itself, whoever starts it chooses what
//! it trusts: the root keys, the log's trust policy, even the role. As a service, the
//! broker holds its own [`ServiceConfig`], set by the people who issue warrants, and the
//! caller sends only a request: the chain, its log proof, the role, and a signature by the
//! key the warrant names as its subject over all of it, fresh to the minute. [`authorize`]
//! decides from the service's own configuration alone; nothing the caller sends can widen
//! what it trusts, and a warrant cannot be used by anyone but its subject.

use core::fmt;

use remit_core::{
    BROKER_REQUEST_DOMAIN, IssuerKey, KeyId, SignedWarrant, decode_chain, encode_chain,
    sign_in_domain, verify_in_domain,
};
use remit_log::{LoggedProof, TrustPolicy, base64};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{PlanError, SessionPlan, plan};

/// The request format this module reads and writes.
pub const FORMAT: &str = "remit-broker-request/1";

/// How far a request's time may be from the service's, either way.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 60;

/// What a caller sends. Every field but the signature is covered by the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRequest {
    /// [`FORMAT`].
    pub format: String,
    /// The warrant chain in its transport encoding, base64.
    pub chain: String,
    /// The proof file that every link is logged (`remit log prove`), as text.
    pub proof: String,
    /// The role to assume.
    pub role: String,
    /// When the request was made, UTC seconds.
    pub time: u64,
    /// 16 random bytes, lowercase hex, so that no two requests sign the same bytes.
    pub nonce: String,
    /// Ed25519 by the leaf warrant's subject key, in the `REMITBv1` domain, lowercase hex.
    pub signature: String,
}

/// What the service trusts, set when it is deployed and never by a caller.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Root keys a chain must start at.
    pub roots: Vec<KeyId>,
    /// The log's trust policy: no chain is honoured unless proven logged under it.
    pub log_policy: TrustPolicy,
    /// The roles this broker may assume, by exact ARN.
    pub roles: Vec<String>,
    /// The roles' maximum session length, seconds.
    pub role_max_seconds: u64,
}

impl ServiceConfig {
    /// Reads the configuration from its deployed settings: root key identifiers separated
    /// by commas, the trust policy file base64-encoded, role ARNs separated by commas, and
    /// the roles' maximum session in seconds.
    ///
    /// # Errors
    ///
    /// Any setting that does not parse; an empty list of roots or roles.
    pub fn from_settings(
        roots: &str,
        log_policy_base64: &str,
        roles: &str,
        role_max_seconds: &str,
    ) -> Result<Self, String> {
        let roots = split(roots)
            .map(|r| KeyId::parse(r).map_err(|e| format!("root {r}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let roles: Vec<String> = split(roles).map(str::to_owned).collect();
        if roots.is_empty() || roles.is_empty() {
            return Err("a broker needs at least one trusted root and one role".into());
        }
        let policy_bytes =
            base64::decode(log_policy_base64.trim()).ok_or("the log policy is not base64")?;
        let policy_text =
            String::from_utf8(policy_bytes).map_err(|_| "the log policy is not text")?;
        let log_policy =
            TrustPolicy::parse(&policy_text).map_err(|e| format!("log policy: {e}"))?;
        let role_max_seconds = role_max_seconds
            .trim()
            .parse()
            .map_err(|_| "the role's maximum session is not a number")?;
        Ok(Self {
            roots,
            log_policy,
            roles,
            role_max_seconds,
        })
    }
}

fn split(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Why a request was refused. Every case is a refusal, and says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not a request this service reads.
    Malformed(String),
    /// Made too long ago, or in the future, by the service's clock.
    Stale {
        /// The request's time.
        time: u64,
        /// The service's.
        now: u64,
    },
    /// A role this broker does not assume.
    Role(String),
    /// The chain, its window or its compilation.
    Plan(PlanError),
    /// Not proven logged under the service's trust policy.
    NotLogged(String),
    /// The warrant's subject is not a key, so no one can prove to be it.
    SubjectNotAKey(String),
    /// The signature is not the subject's over this request.
    NotTheSubject,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed request: {m}"),
            Self::Stale { time, now } => write!(
                f,
                "request made at {time}, the broker's time is {now}: more than {MAX_CLOCK_SKEW_SECONDS} s apart"
            ),
            Self::Role(r) => write!(f, "{r} is not a role this broker assumes"),
            Self::Plan(e) => write!(f, "{e}"),
            Self::NotLogged(e) => write!(f, "not proven logged: {e}"),
            Self::SubjectNotAKey(s) => write!(
                f,
                "the warrant's subject {s} is not a key, so no caller can prove to be it"
            ),
            Self::NotTheSubject => {
                f.write_str("the request is not signed by the warrant's subject key")
            }
        }
    }
}

impl std::error::Error for Refusal {}

/// A request the service accepted: the session to open, and where the chain is logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    /// The session's plan.
    pub plan: SessionPlan,
    /// The role to assume.
    pub role: String,
    /// The log the chain is proven in, and its size then.
    pub logged_origin: String,
    /// The checkpoint's size.
    pub logged_size: u64,
}

/// The bytes the subject signs: every field of the request, the chain by its hash.
fn message(warrant_id: &str, role: &str, time: u64, nonce: &str, chain: &[u8]) -> Vec<u8> {
    let digest = hex(&Sha256::digest(chain));
    format!(
        "{FORMAT}\nwarrant {warrant_id}\nrole {role}\ntime {time}\nnonce {nonce}\nchain {digest}\n"
    )
    .into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N.saturating_mul(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Makes a request for `role` under `chain`, signed by `agent`, the key the leaf warrant
/// names as its subject.
///
/// # Errors
///
/// An empty chain, or a key that cannot sign in the request domain.
pub fn sign_request(
    agent: &IssuerKey,
    chain: &[SignedWarrant],
    proof: &str,
    role: &str,
    time: u64,
    nonce: [u8; 16],
) -> Result<BrokerRequest, String> {
    let leaf = chain.last().ok_or("an empty chain")?.warrant();
    let bytes = encode_chain(chain);
    let nonce = hex(&nonce);
    let signature = sign_in_domain(
        agent,
        BROKER_REQUEST_DOMAIN,
        &message(leaf.id().as_str(), role, time, &nonce, &bytes),
    )
    .map_err(|e| e.to_string())?;
    Ok(BrokerRequest {
        format: FORMAT.to_owned(),
        chain: base64::encode(&bytes),
        proof: proof.to_owned(),
        role: role.to_owned(),
        time,
        nonce,
        signature: hex(&signature),
    })
}

/// Decides a request at `now` from the service's own configuration (SPEC section 8.4):
/// the request is fresh; the role is one this broker assumes; the chain verifies to a root
/// the service trusts and plans a session exactly (as [`plan`]); it is proven logged under
/// the service's trust policy; and the request is signed by the leaf warrant's subject key.
///
/// # Errors
///
/// The first of those that fails, as a [`Refusal`].
pub fn authorize(
    req: &BrokerRequest,
    cfg: &ServiceConfig,
    now: u64,
) -> Result<Authorized, Refusal> {
    if req.format != FORMAT {
        return Err(Refusal::Malformed(format!("format {:?}", req.format)));
    }
    if req.time.abs_diff(now) > MAX_CLOCK_SKEW_SECONDS {
        return Err(Refusal::Stale {
            time: req.time,
            now,
        });
    }
    if !cfg.roles.contains(&req.role) {
        return Err(Refusal::Role(req.role.clone()));
    }
    if unhex::<16>(&req.nonce).is_none() {
        return Err(Refusal::Malformed(
            "the nonce is not 16 bytes of lowercase hex".into(),
        ));
    }
    let bytes = base64::decode(&req.chain)
        .ok_or_else(|| Refusal::Malformed("the chain is not base64".into()))?;
    let chain = decode_chain(&bytes).map_err(|e| Refusal::Malformed(format!("the chain: {e}")))?;
    let planned = plan(&chain, &cfg.roots, now, cfg.role_max_seconds).map_err(Refusal::Plan)?;
    let logged = LoggedProof::parse(&req.proof)
        .map_err(|e| Refusal::NotLogged(e.to_string()))?
        .verify(&chain, &cfg.log_policy)
        .map_err(|e| Refusal::NotLogged(e.to_string()))?;
    let subject = KeyId::parse(&planned.subject)
        .map_err(|_| Refusal::SubjectNotAKey(planned.subject.clone()))?;
    let signature = unhex::<64>(&req.signature).ok_or(Refusal::NotTheSubject)?;
    let signed = message(
        planned.warrant_id.as_str(),
        &req.role,
        req.time,
        &req.nonce,
        &bytes,
    );
    verify_in_domain(&subject, BROKER_REQUEST_DOMAIN, &signed, &signature)
        .map_err(|_| Refusal::NotTheSubject)?;
    Ok(Authorized {
        plan: planned,
        role: req.role.clone(),
        logged_origin: logged.checkpoint.origin().to_owned(),
        logged_size: logged.checkpoint.size(),
    })
}
