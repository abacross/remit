//! The broker service's decision (SPEC section 8.4): it trusts only its own configuration,
//! and only the warrant's subject can use a warrant. Each refusal is an attack the
//! 2026-09-28 boundary review made, or would have made, against `remit run`.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use remit_broker::PlanError;
use remit_broker::service::{BrokerRequest, Refusal, ServiceConfig, authorize, sign_request};
use remit_core::{IssuerKey, SignedWarrant, Warrant, WarrantSpec};
use remit_log::{Entry, KeyKind, LoggedProof, NoteSigner, base64};
use remit_logstore::{LocalWitness, Log, LogDir};

const NOW: u64 = 1_790_000_600;
const ROLE: &str = "arn:aws:iam::111122223333:role/remit-agent-readonly";
const OTHER_ROLE: &str = "arn:aws:iam::111122223333:role/lodestar-agent";

struct LogKeys {
    origin: &'static str,
    log: [u8; 32],
    witness: [u8; 32],
}

const REAL: LogKeys = LogKeys {
    origin: "log.example.com/remit",
    log: [4; 32],
    witness: [5; 32],
};
/// A log the agent made itself, as in the boundary review's reproduction.
const AGENTS_OWN: LogKeys = LogKeys {
    origin: "agent.example.com/own",
    log: [40; 32],
    witness: [50; 32],
};

impl LogKeys {
    fn log(&self) -> NoteSigner {
        NoteSigner::from_seed(self.origin, KeyKind::Log, &self.log).unwrap()
    }
    fn witness(&self) -> NoteSigner {
        NoteSigner::from_seed("witness.example.com/w", KeyKind::Witness, &self.witness).unwrap()
    }
    fn policy(&self) -> String {
        format!(
            "log {}\nwitness {}\nquorum 1\n",
            self.log().verifier_key().to_vkey(),
            self.witness().verifier_key().to_vkey()
        )
    }
    /// Appends `links` to a fresh log in `name` and returns the proof file's text.
    fn log_and_prove(&self, name: &str, links: &[SignedWarrant]) -> String {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&d);
        let mut w = LocalWitness::open(
            self.witness(),
            vec![self.log().verifier_key().clone()],
            &d.join("witness-state"),
            || NOW,
        )
        .unwrap();
        let mut log = Log::create(&d.join("log"), self.log()).unwrap();
        let entries: Vec<Entry> = links
            .iter()
            .map(|l| Entry::warrant(l.clone()).unwrap())
            .collect();
        log.append(&entries, &mut [&mut w]).unwrap();
        let dir = LogDir::new(&d.join("log"));
        let size = dir.checkpoint(self.log().verifier_key()).unwrap().size();
        let proofs = links
            .iter()
            .map(|l| {
                let i = dir
                    .find(&Entry::warrant(l.clone()).unwrap(), size)
                    .unwrap()
                    .unwrap();
                (i, dir.inclusion_proof(i, size).unwrap())
            })
            .collect();
        LoggedProof {
            links: proofs,
            checkpoint: dir.checkpoint_text().unwrap(),
        }
        .encode()
    }
}

fn root() -> IssuerKey {
    IssuerKey::from_seed(&[1; 32])
}
fn agent() -> IssuerKey {
    IssuerKey::from_seed(&[2; 32])
}

fn warrant(issuer: &IssuerKey, subject: &str, actions: &[&str]) -> Vec<SignedWarrant> {
    let resources: &[&str] = &["*"];
    let grants: [(&[&str], &[&str]); 1] = [(actions, resources)];
    let w = Warrant::new(&WarrantSpec {
        issuer: issuer.id().as_str(),
        subject,
        purpose: "broker service tests",
        not_before: NOW - 600,
        not_after: NOW + 3000,
        grants: &grants,
        parent: None,
        max_depth: 0,
    })
    .unwrap();
    vec![issuer.sign(&w).unwrap()]
}

fn config() -> ServiceConfig {
    ServiceConfig::from_settings(
        root().id().as_str(),
        &base64::encode(REAL.policy().as_bytes()),
        &format!("{ROLE}, {OTHER_ROLE}"),
        "3600",
    )
    .unwrap()
}

fn request(signer: &IssuerKey, chain: &[SignedWarrant], proof: &str) -> BrokerRequest {
    sign_request(signer, chain, proof, ROLE, NOW, [9; 16]).unwrap()
}

#[test]
fn the_subject_with_a_logged_warrant_from_a_trusted_root_gets_a_session() {
    let chain = warrant(&root(), agent().id().as_str(), &["s3:GetBucketLocation"]);
    let proof = REAL.log_and_prove("svc-ok", &chain);
    let ok = authorize(&request(&agent(), &chain, &proof), &config(), NOW).unwrap();
    assert_eq!(ok.plan.warrant_id, chain[0].warrant().id());
    assert_eq!(ok.plan.subject, agent().id().as_str());
    assert_eq!(ok.role, ROLE);
    assert_eq!(
        (ok.logged_origin.as_str(), ok.logged_size),
        (REAL.origin, 1)
    );
    // The request travels as JSON and means the same after.
    let req = request(&agent(), &chain, &proof);
    let back: BrokerRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
    assert_eq!(back, req);
}

#[test]
fn a_warrant_the_agent_signed_and_logged_itself_is_refused() {
    // The boundary review's reproduction: the agent's own root key and its own log.
    let own_root = IssuerKey::from_seed(&[66; 32]);
    let minted = warrant(&own_root, agent().id().as_str(), &["iam:*", "s3:*"]);
    let own_proof = AGENTS_OWN.log_and_prove("svc-minted-own", &minted);
    let r = authorize(&request(&agent(), &minted, &own_proof), &config(), NOW);
    assert!(
        matches!(r, Err(Refusal::Plan(PlanError::Chain(_)))),
        "{r:?}"
    );
    // Even logged in the real log, a root the service does not trust is refused.
    let real_proof = REAL.log_and_prove("svc-minted-real", &minted);
    let r = authorize(&request(&agent(), &minted, &real_proof), &config(), NOW);
    assert!(
        matches!(r, Err(Refusal::Plan(PlanError::Chain(_)))),
        "{r:?}"
    );
    // And a real warrant proven only in the agent's own log is not logged.
    let chain = warrant(&root(), agent().id().as_str(), &["s3:GetBucketLocation"]);
    let own = AGENTS_OWN.log_and_prove("svc-real-in-own", &chain);
    let r = authorize(&request(&agent(), &chain, &own), &config(), NOW);
    assert!(matches!(r, Err(Refusal::NotLogged(_))), "{r:?}");
}

#[test]
fn only_the_warrants_subject_can_use_it() {
    let chain = warrant(&root(), agent().id().as_str(), &["s3:GetBucketLocation"]);
    let proof = REAL.log_and_prove("svc-bearer", &chain);
    // Another agent that found the warrant in the public log.
    let other = IssuerKey::from_seed(&[3; 32]);
    let r = authorize(&request(&other, &chain, &proof), &config(), NOW);
    assert_eq!(r.unwrap_err(), Refusal::NotTheSubject);
    // A subject that is not a key cannot be proven at all.
    let named = warrant(&root(), "agent:runner", &["s3:GetBucketLocation"]);
    let named_proof = REAL.log_and_prove("svc-named", &named);
    let r = authorize(&request(&agent(), &named, &named_proof), &config(), NOW);
    assert!(matches!(r, Err(Refusal::SubjectNotAKey(_))), "{r:?}");
}

#[test]
fn a_signed_request_cannot_be_changed_or_replayed_later() {
    let chain = warrant(&root(), agent().id().as_str(), &["s3:GetBucketLocation"]);
    let proof = REAL.log_and_prove("svc-tamper", &chain);
    let good = request(&agent(), &chain, &proof);
    let cfg = config();
    let changed = |edit: &dyn Fn(&mut BrokerRequest)| {
        let mut r = good.clone();
        edit(&mut r);
        authorize(&r, &cfg, NOW)
    };
    // Another role the broker does assume, or another nonce: not what was signed.
    assert_eq!(
        changed(&|r| r.role = OTHER_ROLE.to_owned()).unwrap_err(),
        Refusal::NotTheSubject
    );
    assert_eq!(
        changed(&|r| r.nonce = "00".repeat(16)).unwrap_err(),
        Refusal::NotTheSubject
    );
    // A role the broker does not assume, however it is signed.
    let elsewhere = sign_request(
        &agent(),
        &chain,
        &proof,
        "arn:aws:iam::111122223333:role/admin",
        NOW,
        [9; 16],
    )
    .unwrap();
    assert!(matches!(
        authorize(&elsewhere, &cfg, NOW),
        Err(Refusal::Role(_))
    ));
    // Replayed more than a minute later, or sent from the future.
    assert!(matches!(
        authorize(&good, &cfg, NOW + 61),
        Err(Refusal::Stale { .. })
    ));
    assert!(matches!(
        authorize(&good, &cfg, NOW - 61),
        Err(Refusal::Stale { .. })
    ));
    assert!(authorize(&good, &cfg, NOW + 60).is_ok());
    // Not a request at all.
    assert!(matches!(
        changed(&|r| r.format = "v0".into()),
        Err(Refusal::Malformed(_))
    ));
    assert!(matches!(
        changed(&|r| r.chain = "!".into()),
        Err(Refusal::Malformed(_))
    ));
}

#[test]
fn a_configuration_needs_roots_roles_and_a_real_policy() {
    let policy = base64::encode(REAL.policy().as_bytes());
    assert!(ServiceConfig::from_settings("", &policy, ROLE, "3600").is_err());
    assert!(ServiceConfig::from_settings(root().id().as_str(), &policy, "", "3600").is_err());
    assert!(
        ServiceConfig::from_settings(root().id().as_str(), "not base64", ROLE, "3600").is_err()
    );
    let zero = base64::encode(
        format!("log {}\nquorum 0\n", REAL.log().verifier_key().to_vkey()).as_bytes(),
    );
    assert!(ServiceConfig::from_settings(root().id().as_str(), &zero, ROLE, "3600").is_err());
    assert!(ServiceConfig::from_settings(root().id().as_str(), &policy, ROLE, "an hour").is_err());
}
