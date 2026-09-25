//! `remit approve`: one request through an approver (SPEC section 10).
//!
//! The approver's key holds a bound from a human. The risk band comes from AWS's service
//! reference when one is given; the model, when there is one, is any server that speaks
//! the System One wire format: jeff on this machine, or `TypeSafe`'s Jev. Its API key is read
//! from an environment variable, never from the command line. Exit codes: 0 issued, 3
//! escalated to a person, 4 refused.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use remit_approver::reference::{Referenced, ServiceReference};
use remit_approver::system_one::{parse_response, request_body};
use remit_approver::{Assessment, Band, Config, Decider, Outcome, Request, decide};
use remit_core::encode_chain;

use crate::{Result, now, read_chain, read_seed, roots, verify_chain, write_new};

#[derive(Args)]
pub(crate) struct ApproveArgs {
    /// The approver's seed file: the key the bound names as subject.
    #[arg(long)]
    key: PathBuf,
    /// The chain whose last warrant is the human's bound for this approver.
    #[arg(long)]
    bound: PathBuf,
    /// Trusted root key identifiers for the bound's chain.
    #[arg(long = "root", required = true)]
    roots: Vec<String>,
    /// The requesting agent's identifier.
    #[arg(long)]
    agent: String,
    /// One concrete action.
    #[arg(long)]
    action: String,
    /// One concrete resource.
    #[arg(long)]
    resource: String,
    /// Seconds asked for.
    #[arg(long, default_value_t = 1200)]
    seconds: u64,
    /// The agent's purpose.
    #[arg(long, default_value = "")]
    purpose: String,
    /// Untrusted context shown to the decider.
    #[arg(long, default_value = "")]
    context: String,
    /// A directory of AWS service reference files (`remit reference fetch`): the risk band
    /// is then AWS's own, not a model's.
    #[arg(long)]
    service_reference: Option<PathBuf>,
    /// Base URL of a System One server, such as `http://127.0.0.1:8000`; with a service
    /// reference it answers only whether a read is safe unreviewed.
    #[arg(long, requires = "decider_model")]
    decider_url: Option<String>,
    /// The model to ask for.
    #[arg(long)]
    decider_model: Option<String>,
    /// The decider's name in evidence.
    #[arg(long, default_value = "system-one")]
    decider_name: String,
    /// The environment variable holding the decider's API key.
    #[arg(long, default_value = "TYPESAFE_API_KEY")]
    decider_key_env: String,
    /// The lowest probability of safety approved without a person.
    #[arg(long, default_value_t = 0.9)]
    threshold: f64,
    /// Where to write the chain (bound plus the approval) when issued.
    #[arg(long)]
    out: PathBuf,
    /// The decision log, one JSON line per decision, appended.
    #[arg(long)]
    decisions: PathBuf,
}

/// A decider reached over HTTP.
struct SystemOne {
    name: String,
    url: String,
    model: String,
    key: Option<String>,
    agent: ureq::Agent,
}

impl Decider for SystemOne {
    fn name(&self) -> &str {
        &self.name
    }

    fn assess(&mut self, state_json: &str) -> std::result::Result<Assessment, String> {
        let url = format!("{}/v1/systemone", self.url.trim_end_matches('/'));
        let mut req = self
            .agent
            .post(&url)
            .header("content-type", "application/json");
        if let Some(k) = &self.key {
            req = req.header("authorization", &format!("Bearer {k}"));
        }
        let mut resp = req
            .send(request_body(&self.model, state_json))
            .map_err(|e| e.to_string())?;
        let body = resp
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_string()
            .map_err(|e| e.to_string())?;
        parse_response(&body)
    }
}

/// The reference for the request's service only: `<dir>/<service>.json`. A service with no
/// file loads nothing, and the approver escalates what it cannot classify.
fn load_reference(dir: &std::path::Path, action: &str) -> ServiceReference {
    let mut reference = ServiceReference::new();
    let service = action
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let safe = !service.is_empty()
        && service
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-');
    if safe
        && let Ok(json) = std::fs::read_to_string(dir.join(format!("{service}.json")))
        && let Err(e) = reference.add_service(&json)
    {
        eprintln!("remit: {service}.json: {e}");
    }
    reference
}

/// `remit reference fetch`: AWS's service reference files, from AWS's public endpoint.
pub(crate) fn fetch_reference(out: &std::path::Path, services: &[String]) -> Result<()> {
    let base = "https://servicereference.us-east-1.amazonaws.com";
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(true)
        .build()
        .into();
    let get = |url: &str| -> Result<String> {
        agent
            .get(url)
            .call()
            .map_err(|e| format!("{url}: {e}"))?
            .body_mut()
            .with_config()
            .limit(16 << 20)
            .read_to_string()
            .map_err(|e| format!("{url}: {e}"))
    };
    let index: serde_json::Value =
        serde_json::from_str(&get(&format!("{base}/"))?).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut n = 0usize;
    for entry in index.as_array().ok_or("the index is not a list")? {
        let (Some(name), Some(url)) = (
            entry.get("service").and_then(serde_json::Value::as_str),
            entry.get("url").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        if !services.is_empty() && !services.iter().any(|s| s.eq_ignore_ascii_case(name)) {
            continue;
        }
        if !url.starts_with(base) || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(format!("unexpected index entry for {name}: {url}"));
        }
        let body = get(url)?;
        // Checked before it is kept: every action must carry its flags.
        ServiceReference::new()
            .add_service(&body)
            .map_err(|e| format!("{name}: {e}"))?;
        std::fs::write(out.join(format!("{name}.json")), body).map_err(|e| e.to_string())?;
        n = n.saturating_add(1);
    }
    eprintln!("remit: {n} service reference files in {}", out.display());
    Ok(())
}

pub(crate) fn command(args: &ApproveArgs) -> Result<ExitCode> {
    if !(0.0..=1.0).contains(&args.threshold) {
        return Err("--threshold must be in [0, 1]".into());
    }
    let key = read_seed(&args.key)?;
    let links = read_chain(&args.bound)?;
    let bound = verify_chain(&links, &roots(&args.roots)?)
        .map_err(|e| format!("the bound does not verify: {e}"))?
        .clone();
    let config = Config {
        threshold: args.threshold,
        allowed_bands: vec![Band::ReadOnly],
        ..Config::default()
    };
    let request = Request {
        agent: args.agent.clone(),
        action: args.action.clone(),
        resource: args.resource.clone(),
        seconds: args.seconds,
        purpose: args.purpose.clone(),
        context: args.context.clone(),
    };
    let mut model = match (&args.decider_url, &args.decider_model) {
        (Some(url), Some(model)) => Some(SystemOne {
            name: args.decider_name.clone(),
            url: url.clone(),
            model: model.clone(),
            key: std::env::var(&args.decider_key_env).ok(),
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(10)))
                .http_status_as_error(true)
                .build()
                .into(),
        }),
        _ => None,
    };
    let (outcome, record) = if let Some(dir) = &args.service_reference {
        let reference = load_reference(dir, &request.action);
        let inner = model.as_mut().map(|m| m as &mut dyn Decider);
        let mut d = Referenced::new(&reference, inner);
        decide(&bound, &key, &config, &request, &mut d, now())
    } else {
        let m = model
            .as_mut()
            .ok_or("give --service-reference, --decider-url, or both")?;
        decide(&bound, &key, &config, &request, m, now())
    };

    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.decisions)
        .map_err(|e| format!("{}: {e}", args.decisions.display()))?;
    writeln!(log, "{}", record.to_json())
        .map_err(|e| format!("{}: {e}", args.decisions.display()))?;

    match outcome {
        Outcome::Issued(child) => {
            let id = child.warrant().id();
            let purpose = child.warrant().purpose().to_owned();
            let mut chain = links;
            chain.push(*child);
            write_new(&args.out, &encode_chain(&chain))?;
            println!("issued: {id}");
            println!("{purpose}");
            Ok(ExitCode::SUCCESS)
        }
        Outcome::Escalated(why) => {
            println!("escalated to a person: {why}");
            Ok(ExitCode::from(3))
        }
        Outcome::Refused(why) => {
            println!("refused: {why}");
            Ok(ExitCode::from(4))
        }
    }
}
