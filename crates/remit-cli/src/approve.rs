//! `remit approve`: one request through an approver (SPEC section 10).
//!
//! The approver's key holds a bound from a human. The decider is any server that speaks
//! the System One wire format: jeff on this machine, or `TypeSafe`'s Jev. Its API key is read
//! from an environment variable, never from the command line. Exit codes: 0 issued, 3
//! escalated to a person, 4 refused.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
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
    /// Base URL of a System One server, such as `http://127.0.0.1:8000`.
    #[arg(long)]
    decider_url: String,
    /// The model to ask for.
    #[arg(long)]
    decider_model: String,
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
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(true)
        .build()
        .into();
    let mut decider = SystemOne {
        name: args.decider_name.clone(),
        url: args.decider_url.clone(),
        model: args.decider_model.clone(),
        key: std::env::var(&args.decider_key_env).ok(),
        agent,
    };
    let (outcome, record) = decide(&bound, &key, &config, &request, &mut decider, now());

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
