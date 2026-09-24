//! `remit log`: the witnessed log from the command line (SPEC section 9).
//!
//! Keys are seed files like any other Remit key, but each seed serves one purpose only: a
//! log key signs checkpoints, a witness key cosigns them, and neither is ever an issuer.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use remit_log::{Entry, KeyKind, LoggedProof, NoteSigner, TrustPolicy};
use remit_logstore::{Cosigner, LocalWitness, Log, LogDir};

use crate::{Result, now, read_chain, read_report_signature, read_seed_bytes, write_new};

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Kind {
    /// Signs a log's checkpoints.
    Log,
    /// Cosigns checkpoints as a witness.
    Witness,
}

#[derive(Subcommand)]
pub(crate) enum LogCmd {
    /// Print the verifier key (vkey) of a log or witness seed, for a trust policy.
    Vkey {
        /// The seed file.
        #[arg(long)]
        key: PathBuf,
        /// The key's name: the log's origin, or the witness's name.
        #[arg(long)]
        name: String,
        /// What the key signs.
        #[arg(long, value_enum)]
        kind: Kind,
    },
    /// Create an empty log.
    Create(LogKeyArgs),
    /// Append every link of a chain not already in the log, then cosign.
    Append {
        #[command(flatten)]
        log: LogKeyArgs,
        /// The chain whose links to log.
        #[arg(long)]
        chain: PathBuf,
        #[command(flatten)]
        witness: WitnessArgs,
    },
    /// Append a signed reconciliation report (SPEC 9.4), publishing its bytes.
    AppendResult {
        #[command(flatten)]
        log: LogKeyArgs,
        /// The report; its signature is read from `<report>.sig`.
        #[arg(long)]
        report: PathBuf,
        #[command(flatten)]
        witness: WitnessArgs,
    },
    /// Ask the witness to cosign the current checkpoint again.
    Cosign {
        #[command(flatten)]
        log: LogKeyArgs,
        #[command(flatten)]
        witness: WitnessArgs,
    },
    /// Write the proof that every link of a chain is logged, checked under a policy.
    Prove {
        /// The log directory.
        #[arg(long)]
        dir: PathBuf,
        /// The trust policy the proof must satisfy.
        #[arg(long)]
        policy: PathBuf,
        /// The chain.
        #[arg(long)]
        chain: PathBuf,
        /// Where to write the proof.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a proof offline, as the broker does before issuing a session.
    Verify {
        /// The trust policy.
        #[arg(long)]
        policy: PathBuf,
        /// The chain.
        #[arg(long)]
        chain: PathBuf,
        /// The proof.
        #[arg(long)]
        proof: PathBuf,
    },
}

#[derive(Args)]
pub(crate) struct LogKeyArgs {
    /// The log directory.
    #[arg(long)]
    dir: PathBuf,
    /// The log's seed file.
    #[arg(long)]
    key: PathBuf,
    /// The log's origin, which is its key's name.
    #[arg(long)]
    origin: String,
}

#[derive(Args)]
#[allow(
    clippy::struct_field_names,
    reason = "the field names are the flag names, and flattened beside the log's own"
)]
pub(crate) struct WitnessArgs {
    /// A witness run in this process: its seed file.
    #[arg(long, requires_all = ["witness_name", "witness_state"])]
    witness_key: Option<PathBuf>,
    /// The witness's name.
    #[arg(long)]
    witness_name: Option<String>,
    /// The witness's state file, which must survive between runs.
    #[arg(long)]
    witness_state: Option<PathBuf>,
}

fn signer(path: &Path, name: &str, kind: KeyKind) -> Result<NoteSigner> {
    NoteSigner::from_seed(name, kind, &read_seed_bytes(path)?).map_err(|e| e.to_string())
}

fn open_log(args: &LogKeyArgs) -> Result<Log> {
    Log::open(&args.dir, signer(&args.key, &args.origin, KeyKind::Log)?).map_err(|e| e.to_string())
}

fn local_witness(args: &WitnessArgs, log: &Log) -> Result<Option<LocalWitness>> {
    let (Some(key), Some(name), Some(state)) =
        (&args.witness_key, &args.witness_name, &args.witness_state)
    else {
        return Ok(None);
    };
    LocalWitness::open(
        signer(key, name, KeyKind::Witness)?,
        vec![log.verifier_key().clone()],
        state,
        now,
    )
    .map(Some)
    .map_err(|e| e.to_string())
}

fn report(appended: &remit_logstore::Appended, added: usize) {
    eprintln!(
        "remit: {added} entries from index {}; refusals: {}",
        appended.first,
        if appended.refusals.is_empty() {
            "none".to_owned()
        } else {
            appended
                .refusals
                .iter()
                .map(|(who, why)| format!("{who}: {why}"))
                .collect::<Vec<_>>()
                .join("; ")
        }
    );
    print!("{}", appended.checkpoint);
}

fn append(log: &mut Log, entries: &[Entry], witness: &WitnessArgs) -> Result<()> {
    let mut w = local_witness(witness, log)?;
    let mut cosigners: Vec<&mut dyn Cosigner> = Vec::new();
    if let Some(w) = w.as_mut() {
        cosigners.push(w);
    }
    let appended = log
        .append(entries, &mut cosigners)
        .map_err(|e| e.to_string())?;
    report(&appended, entries.len());
    Ok(())
}

pub(crate) fn read_policy(path: &Path) -> Result<TrustPolicy> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    TrustPolicy::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn command(cmd: LogCmd) -> Result<()> {
    match cmd {
        LogCmd::Vkey { key, name, kind } => {
            let kind = match kind {
                Kind::Log => KeyKind::Log,
                Kind::Witness => KeyKind::Witness,
            };
            println!("{}", signer(&key, &name, kind)?.verifier_key().to_vkey());
        }
        LogCmd::Create(args) => {
            let log = Log::create(&args.dir, signer(&args.key, &args.origin, KeyKind::Log)?)
                .map_err(|e| e.to_string())?;
            print!(
                "{}",
                log.dir().checkpoint_text().map_err(|e| e.to_string())?
            );
        }
        LogCmd::Append {
            log,
            chain,
            witness,
        } => {
            let mut l = open_log(&log)?;
            let size = l.current().map_err(|e| e.to_string())?.size();
            let mut entries = Vec::new();
            for link in read_chain(&chain)? {
                let entry = Entry::warrant(link).map_err(|e| e.to_string())?;
                let present = l.dir().find(&entry, size).map_err(|e| e.to_string())?;
                if present.is_none() && !entries.contains(&entry) {
                    entries.push(entry);
                }
            }
            append(&mut l, &entries, &witness)?;
        }
        LogCmd::AppendResult {
            log,
            report: path,
            witness,
        } => {
            let mut l = open_log(&log)?;
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let (key, signature) = read_report_signature(&path)?;
            let entry = Entry::result(&bytes, &key, &signature).map_err(|e| e.to_string())?;
            l.publish_result(&bytes).map_err(|e| e.to_string())?;
            append(&mut l, &[entry], &witness)?;
        }
        LogCmd::Cosign { log, witness } => {
            let mut l = open_log(&log)?;
            let mut w = local_witness(&witness, &l)?.ok_or("no witness given")?;
            let appended = l.cosign_current(&mut [&mut w]).map_err(|e| e.to_string())?;
            report(&appended, 0);
        }
        LogCmd::Prove {
            dir,
            policy,
            chain,
            out,
        } => {
            let policy = read_policy(&policy)?;
            let links = read_chain(&chain)?;
            let d = LogDir::new(&dir);
            let checkpoint = d.checkpoint(&policy.log).map_err(|e| e.to_string())?;
            let size = checkpoint.size();
            let mut proofs = Vec::new();
            for (i, link) in links.iter().enumerate() {
                let entry = Entry::warrant(link.clone()).map_err(|e| e.to_string())?;
                let index = d
                    .find(&entry, size)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("link {i} of the chain is not in the log"))?;
                proofs.push((
                    index,
                    d.inclusion_proof(index, size).map_err(|e| e.to_string())?,
                ));
            }
            let proof = LoggedProof {
                links: proofs,
                checkpoint: d.checkpoint_text().map_err(|e| e.to_string())?,
            };
            // Written only if it would convince the broker.
            proof
                .verify(&links, &policy)
                .map_err(|e| format!("not provable under this policy: {e}"))?;
            write_new(&out, proof.encode().as_bytes())?;
            eprintln!("remit: {} links proven in a log of {size}", links.len());
        }
        LogCmd::Verify {
            policy,
            chain,
            proof,
        } => {
            let trusted = verify_logged(&policy, &chain, &proof)?;
            println!(
                "logged: every link is in {} at size {}, cosigned by {} witness(es)",
                trusted.checkpoint.origin(),
                trusted.checkpoint.size(),
                trusted.cosignatures.len()
            );
        }
    }
    Ok(())
}

/// Verifies that a chain is proven logged under a policy (SPEC section 9.3).
pub(crate) fn verify_logged(
    policy: &Path,
    chain: &Path,
    proof: &Path,
) -> Result<remit_log::TrustedCheckpoint> {
    let policy = read_policy(policy)?;
    let links = read_chain(chain)?;
    let text = std::fs::read_to_string(proof).map_err(|e| format!("{}: {e}", proof.display()))?;
    let proof = LoggedProof::parse(&text).map_err(|e| format!("{}: {e}", proof.display()))?;
    proof
        .verify(&links, &policy)
        .map_err(|e| format!("not logged: {e}"))
}
