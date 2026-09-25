//! The witness over real HTTP on localhost: a log reaches it through `HttpWitness`, and
//! every status tlog-witness assigns comes back as the specification says.

#![allow(
    // Test code: a panic is how a test reports failure (ADR 0002 keeps these for library code).
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};

use remit_core::{IssuerKey, Warrant, WarrantSpec};
use remit_log::{Checkpoint, Entry, KeyKind, NoteSigner, TrustPolicy, open};
use remit_logstore::{Cosigner, LocalWitness, Log};
use remit_witness::{HttpWitness, serve};

const ORIGIN: &str = "log.example.com/remit-test";

fn log_key() -> NoteSigner {
    NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[4; 32]).unwrap()
}
fn witness_key() -> NoteSigner {
    NoteSigner::from_seed("witness.example.com/w1", KeyKind::Witness, &[5; 32]).unwrap()
}
fn clock() -> u64 {
    1_790_000_000
}

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Starts a witness on a free local port, on its own runtime; returns its URL and the
/// runtime, which stops the server when dropped.
fn start(state: &Path) -> (String, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let w = LocalWitness::open(
        witness_key(),
        vec![log_key().verifier_key().clone()],
        state,
        clock,
    )
    .unwrap();
    rt.spawn(serve(listener, w));
    (url, rt)
}

fn entries(from: u64, n: u64) -> Vec<Entry> {
    let key = IssuerKey::from_seed(&[1; 32]);
    (from..from + n)
        .map(|i| {
            let w = Warrant::new(&WarrantSpec {
                issuer: key.id().as_str(),
                subject: "agent",
                purpose: "http witness tests",
                not_before: 1_790_000_000 + i,
                not_after: 1_790_003_600 + i,
                grants: &[(&["s3:GetObject"], &["arn:aws:s3:::reports/*"])],
                parent: None,
                max_depth: 0,
            })
            .unwrap();
            Entry::warrant(key.sign(&w).unwrap()).unwrap()
        })
        .collect()
}

fn policy() -> TrustPolicy {
    TrustPolicy {
        log: log_key().verifier_key().clone(),
        witnesses: vec![witness_key().verifier_key().clone()],
        quorum: 1,
    }
}

#[test]
fn a_log_is_cosigned_over_http_and_the_witness_survives_a_restart() {
    let d = dir("http-grow");
    let state = d.join("witness-state");
    let (url, rt) = start(&state);
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    let mut w = HttpWitness::new(&url);
    for (from, n) in [(0, 1), (1, 5), (6, 300)] {
        let out = log.append(&entries(from, n), &mut [&mut w]).unwrap();
        assert!(out.refusals.is_empty(), "{:?}", out.refusals);
        assert_eq!(
            open(&out.checkpoint, &policy()).unwrap().checkpoint.size(),
            from + n
        );
    }
    drop(rt);
    // A new process, the same state file: it carries on from 306.
    let (url, _rt) = start(&state);
    let mut w = HttpWitness::new(&url);
    let out = log.append(&entries(306, 2), &mut [&mut w]).unwrap();
    assert!(out.refusals.is_empty(), "{:?}", out.refusals);
    assert!(std::fs::read_to_string(&state).unwrap().contains(" 308 "));
}

#[test]
fn a_witness_behind_the_log_says_so_and_is_caught_up() {
    let d = dir("http-behind");
    let (url, _rt) = start(&d.join("witness-state"));
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    let mut w = HttpWitness::new(&url);
    log.append(&entries(0, 3), &mut [&mut w]).unwrap();
    // Two appends the witness never saw.
    log.append(&entries(3, 4), &mut []).unwrap();
    log.append(&entries(7, 5), &mut []).unwrap();
    // The log asks from 7; the witness answers 409 with 3; the log retries from 3.
    let out = log.append(&entries(12, 1), &mut [&mut w]).unwrap();
    assert!(out.refusals.is_empty(), "{:?}", out.refusals);
    assert_eq!(
        open(&out.checkpoint, &policy()).unwrap().checkpoint.size(),
        13
    );
}

#[test]
fn a_fork_a_stranger_and_an_unknown_log_are_refused_with_their_statuses() {
    let d = dir("http-refuse");
    let (url, _rt) = start(&d.join("witness-state"));
    let mut w = HttpWitness::new(&url);
    let mut honest = Log::create(&d.join("honest"), log_key()).unwrap();
    honest.append(&entries(0, 4), &mut [&mut w]).unwrap();
    // The same key, another history: 422.
    let mut forked = Log::create(&d.join("forked"), log_key()).unwrap();
    let out = forked.append(&entries(100, 6), &mut [&mut w]).unwrap();
    assert_eq!(out.refusals.len(), 1);
    assert!(
        out.refusals[0].1.contains("not consistent"),
        "{:?}",
        out.refusals
    );

    let body = Checkpoint::new(ORIGIN, 1, [7; 32]).unwrap().body();
    let stranger = NoteSigner::from_seed(ORIGIN, KeyKind::Log, &[9; 32]).unwrap();
    let signed = format!("old 0\n\n{body}\n{}", stranger.sign(&body, 0).unwrap());
    assert_eq!(w.add_checkpoint(&signed).unwrap_err().status(), 403);
    let other = NoteSigner::from_seed("other.example.com/log", KeyKind::Log, &[4; 32]).unwrap();
    let body = Checkpoint::new("other.example.com/log", 1, [7; 32])
        .unwrap()
        .body();
    let unknown = format!("old 0\n\n{body}\n{}", other.sign(&body, 0).unwrap());
    assert_eq!(w.add_checkpoint(&unknown).unwrap_err().status(), 404);
    assert_eq!(w.add_checkpoint("not a request").unwrap_err().status(), 400);
}

#[test]
fn only_post_add_checkpoint_is_served() {
    let d = dir("http-paths");
    let (url, _rt) = start(&d.join("witness-state"));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    assert_eq!(
        agent
            .get(&format!("{url}/add-checkpoint"))
            .call()
            .unwrap()
            .status()
            .as_u16(),
        405
    );
    assert_eq!(
        agent
            .post(&format!("{url}/other"))
            .send("x")
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let big = "x".repeat(remit_witness::MAX_REQUEST_BYTES + 1);
    assert_eq!(
        agent
            .post(&format!("{url}/add-checkpoint"))
            .send(big.as_str())
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    // A 409 carries the size as text/x.tlog.size.
    let body = Checkpoint::new(ORIGIN, 0, remit_log::empty_root())
        .unwrap()
        .body();
    let req = format!("old 5\n\n{body}\n{}", log_key().sign(&body, 0).unwrap());
    let mut r = agent
        .post(&format!("{url}/add-checkpoint"))
        .send(req.as_str())
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "old size above the checkpoint's is a 400"
    );
    let _ = r.body_mut().read_to_string();
    let mut log = Log::create(&d.join("log"), log_key()).unwrap();
    log.append(&entries(0, 2), &mut [&mut HttpWitness::new(&url)])
        .unwrap();
    let body = Checkpoint::new(ORIGIN, 2, [0; 32]).unwrap().body();
    let req = format!("old 1\n\n{body}\n{}", log_key().sign(&body, 0).unwrap());
    let mut r = agent
        .post(&format!("{url}/add-checkpoint"))
        .send(req.as_str())
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    assert_eq!(r.headers().get("content-type").unwrap(), "text/x.tlog.size");
    assert_eq!(r.body_mut().read_to_string().unwrap(), "2\n");
}
