//! A Remit witness over HTTP (c2sp.org/tlog-witness), and the client a log uses to reach
//! one (SPEC section 9.2).
//!
//! The server answers `POST <prefix>/add-checkpoint` exactly as the specification assigns:
//! 200 with the cosignature lines; 404 for a log it does not follow; 403 when the log's
//! signature is missing or fails; 400 for a malformed request; 409, with its last cosigned
//! size as `text/x.tlog.size`, when the old size is not that size; 422 when the checkpoint
//! is not consistent with what it cosigned before. Requests are handled one at a time
//! under a lock, and the state is durable before any cosignature leaves, so no two
//! requests can race the witness into cosigning a fork.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use remit_log::WitnessError;
use remit_logstore::{Cosigner, LocalWitness};

/// The largest request accepted: a checkpoint with many signatures and 63 proof lines fit
/// in far less.
pub const MAX_REQUEST_BYTES: usize = 262_144;

fn reply(status: StatusCode, content_type: &str, body: String) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    if let Ok(v) = content_type.parse() {
        r.headers_mut().insert(hyper::header::CONTENT_TYPE, v);
    }
    r
}

/// The response to one `add-checkpoint` body, as tlog-witness assigns it.
fn respond(witness: &Mutex<LocalWitness>, body: &str) -> Response<Full<Bytes>> {
    let outcome = match witness.lock() {
        Ok(mut w) => w.add_checkpoint(body),
        Err(_) => Err(WitnessError::BadRequest("witness unavailable")),
    };
    match outcome {
        Ok(lines) => reply(StatusCode::OK, "text/plain; charset=utf-8", lines),
        Err(WitnessError::Conflict(size)) => reply(
            StatusCode::CONFLICT,
            "text/x.tlog.size",
            format!("{size}\n"),
        ),
        Err(e) => {
            let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST);
            reply(status, "text/plain; charset=utf-8", format!("{e}\n"))
        }
    }
}

async fn handle(
    witness: Arc<Mutex<LocalWitness>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let plain = "text/plain; charset=utf-8";
    if req.uri().path() != "/add-checkpoint" {
        return Ok(reply(StatusCode::NOT_FOUND, plain, "not found\n".into()));
    }
    if req.method() != Method::POST {
        return Ok(reply(
            StatusCode::METHOD_NOT_ALLOWED,
            plain,
            "POST only\n".into(),
        ));
    }
    let Ok(collected) = Limited::new(req.into_body(), MAX_REQUEST_BYTES)
        .collect()
        .await
    else {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            plain,
            "request too large or unreadable\n".into(),
        ));
    };
    let Ok(body) = String::from_utf8(collected.to_bytes().to_vec()) else {
        return Ok(reply(StatusCode::BAD_REQUEST, plain, "not UTF-8\n".into()));
    };
    // The witness writes its state to disk before replying: off the async threads.
    let response = tokio::task::spawn_blocking(move || respond(&witness, &body))
        .await
        .unwrap_or_else(|_| {
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                plain,
                "witness failed\n".into(),
            )
        });
    Ok(response)
}

/// Serves a witness on `listener` until the task is dropped or the listener fails.
///
/// # Errors
///
/// Accepting a connection failed.
pub async fn serve(
    listener: tokio::net::TcpListener,
    witness: LocalWitness,
) -> std::io::Result<()> {
    let witness = Arc::new(Mutex::new(witness));
    loop {
        let (stream, _) = listener.accept().await?;
        let w = Arc::clone(&witness);
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(Arc::clone(&w), req));
            // A connection that errors affects only itself.
            let _ = http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// A witness reached over HTTP, as a log's cosigner.
pub struct HttpWitness {
    url: String,
    agent: ureq::Agent,
}

impl HttpWitness {
    /// A witness at `url`, its submission prefix (`add-checkpoint` is appended).
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(20)))
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }
}

impl Cosigner for HttpWitness {
    fn name(&self) -> String {
        self.url.clone()
    }

    fn add_checkpoint(&mut self, request: &str) -> Result<String, WitnessError> {
        let mut resp = self
            .agent
            .post(&format!("{}/add-checkpoint", self.url))
            .header("content-type", "text/plain; charset=utf-8")
            .send(request)
            .map_err(|_| WitnessError::BadRequest("witness unreachable"))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_string()
            .map_err(|_| WitnessError::BadRequest("unreadable witness response"))?;
        match status {
            200 => Ok(body),
            409 => body
                .trim_end_matches('\n')
                .parse::<u64>()
                .map(WitnessError::Conflict)
                .map_or(
                    Err(WitnessError::BadRequest("unreadable 409 from witness")),
                    Err,
                ),
            404 => Err(WitnessError::UnknownOrigin),
            403 => Err(WitnessError::Forbidden),
            422 => Err(WitnessError::Unprocessable(
                "the witness found the checkpoint inconsistent",
            )),
            _ => Err(WitnessError::BadRequest("the witness refused the request")),
        }
    }
}
