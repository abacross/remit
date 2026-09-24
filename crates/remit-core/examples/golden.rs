//! Prints the golden vector used by `tests/identity.rs`: run it only to regenerate the
//! vector after a deliberate, versioned change to SPEC section 3.6.
use std::fmt::Write as _;

use remit_core::{Warrant, WarrantSpec};

fn main() -> Result<(), remit_core::WarrantError> {
    let grants: &[(&[&str], &[&str])] = &[(
        &["s3:GetObject", "s3:ListBucket"],
        &["arn:aws:s3:::reports", "arn:aws:s3:::reports/*"],
    )];
    let w = Warrant::new(&WarrantSpec {
        issuer: "key:alice",
        subject: "agent:runner",
        purpose: "read the September reports",
        not_before: 1_790_000_000,
        not_after: 1_790_003_600,
        grants,
        parent: None,
        max_depth: 1,
    })?;
    let hex = w
        .canonical_bytes()
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
    println!("{hex}\n{}", w.id());
    Ok(())
}
