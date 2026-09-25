//! Signed notes (c2sp.org/signed-note) with Ed25519 log signatures (type `0x01`), and
//! timestamped witness cosignatures (c2sp.org/tlog-cosignature) in Ed25519 (type `0x04`)
//! or ML-DSA-44 (type `0x06`), the post-quantum form the specification recommends for new
//! deployments. ML-DSA-44 is AWS-LC's (ADR 0007).
//!
//! A note is text followed by a blank line and one signature line per key. Verification
//! follows the specification's rules, taking its "SHOULD" as "MUST": signatures by unknown
//! keys are ignored, a signature by a known key that fails rejects the whole note, and a
//! note with no verified signature is rejected.

use core::fmt;

use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::base64;
use crate::checkpoint::Checkpoint;

/// ML-DSA-44 public keys and signatures, in bytes (FIPS 204).
const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
const ML_DSA_44_SIGNATURE_LEN: usize = 2420;

/// The largest note accepted, in bytes: room for 16 post-quantum signatures, which the
/// specification says a verifier must accept, with margin.
pub const MAX_NOTE_BYTES: usize = 131_072;

/// The most signature lines accepted in one note (the specification's minimum is 16).
pub const MAX_SIGNATURES: usize = 64;

/// The first character of a signature line: U+2014, as the specification requires.
const DASH: char = '\u{2014}';

/// The first line of the message a cosignature signs (c2sp.org/tlog-cosignature).
const COSIGNATURE_HEADER: &str = "cosignature/v1\n";

/// Why a note, key or signature was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteError {
    /// Larger than [`MAX_NOTE_BYTES`], or more than [`MAX_SIGNATURES`] signatures.
    TooLarge,
    /// Not in the note format; the reason says where.
    Malformed(&'static str),
    /// A key name that is empty or contains a space or a plus sign.
    BadKeyName,
    /// A verifier key that does not parse, or whose key identifier does not match.
    BadVerifierKey(&'static str),
    /// A signature by a known key that does not verify.
    BadSignature(String),
    /// No signature by a known key.
    NoTrustedSignature,
}

impl fmt::Display for NoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("note too large"),
            Self::Malformed(why) => write!(f, "malformed note: {why}"),
            Self::BadKeyName => f.write_str("key name is empty or contains a space or '+'"),
            Self::BadVerifierKey(why) => write!(f, "bad verifier key: {why}"),
            Self::BadSignature(name) => write!(f, "signature by {name} does not verify"),
            Self::NoTrustedSignature => f.write_str("no signature by a trusted key"),
        }
    }
}

impl std::error::Error for NoteError {}

/// What a key signs, which fixes its signature type byte and message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// A log's checkpoint signature: Ed25519 over the note text (type `0x01`).
    Log,
    /// A witness cosignature: Ed25519 over the cosignature message, with a timestamp
    /// (type `0x04`).
    Witness,
}

/// A key's signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// ML-DSA-44 (FIPS 204), for witnesses only.
    MlDsa44,
}

/// The signature type byte for a role and algorithm; `None` for a pair no specification
/// defines (a log signs with Ed25519 only).
fn type_byte(kind: KeyKind, algorithm: Algorithm) -> Option<u8> {
    match (kind, algorithm) {
        (KeyKind::Log, Algorithm::Ed25519) => Some(0x01),
        (KeyKind::Witness, Algorithm::Ed25519) => Some(0x04),
        (KeyKind::Witness, Algorithm::MlDsa44) => Some(0x06),
        (KeyKind::Log, Algorithm::MlDsa44) => None,
    }
}

/// A public key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicKey {
    Ed25519(VerifyingKey),
    MlDsa44(Box<[u8]>),
}

impl PublicKey {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(k) => k.as_bytes(),
            Self::MlDsa44(k) => k,
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::MlDsa44(_) => Algorithm::MlDsa44,
        }
    }
}

fn check_name(name: &str) -> Result<(), NoteError> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || c == '+' || c.is_control())
    {
        return Err(NoteError::BadKeyName);
    }
    Ok(())
}

/// The key identifier: the first four bytes of SHA-256(name || 0x0A || type || key).
fn key_id(name: &str, type_byte: u8, key: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([b'\n', type_byte]);
    hasher.update(key);
    let digest: [u8; 32] = hasher.finalize().into();
    let (first, _) = digest.split_first_chunk::<4>().unwrap_or((&[0; 4], &[]));
    u32::from_be_bytes(*first)
}

/// A public key a verifier trusts, with its name and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKey {
    name: String,
    kind: KeyKind,
    id: u32,
    key: PublicKey,
}

impl VerifierKey {
    /// An Ed25519 verifier key from its parts.
    ///
    /// # Errors
    ///
    /// A bad name, or bytes that are not an Ed25519 public key.
    pub fn new(name: &str, kind: KeyKind, public: &[u8; 32]) -> Result<Self, NoteError> {
        let key = VerifyingKey::from_bytes(public)
            .map_err(|_| NoteError::BadVerifierKey("not an Ed25519 public key"))?;
        Self::from_parts(name, kind, PublicKey::Ed25519(key))
    }

    /// An ML-DSA-44 witness's verifier key from its name and 1,312-byte public key.
    ///
    /// # Errors
    ///
    /// A bad name, or a key of the wrong length.
    pub fn ml_dsa_witness(name: &str, public: &[u8]) -> Result<Self, NoteError> {
        if public.len() != ML_DSA_44_PUBLIC_KEY_LEN {
            return Err(NoteError::BadVerifierKey(
                "ML-DSA-44 public key is not 1312 bytes",
            ));
        }
        Self::from_parts(name, KeyKind::Witness, PublicKey::MlDsa44(public.into()))
    }

    fn from_parts(name: &str, kind: KeyKind, key: PublicKey) -> Result<Self, NoteError> {
        check_name(name)?;
        let byte = type_byte(kind, key.algorithm()).ok_or(NoteError::BadVerifierKey(
            "no signature type for this role and algorithm",
        ))?;
        Ok(Self {
            name: name.to_owned(),
            kind,
            id: key_id(name, byte, key.bytes()),
            key,
        })
    }

    /// Parses a verifier key in the specification's text form,
    /// `<name>+<hex key ID>+<base64(type || public key)>`.
    ///
    /// # Errors
    ///
    /// Anything else, an unsupported type, or a key identifier that does not match.
    pub fn parse(vkey: &str) -> Result<Self, NoteError> {
        // Only the first two plus signs separate: base64 uses `+` too.
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(id), Some(material)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(NoteError::BadVerifierKey("not three parts"));
        };
        let id_ok = id.len() == 8 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
        let id =
            u32::from_str_radix(id, 16)
                .ok()
                .filter(|_| id_ok)
                .ok_or(NoteError::BadVerifierKey(
                    "key ID is not 8 lowercase hex digits",
                ))?;
        let material =
            base64::decode(material).ok_or(NoteError::BadVerifierKey("key is not base64"))?;
        let key = match material.split_first() {
            Some((0x01 | 0x04, rest)) => {
                let kind = if material.first() == Some(&0x01) {
                    KeyKind::Log
                } else {
                    KeyKind::Witness
                };
                let public: &[u8; 32] = rest
                    .try_into()
                    .map_err(|_| NoteError::BadVerifierKey("public key is not 32 bytes"))?;
                Self::new(name, kind, public)?
            }
            Some((0x06, rest)) => Self::ml_dsa_witness(name, rest)?,
            _ => return Err(NoteError::BadVerifierKey("unsupported signature type")),
        };
        if key.id != id {
            return Err(NoteError::BadVerifierKey("key ID does not match the key"));
        }
        Ok(key)
    }

    /// The text form.
    #[must_use]
    pub fn to_vkey(&self) -> String {
        let mut material = vec![type_byte(self.kind, self.key.algorithm()).unwrap_or(0)];
        material.extend_from_slice(self.key.bytes());
        format!(
            "{}+{:08x}+{}",
            self.name,
            self.id,
            base64::encode(&material)
        )
    }

    /// The key's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the key signs.
    #[must_use]
    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    /// The key identifier.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Its signature algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    /// The raw public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.key.bytes().to_vec()
    }
}

/// A key that signs notes: a log's key, or a witness's.
pub struct NoteSigner {
    verifier: VerifierKey,
    signing: Signing,
}

enum Signing {
    Ed25519(SigningKey),
    MlDsa44(PqdsaKeyPair),
}

impl fmt::Debug for NoteSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the private key.
        f.debug_struct("NoteSigner")
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl NoteSigner {
    /// A signer from a 32-byte Ed25519 seed. A seed must be used for one kind and one
    /// name only; Remit's issuer, reconciler, log and witness keys are all distinct.
    ///
    /// # Errors
    ///
    /// A bad name.
    pub fn from_seed(name: &str, kind: KeyKind, seed: &[u8; 32]) -> Result<Self, NoteError> {
        let signing = SigningKey::from_bytes(seed);
        let verifier = VerifierKey::new(name, kind, signing.verifying_key().as_bytes())?;
        Ok(Self {
            verifier,
            signing: Signing::Ed25519(signing),
        })
    }

    /// An ML-DSA-44 witness from its 32-byte seed (FIPS 204 key generation from a seed, as
    /// the reference implementations store keys).
    ///
    /// # Errors
    ///
    /// A bad name, or a seed AWS-LC refuses.
    pub fn ml_dsa_witness_from_seed(name: &str, seed: &[u8; 32]) -> Result<Self, NoteError> {
        let pair = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, seed)
            .map_err(|_| NoteError::BadVerifierKey("ML-DSA-44 key generation failed"))?;
        let verifier = VerifierKey::ml_dsa_witness(name, pair.public_key().as_ref())?;
        Ok(Self {
            verifier,
            signing: Signing::MlDsa44(pair),
        })
    }

    /// The matching verifier key.
    #[must_use]
    pub fn verifier_key(&self) -> &VerifierKey {
        &self.verifier
    }

    /// The signature line for `text` (a log key), or for `text` cosigned at `time` (a
    /// witness key; POSIX seconds, at most 2^63 - 1). `time` is ignored for a log key.
    ///
    /// # Errors
    ///
    /// Text that is not note text, or a time out of range.
    pub fn sign(&self, text: &str, time: u64) -> Result<String, NoteError> {
        check_text(text)?;
        let mut sig = self.verifier.id.to_be_bytes().to_vec();
        match (&self.signing, self.verifier.kind) {
            (Signing::Ed25519(k), KeyKind::Log) => {
                sig.extend_from_slice(&k.sign(text.as_bytes()).to_bytes());
            }
            (Signing::Ed25519(k), KeyKind::Witness) => {
                if i64::try_from(time).is_err() {
                    return Err(NoteError::Malformed("timestamp above 2^63 - 1"));
                }
                let message = cosigned_message(text, time);
                sig.extend_from_slice(&time.to_be_bytes());
                sig.extend_from_slice(&k.sign(message.as_bytes()).to_bytes());
            }
            (Signing::MlDsa44(pair), _) => {
                if i64::try_from(time).is_err() {
                    return Err(NoteError::Malformed("timestamp above 2^63 - 1"));
                }
                let message = ml_dsa_message(&self.verifier.name, time, text)?;
                let mut out = vec![0u8; ML_DSA_44_SIGNATURE_LEN];
                let n = pair
                    .sign(&message, &mut out)
                    .map_err(|_| NoteError::Malformed("ML-DSA-44 signing failed"))?;
                sig.extend_from_slice(&time.to_be_bytes());
                sig.extend_from_slice(out.get(..n).unwrap_or_default());
            }
        }
        Ok(format!(
            "{DASH} {} {}\n",
            self.verifier.name,
            base64::encode(&sig)
        ))
    }
}

/// The message an ML-DSA-44 cosignature signs (c2sp.org/tlog-cosignature): the label
/// `subtree/v1\n\0`, the cosigner's name, the time, the log's origin, the subtree
/// `[0, size)` and the root, lengths as one byte and integers big-endian. The checkpoint's
/// extension lines, which Remit refuses anyway, are not covered.
fn ml_dsa_message(cosigner: &str, time: u64, text: &str) -> Result<Vec<u8>, NoteError> {
    let checkpoint = Checkpoint::parse(text)
        .map_err(|_| NoteError::Malformed("an ML-DSA cosignature covers a checkpoint"))?;
    let name = u8::try_from(cosigner.len()).map_err(|_| NoteError::BadKeyName)?;
    let origin = u8::try_from(checkpoint.origin().len())
        .map_err(|_| NoteError::Malformed("origin over 255 bytes"))?;
    let mut m = b"subtree/v1\n\0".to_vec();
    m.push(name);
    m.extend_from_slice(cosigner.as_bytes());
    m.extend_from_slice(&time.to_be_bytes());
    m.push(origin);
    m.extend_from_slice(checkpoint.origin().as_bytes());
    m.extend_from_slice(&0u64.to_be_bytes());
    m.extend_from_slice(&checkpoint.size().to_be_bytes());
    m.extend_from_slice(checkpoint.root());
    Ok(m)
}

fn cosigned_message(text: &str, time: u64) -> String {
    format!("{COSIGNATURE_HEADER}time {time}\n{text}")
}

/// Checks that `text` can be the text of a note: non-empty, ending in a newline, and free
/// of control characters other than newline.
fn check_text(text: &str) -> Result<(), NoteError> {
    if !text.ends_with('\n') {
        return Err(NoteError::Malformed("text does not end in a newline"));
    }
    if text
        .chars()
        .any(|c| c != '\n' && (c < ' ' || c == '\u{7f}'))
    {
        return Err(NoteError::Malformed("control character"));
    }
    Ok(())
}

/// One signature line, not yet verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureLine {
    /// The key name.
    pub name: String,
    /// The key identifier (the first four bytes of the signature).
    pub id: u32,
    /// The rest of the signature: for a witness, the 8-byte timestamp and the signature.
    pub signature: Vec<u8>,
}

/// A signature that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The verifying key.
    pub key: VerifierKey,
    /// For a cosignature, the time the witness signed at.
    pub time: Option<u64>,
}

/// A parsed note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    text: String,
    signatures: Vec<SignatureLine>,
}

impl Note {
    /// Parses a note. Parsing checks the format only; nothing is trusted until
    /// [`Note::verify`].
    ///
    /// # Errors
    ///
    /// Anything that is not a note.
    pub fn parse(note: &str) -> Result<Self, NoteError> {
        if note.len() > MAX_NOTE_BYTES {
            return Err(NoteError::TooLarge);
        }
        let split = note
            .rfind("\n\n")
            .ok_or(NoteError::Malformed("no blank line before the signatures"))?;
        let (text, rest) = note.split_at(split.saturating_add(1));
        check_text(text)?;
        let lines = rest
            .strip_prefix('\n')
            .ok_or(NoteError::Malformed("no blank line"))?;
        if lines.is_empty() {
            return Err(NoteError::Malformed("no signatures"));
        }
        let lines = lines
            .strip_suffix('\n')
            .ok_or(NoteError::Malformed("signatures do not end in a newline"))?;
        let mut signatures = Vec::new();
        for line in lines.split('\n') {
            if signatures.len() == MAX_SIGNATURES {
                return Err(NoteError::TooLarge);
            }
            signatures.push(parse_signature_line(line)?);
        }
        Ok(Self {
            text: text.to_owned(),
            signatures,
        })
    }

    /// The signed text, including its final newline.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The signature lines, unverified.
    #[must_use]
    pub fn signatures(&self) -> &[SignatureLine] {
        &self.signatures
    }

    /// Verifies the signatures by `keys`, and returns those that verified, once per key.
    ///
    /// # Errors
    ///
    /// [`NoteError::BadSignature`] when a signature by a known key fails, which rejects the
    /// whole note; [`NoteError::NoTrustedSignature`] when no known key signed.
    pub fn verify(&self, keys: &[VerifierKey]) -> Result<Vec<Verified>, NoteError> {
        let mut verified: Vec<Verified> = Vec::new();
        for line in &self.signatures {
            for key in keys
                .iter()
                .filter(|k| k.name == line.name && k.id == line.id)
            {
                let time = verify_one(key, &self.text, &line.signature)
                    .map_err(|()| NoteError::BadSignature(key.name.clone()))?;
                if !verified.iter().any(|v| v.key == *key) {
                    verified.push(Verified {
                        key: key.clone(),
                        time,
                    });
                }
            }
        }
        if verified.is_empty() {
            return Err(NoteError::NoTrustedSignature);
        }
        Ok(verified)
    }
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.text)?;
        for line in &self.signatures {
            let mut sig = line.id.to_be_bytes().to_vec();
            sig.extend_from_slice(&line.signature);
            writeln!(f, "{DASH} {} {}", line.name, base64::encode(&sig))?;
        }
        Ok(())
    }
}

fn parse_signature_line(line: &str) -> Result<SignatureLine, NoteError> {
    let rest = line
        .strip_prefix(DASH)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or(NoteError::Malformed(
            "signature line does not start with U+2014 and a space",
        ))?;
    let (name, sig) = rest
        .split_once(' ')
        .ok_or(NoteError::Malformed("signature line has no signature"))?;
    check_name(name)?;
    let sig = base64::decode(sig).ok_or(NoteError::Malformed("signature is not base64"))?;
    match sig.split_first_chunk::<4>() {
        Some((id, signature)) if !signature.is_empty() => Ok(SignatureLine {
            name: name.to_owned(),
            id: u32::from_be_bytes(*id),
            signature: signature.to_vec(),
        }),
        _ => Err(NoteError::Malformed("signature too short")),
    }
}

/// Verifies one signature: `Ok` on success, with the time for a cosignature.
fn verify_one(key: &VerifierKey, text: &str, signature: &[u8]) -> Result<Option<u64>, ()> {
    match (&key.key, key.kind) {
        (PublicKey::Ed25519(k), KeyKind::Log) => {
            let sig: &[u8; 64] = signature.try_into().map_err(drop)?;
            k.verify_strict(text.as_bytes(), &Signature::from_bytes(sig))
                .map_err(drop)?;
            Ok(None)
        }
        (PublicKey::Ed25519(k), KeyKind::Witness) => {
            let (time, sig) = signature.split_first_chunk::<8>().ok_or(())?;
            let sig: &[u8; 64] = sig.try_into().map_err(drop)?;
            let time = u64::from_be_bytes(*time);
            i64::try_from(time).map_err(drop)?;
            let message = cosigned_message(text, time);
            k.verify_strict(message.as_bytes(), &Signature::from_bytes(sig))
                .map_err(drop)?;
            Ok(Some(time))
        }
        (PublicKey::MlDsa44(k), _) => {
            let (time, sig) = signature.split_first_chunk::<8>().ok_or(())?;
            if sig.len() != ML_DSA_44_SIGNATURE_LEN {
                return Err(());
            }
            let time = u64::from_be_bytes(*time);
            i64::try_from(time).map_err(drop)?;
            let message = ml_dsa_message(&key.name, time, text).map_err(drop)?;
            UnparsedPublicKey::new(&ML_DSA_44, k.as_ref())
                .verify(&message, sig)
                .map_err(drop)?;
            Ok(Some(time))
        }
    }
}
