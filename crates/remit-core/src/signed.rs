//! Keys, signed warrants and chains (SPEC section 5, ADR 0003).
//!
//! A key's identifier is the key: `ed25519:` and the 32-byte public key in lowercase
//! base32. A signed warrant is its canonical encoding and an Ed25519 signature over exactly
//! those bytes, checked with strict verification. A chain runs from a trusted root to the
//! warrant being used and is valid only if every link's signature and attenuation hold.

use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::attenuation::{AttenuationError, check as check_attenuation};
use crate::decode::DecodeError;
use crate::encoding::{base32_lower, base32_lower_decode};
use crate::warrant::Warrant;

/// Prefix of every key identifier.
pub const KEY_PREFIX: &str = "ed25519:";
/// Length of a signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Why a key, a signature or a chain was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Not `ed25519:` and 52 base32 characters naming a valid public key.
    KeyId(String),
    /// The warrant's issuer is not the key asked to sign it.
    WrongSigner {
        /// The warrant's issuer.
        issuer: String,
        /// The key that was asked to sign.
        key: String,
    },
    /// The warrant bytes did not decode.
    Decode(DecodeError),
    /// Transport bytes shorter than a signature.
    Truncated,
    /// The signature does not verify under the issuer's key, strictly.
    BadSignature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyId(s) => write!(f, "{s:?} is not an Ed25519 key identifier"),
            Self::WrongSigner { issuer, key } => {
                write!(
                    f,
                    "warrant issuer is {issuer}, but the signing key is {key}"
                )
            }
            Self::Decode(e) => write!(f, "{e}"),
            Self::Truncated => f.write_str("shorter than a signature"),
            Self::BadSignature => f.write_str("signature does not verify"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// A self-certifying key identifier (SPEC section 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId {
    text: String,
    key: VerifyingKey,
}

impl KeyId {
    /// Parses `ed25519:` and 52 base32 characters, refusing any other spelling of a key.
    ///
    /// # Errors
    ///
    /// The wrong prefix, invalid or non-canonical base32, or bytes that are not a public key.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        let bad = || SignatureError::KeyId(text.to_owned());
        let encoded = text.strip_prefix(KEY_PREFIX).ok_or_else(bad)?;
        let bytes = base32_lower_decode(encoded).ok_or_else(bad)?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| bad())?;
        let key = VerifyingKey::from_bytes(&array).map_err(|_| bad())?;
        Ok(Self {
            text: text.to_owned(),
            key,
        })
    }

    fn from_key(key: VerifyingKey) -> Self {
        Self {
            text: format!("{KEY_PREFIX}{}", base32_lower(key.as_bytes())),
            key,
        }
    }

    /// The identifier as written in a warrant's `issuer` or `subject`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// A key that signs warrants. `remit-core` has no randomness: the caller supplies the
/// 32-byte seed, and generates it with a cryptographically secure source (ADR 0003).
pub struct IssuerKey {
    signing: SigningKey,
    id: KeyId,
}

impl fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        f.debug_struct("IssuerKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl IssuerKey {
    /// A key from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let id = KeyId::from_key(signing.verifying_key());
        Self { signing, id }
    }

    /// This key's identifier, to put in a warrant's `issuer` (or `subject`, to receive one).
    #[must_use]
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// Signs a warrant this key issued.
    ///
    /// # Errors
    ///
    /// The warrant's issuer is not this key: a key signs only what it issues.
    pub fn sign(&self, warrant: &Warrant) -> Result<SignedWarrant, SignatureError> {
        if warrant.issuer().as_str() != self.id.as_str() {
            return Err(SignatureError::WrongSigner {
                issuer: warrant.issuer().as_str().to_owned(),
                key: self.id.as_str().to_owned(),
            });
        }
        let bytes = warrant.canonical_bytes();
        let signature = self.signing.sign(&bytes).to_bytes();
        Ok(SignedWarrant {
            warrant: warrant.clone(),
            bytes,
            signature,
        })
    }
}

/// A warrant with a verified signature by its issuer (SPEC section 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWarrant {
    warrant: Warrant,
    bytes: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
}

impl SignedWarrant {
    /// Verifies a canonical encoding and its signature; the only way to obtain a
    /// `SignedWarrant` from bytes.
    ///
    /// # Errors
    ///
    /// Bytes that do not decode, an issuer that is not a key identifier, or a signature that
    /// does not verify strictly under it.
    pub fn verify(bytes: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<Self, SignatureError> {
        let warrant = Warrant::from_canonical_bytes(bytes).map_err(SignatureError::Decode)?;
        let key = KeyId::parse(warrant.issuer().as_str())?;
        key.key
            .verify_strict(bytes, &Signature::from_bytes(signature))
            .map_err(|_| SignatureError::BadSignature)?;
        Ok(Self {
            warrant,
            bytes: bytes.to_vec(),
            signature: *signature,
        })
    }

    /// The transport form (SPEC section 5.5): the canonical encoding, then the signature.
    #[must_use]
    pub fn to_transport(&self) -> Vec<u8> {
        let mut out = self.bytes.clone();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Reads and verifies the transport form.
    ///
    /// # Errors
    ///
    /// As [`SignedWarrant::verify`], or input shorter than a signature.
    pub fn from_transport(bytes: &[u8]) -> Result<Self, SignatureError> {
        let split = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(SignatureError::Truncated)?;
        let (body, sig) = bytes.split_at(split);
        let sig: [u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| SignatureError::Truncated)?;
        Self::verify(body, &sig)
    }

    /// The warrant, whose signature has been verified.
    #[must_use]
    pub fn warrant(&self) -> &Warrant {
        &self.warrant
    }
}

/// Why a chain was refused (SPEC section 5.3). The index is the link at fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// No links at all.
    Empty,
    /// The first link names a parent, so it is not a root.
    RootHasParent,
    /// The first link's issuer is not a trusted root.
    UntrustedRoot(String),
    /// Link `index` is not a valid attenuation of the link before it.
    Attenuation {
        /// Index of the offending link.
        index: usize,
        /// The rule it broke.
        error: AttenuationError,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty chain"),
            Self::RootHasParent => f.write_str("the first warrant names a parent"),
            Self::UntrustedRoot(k) => write!(f, "root issuer {k} is not trusted"),
            Self::Attenuation { index, error } => write!(f, "link {index}: {error}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verifies a chain and returns the warrant whose authority it confers: the last one.
///
/// Every link's signature was verified when it became a [`SignedWarrant`]; this checks
/// the root against `roots` and every link's attenuation of the one before (SPEC 5.3).
///
/// # Errors
///
/// The first rule the chain breaks. A verifier never uses a prefix of an invalid chain.
pub fn verify_chain<'a>(
    links: &'a [SignedWarrant],
    roots: &[KeyId],
) -> Result<&'a Warrant, ChainError> {
    let root = links.first().ok_or(ChainError::Empty)?.warrant();
    if root.parent().is_some() {
        return Err(ChainError::RootHasParent);
    }
    if !roots.iter().any(|k| k.as_str() == root.issuer().as_str()) {
        return Err(ChainError::UntrustedRoot(root.issuer().as_str().to_owned()));
    }
    for (index, pair) in links.windows(2).enumerate() {
        if let [parent, child] = pair {
            check_attenuation(parent.warrant(), child.warrant()).map_err(|error| {
                ChainError::Attenuation {
                    index: index.saturating_add(1),
                    error,
                }
            })?;
        }
    }
    Ok(links.last().map_or(root, SignedWarrant::warrant))
}

/// First bytes of a chain in transport (SPEC section 5.5).
pub const CHAIN_MAGIC: &[u8; 8] = b"REMITCv1";
/// The most links a chain may carry.
pub const MAX_CHAIN: usize = 16;

/// Encodes a chain for transport (SPEC section 5.5).
#[must_use]
pub fn encode_chain(links: &[SignedWarrant]) -> Vec<u8> {
    let mut out = CHAIN_MAGIC.to_vec();
    out.extend_from_slice(&u32::try_from(links.len()).unwrap_or(u32::MAX).to_be_bytes());
    for link in links {
        let t = link.to_transport();
        out.extend_from_slice(&u32::try_from(t.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&t);
    }
    out
}

/// Decodes a chain from transport, verifying every link's signature. Whether the chain is
/// valid as a chain is [`verify_chain`]'s question, not this one's.
///
/// # Errors
///
/// A wrong magic, a count over [`MAX_CHAIN`], a length past the end, trailing bytes, or
/// any link that is not a valid signed warrant.
pub fn decode_chain(bytes: &[u8]) -> Result<Vec<SignedWarrant>, SignatureError> {
    let rest = bytes
        .strip_prefix(CHAIN_MAGIC.as_slice())
        .ok_or(SignatureError::Truncated)?;
    let (count, mut rest) = split_u32(rest)?;
    if count > MAX_CHAIN {
        return Err(SignatureError::Truncated);
    }
    let mut links = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, tail) = split_u32(rest)?;
        if tail.len() < len {
            return Err(SignatureError::Truncated);
        }
        let (link, tail) = tail.split_at(len);
        links.push(SignedWarrant::from_transport(link)?);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(SignatureError::Truncated);
    }
    Ok(links)
}

fn split_u32(bytes: &[u8]) -> Result<(usize, &[u8]), SignatureError> {
    if bytes.len() < 4 {
        return Err(SignatureError::Truncated);
    }
    let (head, tail) = bytes.split_at(4);
    let n = u32::from_be_bytes(head.try_into().map_err(|_| SignatureError::Truncated)?);
    Ok((
        usize::try_from(n).map_err(|_| SignatureError::Truncated)?,
        tail,
    ))
}
