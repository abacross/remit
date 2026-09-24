//! Log entries (SPEC section 9.1): a signed warrant, or a commitment to a signed
//! reconciliation result.

use core::fmt;

use remit_core::{KeyId, RESULT_DOMAIN, SignedWarrant, verify_in_domain};
use sha2::{Digest, Sha256};

use crate::merkle::{Hash, leaf_hash};

/// The first 8 bytes of every entry.
pub const ENTRY_MAGIC: &[u8; 8] = b"REMITLv1";

/// The largest entry: what a tile's entry bundle can carry (a 16-bit length prefix).
pub const MAX_ENTRY_BYTES: usize = 65_535;

const KIND_WARRANT: u8 = 0x01;
const KIND_RESULT: u8 = 0x02;

/// Why an entry was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// Larger than [`MAX_ENTRY_BYTES`].
    TooLarge,
    /// Not an entry; the reason says where.
    Malformed(&'static str),
    /// A signature that does not verify.
    BadSignature,
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "entry larger than {MAX_ENTRY_BYTES} bytes"),
            Self::Malformed(why) => write!(f, "malformed entry: {why}"),
            Self::BadSignature => f.write_str("entry signature does not verify"),
        }
    }
}

impl std::error::Error for EntryError {}

/// A log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// One signed warrant, one link of a chain.
    Warrant(SignedWarrant),
    /// A reconciliation result, by its hash, signer and signature.
    Result {
        /// SHA-256 of the result's exact bytes.
        digest: Hash,
        /// The reconciler's key.
        key: KeyId,
        /// The result's signature (SPEC section 6.6).
        signature: [u8; 64],
    },
}

impl Entry {
    /// A warrant entry.
    ///
    /// # Errors
    ///
    /// A warrant too large to log, which therefore cannot be used (SPEC section 9.3).
    pub fn warrant(signed: SignedWarrant) -> Result<Self, EntryError> {
        let entry = Self::Warrant(signed);
        if entry.encode().len() > MAX_ENTRY_BYTES {
            return Err(EntryError::TooLarge);
        }
        Ok(entry)
    }

    /// A result entry, after checking the signature over the result's bytes.
    ///
    /// # Errors
    ///
    /// A signature that does not verify under `key` in the result domain.
    pub fn result(bytes: &[u8], key: &KeyId, signature: &[u8; 64]) -> Result<Self, EntryError> {
        verify_in_domain(key, RESULT_DOMAIN, bytes, signature)
            .map_err(|_| EntryError::BadSignature)?;
        Ok(Self::Result {
            digest: Sha256::digest(bytes).into(),
            key: key.clone(),
            signature: *signature,
        })
    }

    /// Checks that `bytes` are the result this entry commits to, signed as it says.
    ///
    /// # Errors
    ///
    /// Not a result entry, other bytes, or a signature that does not verify.
    pub fn check_result(&self, bytes: &[u8]) -> Result<(), EntryError> {
        let Self::Result {
            digest,
            key,
            signature,
        } = self
        else {
            return Err(EntryError::Malformed("not a result entry"));
        };
        let actual: Hash = Sha256::digest(bytes).into();
        if actual != *digest {
            return Err(EntryError::Malformed("result bytes do not match the entry"));
        }
        verify_in_domain(key, RESULT_DOMAIN, bytes, signature).map_err(|_| EntryError::BadSignature)
    }

    /// The entry's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = ENTRY_MAGIC.to_vec();
        match self {
            Self::Warrant(signed) => {
                out.push(KIND_WARRANT);
                out.extend_from_slice(&signed.to_transport());
            }
            Self::Result {
                digest,
                key,
                signature,
            } => {
                out.push(KIND_RESULT);
                out.extend_from_slice(digest);
                out.extend_from_slice(&key.public_key());
                out.extend_from_slice(signature);
            }
        }
        out
    }

    /// Decodes an entry. A warrant entry's signature is verified; a result entry's can be
    /// only with the result's bytes ([`Entry::check_result`]).
    ///
    /// # Errors
    ///
    /// Anything [`Entry::encode`] does not produce, or a warrant signature that fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, EntryError> {
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(EntryError::TooLarge);
        }
        let rest = bytes
            .strip_prefix(ENTRY_MAGIC.as_slice())
            .ok_or(EntryError::Malformed("wrong magic"))?;
        match rest.split_first() {
            Some((&KIND_WARRANT, body)) => SignedWarrant::from_transport(body)
                .map(Self::Warrant)
                .map_err(|_| EntryError::BadSignature),
            Some((&KIND_RESULT, body)) => {
                let (digest, body) = body
                    .split_first_chunk::<32>()
                    .ok_or(EntryError::Malformed("result entry too short"))?;
                let (key, body) = body
                    .split_first_chunk::<32>()
                    .ok_or(EntryError::Malformed("result entry too short"))?;
                let signature: [u8; 64] = body
                    .try_into()
                    .map_err(|_| EntryError::Malformed("result entry is not 136 bytes"))?;
                let key = KeyId::from_public_key(key)
                    .map_err(|_| EntryError::Malformed("not a public key"))?;
                Ok(Self::Result {
                    digest: *digest,
                    key,
                    signature,
                })
            }
            _ => Err(EntryError::Malformed("unknown kind")),
        }
    }

    /// The entry's leaf hash in the tree.
    #[must_use]
    pub fn leaf_hash(&self) -> Hash {
        leaf_hash(&self.encode())
    }
}
