//! Delegation and attenuation (SPEC section 4).
//!
//! A child warrant is a valid attenuation of its parent when it can never permit a
//! request the parent does not. [`check`] enforces the four rules of SPEC section 4;
//! the attenuation theorem that follows from them is property-tested in
//! `tests/attenuation_theorem.rs`.

use core::fmt;

use crate::warrant::{Warrant, WarrantId};

/// Which rule of SPEC section 4 a delegation broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuationError {
    /// The child does not name this parent.
    WrongParent {
        /// What the child names, if anything.
        named: Option<WarrantId>,
        /// The parent's actual identifier.
        actual: WarrantId,
    },
    /// Rule 4: the child is not issued by the parent's subject.
    NotIssuedBySubject,
    /// Rule 1: the parent permits no further delegation, or the child keeps too much.
    Depth {
        /// The parent's `max_depth`.
        parent: u64,
        /// The child's `max_depth`.
        child: u64,
    },
    /// Rule 2: the child's validity window is not inside the parent's.
    Window,
    /// Rule 3: this child grant is not covered by any parent grant.
    Uncovered(usize),
}

impl fmt::Display for AttenuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongParent { named, actual } => match named {
                Some(n) => write!(f, "child names parent {n}, not {actual}"),
                None => write!(f, "child names no parent; expected {actual}"),
            },
            Self::NotIssuedBySubject => f.write_str("child is not issued by the parent's subject"),
            Self::Depth { parent, child } => {
                write!(
                    f,
                    "parent max_depth {parent} does not allow a child with max_depth {child}"
                )
            }
            Self::Window => f.write_str("child's validity window is not inside the parent's"),
            Self::Uncovered(i) => write!(f, "child grant {i} is not covered by any parent grant"),
        }
    }
}

impl std::error::Error for AttenuationError {}

/// Checks that `child` is a valid attenuation of `parent` (SPEC section 4).
///
/// # Errors
///
/// The first rule broken, checked in the order: parent link, issuer, depth, window,
/// grants.
pub fn check(parent: &Warrant, child: &Warrant) -> Result<(), AttenuationError> {
    let actual = parent.id();
    if child.parent() != Some(&actual) {
        return Err(AttenuationError::WrongParent {
            named: child.parent().cloned(),
            actual,
        });
    }
    if child.issuer().as_str() != parent.subject().as_str() {
        return Err(AttenuationError::NotIssuedBySubject);
    }
    let depth_ok =
        parent.max_depth() >= 1 && child.max_depth() <= parent.max_depth().saturating_sub(1);
    if !depth_ok {
        return Err(AttenuationError::Depth {
            parent: parent.max_depth(),
            child: child.max_depth(),
        });
    }
    if child.not_before() < parent.not_before() || child.not_after() > parent.not_after() {
        return Err(AttenuationError::Window);
    }
    for (i, grant) in child.grants().iter().enumerate() {
        if !parent.grants().iter().any(|p| p.covers(grant)) {
            return Err(AttenuationError::Uncovered(i));
        }
    }
    Ok(())
}
