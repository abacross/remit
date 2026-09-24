//! Warrants, grants and requests (SPEC section 3), and the authorization decision.
//!
//! Every type here is valid by construction: a [`Warrant`] that exists satisfies every
//! rule of SPEC sections 3.1 to 3.3, because the only way to make one is
//! [`Warrant::new`], which checks them all and refuses rather than repairs.

use core::fmt;

use crate::pattern::{ActionPattern, PatternError, ResourcePattern, validate_name};

/// The version of SPEC this crate implements.
pub const VERSION: u16 = 1;
/// At most this many grants in a warrant (SPEC section 3.1, limits).
pub const MAX_GRANTS: usize = 64;
/// At most this many action or resource patterns in a grant.
pub const MAX_PATTERNS: usize = 64;
/// At most this many bytes of purpose text.
pub const MAX_PURPOSE: usize = 512;
/// At most this many bytes in an identifier.
pub const MAX_IDENTIFIER: usize = 128;

/// Why a warrant, grant, identifier or request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarrantError {
    /// An identifier that is empty, too long, or not printable ASCII.
    Identifier(String),
    /// A pattern, with its position: grant index, and which list.
    Pattern {
        /// Index of the grant.
        grant: usize,
        /// `"actions"` or `"resources"`.
        list: &'static str,
        /// What was wrong with it.
        error: PatternError,
    },
    /// A grant with no action patterns or no resource patterns.
    EmptyGrantList {
        /// Index of the grant.
        grant: usize,
        /// `"actions"` or `"resources"`.
        list: &'static str,
    },
    /// No grants at all.
    NoGrants,
    /// More grants, or more patterns in a grant, than the limits allow.
    TooMany(&'static str, usize),
    /// Purpose text over [`MAX_PURPOSE`] bytes.
    PurposeTooLong(usize),
    /// `not_before` is not strictly before `not_after`.
    EmptyWindow {
        /// The first valid second.
        not_before: u64,
        /// The last valid second.
        not_after: u64,
    },
    /// A request's action or resource is not an acceptable concrete name.
    RequestName(PatternError),
}

impl fmt::Display for WarrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identifier(s) => write!(f, "invalid identifier {s:?}"),
            Self::Pattern { grant, list, error } => write!(f, "grant {grant} {list}: {error}"),
            Self::EmptyGrantList { grant, list } => write!(f, "grant {grant} has no {list}"),
            Self::NoGrants => f.write_str("a warrant needs at least one grant"),
            Self::TooMany(what, n) => write!(f, "{n} {what}, over the limit"),
            Self::PurposeTooLong(n) => write!(f, "purpose is {n} bytes, over {MAX_PURPOSE}"),
            Self::EmptyWindow {
                not_before,
                not_after,
            } => {
                write!(f, "validity window {not_before}..={not_after} is empty")
            }
            Self::RequestName(e) => write!(f, "request name: {e}"),
        }
    }
}

impl std::error::Error for WarrantError {}

/// An issuer or subject identifier: 1 to 128 characters of printable ASCII.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identifier(String);

impl Identifier {
    /// Parses an identifier.
    ///
    /// # Errors
    ///
    /// Empty, over [`MAX_IDENTIFIER`] bytes, or outside printable ASCII.
    pub fn new(text: &str) -> Result<Self, WarrantError> {
        let ok = !text.is_empty()
            && text.len() <= MAX_IDENTIFIER
            && text.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(WarrantError::Identifier(text.to_owned()))
        }
    }

    /// The identifier as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One allowance: some actions on some resources (SPEC section 3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    actions: Vec<ActionPattern>,
    resources: Vec<ResourcePattern>,
}

impl Grant {
    /// Builds a grant from pattern text, validating every pattern.
    ///
    /// # Errors
    ///
    /// An empty list, too many patterns, or an invalid pattern. The grant index in the
    /// error is 0; [`Warrant::new`] reports the real index.
    pub fn new(actions: &[&str], resources: &[&str]) -> Result<Self, WarrantError> {
        Self::parse(0, actions, resources)
    }

    fn parse(index: usize, actions: &[&str], resources: &[&str]) -> Result<Self, WarrantError> {
        for (list, n) in [("actions", actions.len()), ("resources", resources.len())] {
            if n == 0 {
                return Err(WarrantError::EmptyGrantList { grant: index, list });
            }
            if n > MAX_PATTERNS {
                return Err(WarrantError::TooMany(list, n));
            }
        }
        let pattern_err = |list, error| WarrantError::Pattern {
            grant: index,
            list,
            error,
        };
        let actions = actions
            .iter()
            .map(|t| ActionPattern::new(t).map_err(|e| pattern_err("actions", e)))
            .collect::<Result<Vec<_>, _>>()?;
        let resources = resources
            .iter()
            .map(|t| ResourcePattern::new(t).map_err(|e| pattern_err("resources", e)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { actions, resources })
    }

    /// The action patterns, in the order written.
    #[must_use]
    pub fn actions(&self) -> &[ActionPattern] {
        &self.actions
    }

    /// The resource patterns, in the order written.
    #[must_use]
    pub fn resources(&self) -> &[ResourcePattern] {
        &self.resources
    }

    /// Does this grant allow the action on the resource (SPEC section 3.2)?
    #[must_use]
    pub fn allows(&self, action: &str, resource: &str) -> bool {
        self.actions.iter().any(|p| p.matches(action))
            && self.resources.iter().any(|p| p.matches(resource))
    }

    /// Does this grant cover `other`: is every action pattern of `other` contained in
    /// one of ours, and every resource pattern likewise (SPEC section 4, rule 3)?
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        other
            .actions
            .iter()
            .all(|inner| self.actions.iter().any(|outer| outer.contains(inner)))
            && other
                .resources
                .iter()
                .all(|inner| self.resources.iter().any(|outer| outer.contains(inner)))
    }
}

/// The content-derived identifier of a warrant (SPEC section 3.5): `rw1-` and 32
/// characters of lowercase base32.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WarrantId(String);

impl WarrantId {
    /// Parses an identifier in the SPEC section 3.5 form.
    ///
    /// # Errors
    ///
    /// Anything other than `rw1-` followed by 32 characters from `a` to `z` and `2` to `7`.
    pub fn parse(text: &str) -> Result<Self, WarrantError> {
        let ok = text.len() == 36
            && text.starts_with("rw1-")
            && text
                .bytes()
                .skip(4)
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(WarrantError::Identifier(text.to_owned()))
        }
    }

    pub(crate) fn from_trusted(text: String) -> Self {
        Self(text)
    }

    /// The identifier, as set on an AWS session's `SourceIdentity`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WarrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The unvalidated parts of a warrant, as an author writes them.
#[derive(Debug, Clone)]
pub struct WarrantSpec<'a> {
    /// Who signs it.
    pub issuer: &'a str,
    /// Which agent it authorizes.
    pub subject: &'a str,
    /// Why, as free text; no effect on authorization.
    pub purpose: &'a str,
    /// First valid second, UTC seconds since the epoch.
    pub not_before: u64,
    /// Last valid second.
    pub not_after: u64,
    /// Each grant as (action patterns, resource patterns).
    pub grants: &'a [(&'a [&'a str], &'a [&'a str])],
    /// The warrant this one is delegated from, if any.
    pub parent: Option<WarrantId>,
    /// How many further delegations it permits.
    pub max_depth: u64,
}

/// A warrant (SPEC section 3.1). Valid by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warrant {
    pub(crate) issuer: Identifier,
    pub(crate) subject: Identifier,
    pub(crate) purpose: String,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    pub(crate) grants: Vec<Grant>,
    pub(crate) parent: Option<WarrantId>,
    pub(crate) max_depth: u64,
}

impl Warrant {
    /// Builds a warrant, checking every rule of SPEC sections 3.1 to 3.3.
    ///
    /// # Errors
    ///
    /// The first rule the spec breaks; nothing is repaired or normalized.
    pub fn new(spec: &WarrantSpec<'_>) -> Result<Self, WarrantError> {
        if spec.purpose.len() > MAX_PURPOSE {
            return Err(WarrantError::PurposeTooLong(spec.purpose.len()));
        }
        if spec.not_before >= spec.not_after {
            return Err(WarrantError::EmptyWindow {
                not_before: spec.not_before,
                not_after: spec.not_after,
            });
        }
        if spec.grants.is_empty() {
            return Err(WarrantError::NoGrants);
        }
        if spec.grants.len() > MAX_GRANTS {
            return Err(WarrantError::TooMany("grants", spec.grants.len()));
        }
        let grants = spec
            .grants
            .iter()
            .enumerate()
            .map(|(i, (actions, resources))| Grant::parse(i, actions, resources))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            issuer: Identifier::new(spec.issuer)?,
            subject: Identifier::new(spec.subject)?,
            purpose: spec.purpose.to_owned(),
            not_before: spec.not_before,
            not_after: spec.not_after,
            grants,
            parent: spec.parent.clone(),
            max_depth: spec.max_depth,
        })
    }

    /// The signing key's identifier.
    #[must_use]
    pub fn issuer(&self) -> &Identifier {
        &self.issuer
    }
    /// The authorized agent.
    #[must_use]
    pub fn subject(&self) -> &Identifier {
        &self.subject
    }
    /// The stated purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    /// First valid second.
    #[must_use]
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    /// Last valid second.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    /// The grants, in the order written.
    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
    /// The parent warrant, for a delegated warrant.
    #[must_use]
    pub fn parent(&self) -> Option<&WarrantId> {
        self.parent.as_ref()
    }
    /// Further delegations permitted.
    #[must_use]
    pub fn max_depth(&self) -> u64 {
        self.max_depth
    }

    /// The authorization decision (SPEC section 3.4). Pure and total: signature and
    /// chain checks are preconditions of using a warrant, not part of this function.
    #[must_use]
    pub fn permits(&self, request: &Request) -> bool {
        request.subject == self.subject
            && self.not_before <= request.at
            && request.at <= self.not_after
            && self
                .grants
                .iter()
                .any(|g| g.allows(&request.action, &request.resource))
    }
}

/// One concrete action an agent wants to take (SPEC section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    subject: Identifier,
    action: String,
    resource: String,
    at: u64,
}

impl Request {
    /// Builds a request, refusing wildcards and anything outside printable ASCII.
    ///
    /// # Errors
    ///
    /// An invalid subject, action or resource.
    pub fn new(subject: &str, action: &str, resource: &str, at: u64) -> Result<Self, WarrantError> {
        validate_name(action).map_err(WarrantError::RequestName)?;
        validate_name(resource).map_err(WarrantError::RequestName)?;
        Ok(Self {
            subject: Identifier::new(subject)?,
            action: action.to_owned(),
            resource: resource.to_owned(),
            at,
        })
    }

    /// The agent making it.
    #[must_use]
    pub fn subject(&self) -> &Identifier {
        &self.subject
    }
    /// The action name.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
    /// The resource name.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
    /// When, in UTC seconds since the epoch.
    #[must_use]
    pub fn at(&self) -> u64 {
        self.at
    }
}
