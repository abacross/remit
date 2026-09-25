//! Risk bands from AWS's own service reference (SPEC section 10.3), not from a model.
//!
//! AWS publishes machine-readable metadata for every IAM action
//! (`https://servicereference.us-east-1.amazonaws.com/`), including four flags per action:
//! `IsList`, `IsWrite`, `IsPermissionManagement` and `IsTaggingOnly`. All four false means
//! the action only reads. The band is taken from those flags, so no text an agent writes
//! can change it; a model, when one is configured, answers only the remaining question of
//! whether this resource and purpose are safe without a person.
//!
//! Two limits, stated where they apply. AWS does not say which writes cannot be undone, so
//! `destructive` is a judgement from the action's verb. And a read is not always harmless:
//! `secretsmanager:GetSecretValue` carries no flags at all, which is why the default hard
//! rules send secret reads to a person before any decider is asked (`Config::default`).

use std::collections::HashMap;

use serde_json::Value;

use crate::{Assessment, Band, Decider};

/// The four flags AWS publishes for an action.
#[allow(
    clippy::struct_excessive_bools,
    reason = "AWS's four published flags, one field each"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// Discovers and lists resources without reading their contents.
    pub is_list: bool,
    /// Modifies resources.
    pub is_write: bool,
    /// Modifies permissions or credentials.
    pub is_permission_management: bool,
    /// Modifies only tags.
    pub is_tagging_only: bool,
}

/// Verbs whose writes this approver treats as not undoable. AWS does not publish this.
const DESTRUCTIVE_VERBS: [&str; 6] = [
    "Delete",
    "Terminate",
    "Destroy",
    "Purge",
    "Remove",
    "Revoke",
];

impl Flags {
    /// The band for an action with these flags and this name.
    #[must_use]
    pub fn band(self, action_name: &str) -> Band {
        if self.is_permission_management {
            Band::SensitiveOrExternal
        } else if self.is_write && !self.is_tagging_only {
            if DESTRUCTIVE_VERBS.iter().any(|v| action_name.starts_with(v)) {
                Band::Destructive
            } else {
                Band::ReversibleChange
            }
        } else if self.is_tagging_only {
            Band::ReversibleChange
        } else {
            Band::ReadOnly
        }
    }
}

/// The actions of one or more services, keyed by `service:action` in lower case.
#[derive(Debug, Clone, Default)]
pub struct ServiceReference {
    actions: HashMap<String, (String, Flags)>,
    versions: Vec<String>,
}

impl ServiceReference {
    /// An empty reference.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one service's reference file (the JSON AWS serves for it).
    ///
    /// # Errors
    ///
    /// Not a service reference: no `Name`, no `Actions`, or an action without its flags.
    pub fn add_service(&mut self, json: &str) -> Result<usize, String> {
        let v: Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
        let service = v
            .get("Name")
            .and_then(Value::as_str)
            .ok_or("no service Name")?
            .to_ascii_lowercase();
        let actions = v
            .get("Actions")
            .and_then(Value::as_array)
            .ok_or("no Actions")?;
        let flag = |p: &Value, k: &str| p.get(k).and_then(Value::as_bool);
        let mut added = 0usize;
        for a in actions {
            let name = a
                .get("Name")
                .and_then(Value::as_str)
                .ok_or("an action without a Name")?;
            let p = a
                .get("Annotations")
                .and_then(|x| x.get("Properties"))
                .ok_or_else(|| format!("{service}:{name} has no flags"))?;
            let (Some(is_list), Some(is_write), Some(is_pm), Some(is_tag)) = (
                flag(p, "IsList"),
                flag(p, "IsWrite"),
                flag(p, "IsPermissionManagement"),
                flag(p, "IsTaggingOnly"),
            ) else {
                return Err(format!("{service}:{name} is missing a flag"));
            };
            self.actions.insert(
                format!("{service}:{}", name.to_ascii_lowercase()),
                (
                    name.to_owned(),
                    Flags {
                        is_list,
                        is_write,
                        is_permission_management: is_pm,
                        is_tagging_only: is_tag,
                    },
                ),
            );
            added = added.saturating_add(1);
        }
        if let Some(ver) = v.get("Version").and_then(Value::as_str) {
            self.versions.push(format!("{service}@{ver}"));
        }
        Ok(added)
    }

    /// The band of an IAM action such as `s3:GetObject`, compared without regard to case
    /// as IAM does; `None` for an action the reference does not list.
    #[must_use]
    pub fn band(&self, action: &str) -> Option<Band> {
        self.actions
            .get(&action.to_ascii_lowercase())
            .map(|(name, flags)| flags.band(name))
    }

    /// How many actions are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether nothing is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// A decider whose band is AWS's, and whose probability comes from an inner decider when
/// there is one; without one, reads are judged safe and everything else is not.
pub struct Referenced<'a> {
    reference: &'a ServiceReference,
    inner: Option<&'a mut dyn Decider>,
    name: String,
}

impl<'a> Referenced<'a> {
    /// The reference alone, or the reference with a model for the remaining question.
    #[must_use]
    pub fn new(reference: &'a ServiceReference, inner: Option<&'a mut dyn Decider>) -> Self {
        let name = match &inner {
            Some(d) => format!("aws-reference+{}", d.name()),
            None => "aws-reference".to_owned(),
        };
        Self {
            reference,
            inner,
            name,
        }
    }
}

impl Decider for Referenced<'_> {
    fn name(&self) -> &str {
        &self.name
    }

    fn assess(&mut self, state_json: &str) -> Result<Assessment, String> {
        let state: Value = serde_json::from_str(state_json).map_err(|e| e.to_string())?;
        let action = state
            .get("action")
            .and_then(Value::as_str)
            .ok_or("no action in the state")?;
        let band = self
            .reference
            .band(action)
            .ok_or_else(|| format!("{action} is not in the loaded service reference"))?;
        match self.inner.as_mut() {
            Some(model) => {
                let a = model.assess(state_json)?;
                // The model's band is ignored: AWS's is authoritative. Its probability
                // answers only whether this resource and purpose are safe unreviewed.
                Ok(Assessment {
                    band,
                    p_safe: a.p_safe,
                    model: format!("aws-service-reference+{}", a.model),
                })
            }
            None => Ok(Assessment {
                band,
                p_safe: if band == Band::ReadOnly { 1.0 } else { 0.0 },
                model: "aws-service-reference".to_owned(),
            }),
        }
    }
}
