//! Grants that let work escape the warrant that granted them (THREAT-MODEL.md, E4).
//!
//! A warrant bounds what its sessions can do while it is valid. Some actions hand the
//! agent power the warrant cannot bound: another role's permissions, credentials that
//! outlive the window, a policy that admits someone else, or code that runs later under
//! a different identity. AWS enforces the warrant on the call that does it, and allows
//! it, because the warrant says so. What happens next is outside the warrant.
//!
//! This list is the known ways out, not a proof that there are no others: the role's
//! permissions are the ceiling that holds when a way out is missing from it.

use crate::Warrant;

/// Why an action lets work escape its warrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    /// Acts as another role, whose permissions the warrant does not bound.
    AnotherRole,
    /// Makes credentials or sign-ins that outlive the warrant's window.
    StandingCredentials,
    /// Widens what an IAM principal may do, the managed role's ceiling included.
    WidensIam,
    /// Changes a resource policy, which can admit other principals, and whose grants to
    /// the session itself a session policy does not limit.
    ResourcePolicy,
    /// Changes code or commands that run later under another identity.
    RunsLater,
    /// Returns a credential that acts outside the session and its record: a password, a
    /// token, a secret.
    OutsideTheRecord,
}

impl Escape {
    /// The reason in words.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::AnotherRole => "acts as another role, which the warrant does not bound",
            Self::StandingCredentials => "makes credentials that outlive the warrant",
            Self::WidensIam => "widens what an IAM principal may do",
            Self::ResourcePolicy => "changes a resource policy, which can admit others",
            Self::RunsLater => "changes what runs later under another identity",
            Self::OutsideTheRecord => "returns a credential that acts outside the session",
        }
    }
}

/// The actions known to let work escape a warrant, with why.
pub const ESCAPES: &[(&str, Escape)] = &[
    ("iam:PassRole", Escape::AnotherRole),
    ("sts:AssumeRole", Escape::AnotherRole),
    ("sts:AssumeRoleWithSAML", Escape::AnotherRole),
    ("sts:AssumeRoleWithWebIdentity", Escape::AnotherRole),
    ("sts:GetFederationToken", Escape::StandingCredentials),
    ("iam:CreateAccessKey", Escape::StandingCredentials),
    ("iam:CreateLoginProfile", Escape::StandingCredentials),
    ("iam:UpdateLoginProfile", Escape::StandingCredentials),
    (
        "iam:CreateServiceSpecificCredential",
        Escape::StandingCredentials,
    ),
    ("iam:UploadSSHPublicKey", Escape::StandingCredentials),
    ("iam:CreateUser", Escape::WidensIam),
    ("iam:CreateRole", Escape::WidensIam),
    ("iam:AttachRolePolicy", Escape::WidensIam),
    ("iam:PutRolePolicy", Escape::WidensIam),
    ("iam:UpdateAssumeRolePolicy", Escape::WidensIam),
    ("iam:DeleteRolePermissionsBoundary", Escape::WidensIam),
    ("iam:PutRolePermissionsBoundary", Escape::WidensIam),
    ("iam:AttachUserPolicy", Escape::WidensIam),
    ("iam:PutUserPolicy", Escape::WidensIam),
    ("iam:AttachGroupPolicy", Escape::WidensIam),
    ("iam:PutGroupPolicy", Escape::WidensIam),
    ("iam:AddUserToGroup", Escape::WidensIam),
    ("iam:CreatePolicyVersion", Escape::WidensIam),
    ("iam:SetDefaultPolicyVersion", Escape::WidensIam),
    ("s3:PutBucketPolicy", Escape::ResourcePolicy),
    ("s3:PutBucketAcl", Escape::ResourcePolicy),
    ("kms:PutKeyPolicy", Escape::ResourcePolicy),
    ("kms:CreateGrant", Escape::ResourcePolicy),
    ("lambda:AddPermission", Escape::ResourcePolicy),
    ("sqs:AddPermission", Escape::ResourcePolicy),
    ("sns:AddPermission", Escape::ResourcePolicy),
    ("secretsmanager:PutResourcePolicy", Escape::ResourcePolicy),
    ("ecr:SetRepositoryPolicy", Escape::ResourcePolicy),
    ("lambda:UpdateFunctionCode", Escape::RunsLater),
    ("lambda:CreateFunction", Escape::RunsLater),
    ("lambda:UpdateFunctionConfiguration", Escape::RunsLater),
    ("ssm:SendCommand", Escape::RunsLater),
    ("ssm:StartSession", Escape::RunsLater),
    ("ec2-instance-connect:SendSSHPublicKey", Escape::RunsLater),
    ("ec2:GetPasswordData", Escape::OutsideTheRecord),
    (
        "lightsail:GetInstanceAccessDetails",
        Escape::OutsideTheRecord,
    ),
    ("lightsail:DownloadDefaultKeyPair", Escape::OutsideTheRecord),
    ("ecr:GetAuthorizationToken", Escape::OutsideTheRecord),
    (
        "codeartifact:GetAuthorizationToken",
        Escape::OutsideTheRecord,
    ),
    ("sts:GetServiceBearerToken", Escape::OutsideTheRecord),
    ("rds-db:connect", Escape::OutsideTheRecord),
    ("redshift:GetClusterCredentials", Escape::OutsideTheRecord),
    (
        "redshift-serverless:GetCredentials",
        Escape::OutsideTheRecord,
    ),
    ("secretsmanager:GetSecretValue", Escape::OutsideTheRecord),
];

/// Every known escape a warrant's grants reach, as (grant index, action, why), in grant
/// order. A pattern reaches an action when it matches it, so `*` and `iam:*` reach many.
#[must_use]
pub fn escapes(w: &Warrant) -> Vec<(usize, &'static str, Escape)> {
    let mut found = Vec::new();
    for (i, grant) in w.grants().iter().enumerate() {
        for &(action, why) in ESCAPES {
            if grant.actions().iter().any(|p| p.matches(action)) {
                found.push((i, action, why));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::{Escape, escapes};
    use crate::{Warrant, WarrantSpec};

    fn warrant(actions: &[&str]) -> Warrant {
        let resources: &[&str] = &["*"];
        let grants: [(&[&str], &[&str]); 1] = [(actions, resources)];
        Warrant::new(&WarrantSpec {
            issuer: "i",
            subject: "s",
            purpose: "",
            not_before: 1,
            not_after: 2,
            grants: &grants,
            parent: None,
            max_depth: 0,
        })
        .unwrap()
    }

    #[test]
    fn reading_and_ordinary_writes_escape_nothing() {
        let w = warrant(&[
            "s3:GetObject",
            "s3:PutObject",
            "iam:List*",
            "iam:Get*",
            "cloudfront:CreateInvalidation",
            "lambda:GetFunction",
        ]);
        assert_eq!(escapes(&w), vec![]);
    }

    #[test]
    fn named_actions_and_wildcards_that_reach_them_are_found() {
        let w = warrant(&["iam:PassRole"]);
        assert_eq!(escapes(&w), vec![(0, "iam:PassRole", Escape::AnotherRole)]);
        let w = warrant(&["STS:assumerole"]);
        assert_eq!(escapes(&w).len(), 1);
        assert!(escapes(&warrant(&["iam:*"])).len() > 10);
        assert_eq!(escapes(&warrant(&["*"])).len(), super::ESCAPES.len());
        assert!(
            escapes(&warrant(&["lambda:Update*"]))
                .iter()
                .all(|(_, _, why)| *why == Escape::RunsLater)
        );
    }
}
