//! The IAM actions that authorize a recorded event (SPEC section 6.5).
//!
//! `CloudTrail` names an event by the API operation, and a warrant grants IAM actions. For
//! most services the two are the same word, but not for all: 60 of Amazon S3's operations
//! are authorized by a differently named action (`HeadObject` by `s3:GetObject`,
//! `ListBuckets` by `s3:ListAllMyBuckets`), and Lambda's event names carry the API version
//! (`GetFunction20150331v2`). Checking the event name as if it were the action would
//! report warranted work as outside its warrant, or, for an event that names no resource,
//! miss work that no grant covers.

/// Amazon S3 operations whose authorizing action is not `s3:` plus the operation's name,
/// with every action that can authorize them. Generated from "Required permissions for
/// Amazon S3 API operations" in the Amazon S3 User Guide
/// (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>,
/// read 2026-09-28). Where the page lists alternatives (a versioned request needs the
/// `...Version` action), any of them authorizes the event; `CopyObject` and
/// `UploadPartCopy` read one object and write another.
const S3: &[(&str, &[&str])] = &[
    ("CompleteMultipartUpload", &["s3:PutObject"]),
    ("CopyObject", &["s3:GetObject", "s3:PutObject"]),
    ("CreateMultipartUpload", &["s3:PutObject"]),
    (
        "DeleteBucketAnalyticsConfiguration",
        &["s3:PutAnalyticsConfiguration"],
    ),
    ("DeleteBucketCors", &["s3:PutBucketCORS"]),
    ("DeleteBucketEncryption", &["s3:PutEncryptionConfiguration"]),
    (
        "DeleteBucketIntelligentTieringConfiguration",
        &["s3:PutIntelligentTieringConfiguration"],
    ),
    (
        "DeleteBucketInventoryConfiguration",
        &["s3:PutInventoryConfiguration"],
    ),
    ("DeleteBucketLifecycle", &["s3:PutLifecycleConfiguration"]),
    (
        "DeleteBucketMetricsConfiguration",
        &["s3:PutMetricsConfiguration"],
    ),
    (
        "DeleteBucketOwnershipControls",
        &["s3:PutBucketOwnershipControls"],
    ),
    (
        "DeleteBucketReplication",
        &["s3:PutReplicationConfiguration"],
    ),
    ("DeleteBucketTagging", &["s3:PutBucketTagging"]),
    (
        "DeleteObject",
        &["s3:DeleteObject", "s3:DeleteObjectVersion"],
    ),
    (
        "DeleteObjectTagging",
        &["s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging"],
    ),
    (
        "DeleteObjects",
        &["s3:DeleteObject", "s3:DeleteObjectVersion"],
    ),
    (
        "GetBucketAccelerateConfiguration",
        &["s3:GetAccelerateConfiguration"],
    ),
    (
        "GetBucketAnalyticsConfiguration",
        &["s3:GetAnalyticsConfiguration"],
    ),
    ("GetBucketCors", &["s3:GetBucketCORS"]),
    ("GetBucketEncryption", &["s3:GetEncryptionConfiguration"]),
    (
        "GetBucketIntelligentTieringConfiguration",
        &["s3:GetIntelligentTieringConfiguration"],
    ),
    (
        "GetBucketInventoryConfiguration",
        &["s3:GetInventoryConfiguration"],
    ),
    ("GetBucketLifecycle", &["s3:GetLifecycleConfiguration"]),
    (
        "GetBucketMetricsConfiguration",
        &["s3:GetMetricsConfiguration"],
    ),
    (
        "GetBucketNotificationConfiguration",
        &["s3:GetBucketNotification"],
    ),
    ("GetBucketReplication", &["s3:GetReplicationConfiguration"]),
    ("GetObject", &["s3:GetObject", "s3:GetObjectVersion"]),
    (
        "GetObjectAcl",
        &["s3:GetObjectAcl", "s3:GetObjectVersionAcl"],
    ),
    (
        "GetObjectAttributes",
        &["s3:GetObject", "s3:GetObjectVersion"],
    ),
    (
        "GetObjectLockConfiguration",
        &["s3:GetBucketObjectLockConfiguration"],
    ),
    (
        "GetObjectTagging",
        &["s3:GetObjectTagging", "s3:GetObjectVersionTagging"],
    ),
    ("GetObjectTorrent", &["s3:GetObject"]),
    ("HeadBucket", &["s3:ListBucket"]),
    ("HeadObject", &["s3:GetObject"]),
    (
        "ListBucketAnalyticsConfigurations",
        &["s3:GetAnalyticsConfiguration"],
    ),
    (
        "ListBucketIntelligentTieringConfigurations",
        &["s3:GetIntelligentTieringConfiguration"],
    ),
    (
        "ListBucketInventoryConfigurations",
        &["s3:GetInventoryConfiguration"],
    ),
    (
        "ListBucketMetricsConfigurations",
        &["s3:GetMetricsConfiguration"],
    ),
    ("ListBuckets", &["s3:ListAllMyBuckets"]),
    ("ListMultipartUploads", &["s3:ListBucketMultipartUploads"]),
    ("ListObjectVersions", &["s3:ListBucketVersions"]),
    ("ListObjects", &["s3:ListBucket"]),
    ("ListObjectsV2", &["s3:ListBucket"]),
    ("ListParts", &["s3:ListMultipartUploadParts"]),
    (
        "PutBucketAccelerateConfiguration",
        &["s3:PutAccelerateConfiguration"],
    ),
    (
        "PutBucketAnalyticsConfiguration",
        &["s3:PutAnalyticsConfiguration"],
    ),
    ("PutBucketCors", &["s3:PutBucketCORS"]),
    ("PutBucketEncryption", &["s3:PutEncryptionConfiguration"]),
    (
        "PutBucketIntelligentTieringConfiguration",
        &["s3:PutIntelligentTieringConfiguration"],
    ),
    (
        "PutBucketInventoryConfiguration",
        &["s3:PutInventoryConfiguration"],
    ),
    ("PutBucketLifecycle", &["s3:PutLifecycleConfiguration"]),
    (
        "PutBucketMetricsConfiguration",
        &["s3:PutMetricsConfiguration"],
    ),
    (
        "PutBucketNotificationConfiguration",
        &["s3:PutBucketNotification"],
    ),
    ("PutBucketReplication", &["s3:PutReplicationConfiguration"]),
    (
        "PutObjectAcl",
        &["s3:PutObjectAcl", "s3:PutObjectVersionAcl"],
    ),
    (
        "PutObjectLockConfiguration",
        &["s3:PutBucketObjectLockConfiguration"],
    ),
    (
        "PutObjectTagging",
        &["s3:PutObjectTagging", "s3:PutObjectVersionTagging"],
    ),
    ("SelectObjectContent", &["s3:GetObject"]),
    ("UploadPart", &["s3:PutObject"]),
    ("UploadPartCopy", &["s3:GetObject", "s3:PutObject"]),
];

/// Lambda operations whose authorizing action has another name, from the Lambda API
/// reference ("This operation requires permission for the lambda:InvokeFunction action").
const LAMBDA: &[(&str, &[&str])] = &[
    ("Invoke", &["lambda:InvokeFunction"]),
    ("InvokeWithResponseStream", &["lambda:InvokeFunction"]),
];

/// The IAM actions any one of which authorizes an event with this source and name. Empty
/// for an operation that needs no permission (`sts:GetCallerIdentity`: "No permissions
/// are required to perform this operation.").
#[must_use]
pub fn authorizing_actions(source: &str, name: &str) -> Vec<String> {
    let service = source.strip_suffix(".amazonaws.com").unwrap_or(source);
    let listed = |table: &[(&str, &[&str])], name: &str| {
        table
            .iter()
            .find(|(op, _)| *op == name)
            .map(|(_, actions)| actions.iter().map(|a| (*a).to_owned()).collect())
    };
    match service {
        "sts" if name == "GetCallerIdentity" => Vec::new(),
        "s3" => listed(S3, name).unwrap_or_else(|| vec![format!("s3:{name}")]),
        "lambda" => {
            let name = without_api_version(name);
            listed(LAMBDA, name).unwrap_or_else(|| vec![format!("lambda:{name}")])
        }
        _ => vec![format!("{service}:{name}")],
    }
}

/// A Lambda event name without the API version `CloudTrail` appends: eight digits, then
/// optionally `v` and a number (`GetFunction20150331v2`, `ListTags20170331`).
fn without_api_version(name: &str) -> &str {
    let digit = |c: char| c.is_ascii_digit();
    let unnumbered = name.trim_end_matches(digit);
    let dated = if unnumbered.len() < name.len() {
        unnumbered.strip_suffix('v').unwrap_or(name)
    } else {
        name
    };
    let operation = dated.trim_end_matches(digit);
    let date = dated.get(operation.len()..).map_or(0, str::len);
    if date == 8 && !operation.is_empty() {
        operation
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::authorizing_actions as a;

    #[test]
    fn s3_operations_map_to_the_actions_that_authorize_them() {
        assert_eq!(
            a("s3.amazonaws.com", "ListBuckets"),
            ["s3:ListAllMyBuckets"]
        );
        assert_eq!(a("s3.amazonaws.com", "HeadObject"), ["s3:GetObject"]);
        assert_eq!(a("s3.amazonaws.com", "UploadPart"), ["s3:PutObject"]);
        assert_eq!(
            a("s3.amazonaws.com", "GetObject"),
            ["s3:GetObject", "s3:GetObjectVersion"]
        );
        assert_eq!(
            a("s3.amazonaws.com", "GetBucketLocation"),
            ["s3:GetBucketLocation"]
        );
    }

    #[test]
    fn lambda_event_names_lose_their_api_version() {
        let cases = [
            ("GetFunction20150331v2", "lambda:GetFunction"),
            (
                "GetFunctionConfiguration20150331v2",
                "lambda:GetFunctionConfiguration",
            ),
            ("ListFunctions20150331", "lambda:ListFunctions"),
            ("ListTags20170331", "lambda:ListTags"),
            ("Invoke", "lambda:InvokeFunction"),
            ("PublishVersion", "lambda:PublishVersion"),
        ];
        for (event, action) in cases {
            assert_eq!(a("lambda.amazonaws.com", event), [action], "{event}");
        }
    }

    #[test]
    fn only_lambda_names_are_stripped_and_only_of_a_whole_version() {
        assert_eq!(a("ec2.amazonaws.com", "Run20150331"), ["ec2:Run20150331"]);
        assert_eq!(
            a("lambda.amazonaws.com", "Get1234567"),
            ["lambda:Get1234567"]
        );
        assert_eq!(a("lambda.amazonaws.com", "20150331"), ["lambda:20150331"]);
    }

    #[test]
    fn get_caller_identity_needs_no_permission() {
        assert!(a("sts.amazonaws.com", "GetCallerIdentity").is_empty());
        assert_eq!(a("sts.amazonaws.com", "AssumeRole"), ["sts:AssumeRole"]);
    }
}
