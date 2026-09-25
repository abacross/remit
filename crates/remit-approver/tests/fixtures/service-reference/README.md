# AWS service reference fixtures

`s3.json`, `sts.json` and `secretsmanager.json` are AWS's service reference information, fetched unchanged from `https://servicereference.us-east-1.amazonaws.com/v1/<service>/<service>.json` on 2026-09-24 (reference version v1.4).
AWS documents the format at https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html.
The approver's tests read them to check that bands follow AWS's own per-action flags.
