#!/usr/bin/env bash
# setup.sh - Remit's production layout in one AWS account (docs/PRODUCTION.md).
#
#   bash deploy/aws/setup.sh code                        verify the broker's release zip, upload it
#   bash deploy/aws/setup.sh broker                      deploy the broker service (SPEC 8.4)
#   bash deploy/aws/setup.sh role <name> [ceiling-arn]   a role only the broker service may assume
#   bash deploy/aws/setup.sh reconciler <owner/repo>     the off-host reconciler's read-only role
#   bash deploy/aws/setup.sh status                      what is deployed, and what comes next
#
# Run it as a person with administrator rights, never as an agent. It reads, from the
# environment:
#   REMIT_VERSION        the release to deploy, such as v0.1.4
#   REMIT_ROOTS          the issuers' root key ids, separated by commas (remit key id)
#   REMIT_LOG_POLICY     the log's trust policy file
#   REMIT_ROLES          the role names the broker may assume, separated by commas; each is
#                        then made with `role`
#   AWS_REGION           default us-east-1
#   DRY_RUN=1            print each AWS command instead of running it
#
# Order: code, broker, one `role` per name in REMIT_ROLES, reconciler. Nothing here creates
# an access key: the broker service's invoker needs one, which you make and give to the
# agent's own system (`status` prints how).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REGION="${AWS_REGION:-us-east-1}"
VERSION="${REMIT_VERSION:-}"
say() { printf '  %s\n' "$*"; }
die() { echo "setup.sh: $*" >&2; exit 2; }
run() { if [ "${DRY_RUN:-}" = 1 ]; then printf '  would run:'; printf ' %q' "$@"; echo; else "$@"; fi; }
need() { [ -n "${!1:-}" ] || die "set $1 (see the header)"; }
account() {
  if [ "${DRY_RUN:-}" = 1 ]; then echo 111122223333; else aws sts get-caller-identity --query Account --output text; fi
}
out() {
  if [ "${DRY_RUN:-}" = 1 ]; then echo "<$2 of $1>"; return; fi
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null || true
}
bucket() { echo "remit-broker-code-$(account)"; }
zip_name() { echo "remit-broker-lambda-${VERSION}-arm64.zip"; }
role_arns() {
  local a; a=$(account)
  tr ',' '\n' <<<"$REMIT_ROLES" | sed "s|^ *|arn:aws:iam::$a:role/|; s| *$||" | paste -sd, -
}

case "${1:-}" in
  code)
    need REMIT_VERSION
    command -v gh >/dev/null || die "gh is needed to check the release's provenance"
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    zip=$(zip_name)
    gh release download "$VERSION" --repo abacross/remit --pattern "$zip" --pattern SHA256SUMS --dir "$tmp"
    (cd "$tmp" && grep " ${zip}\$" SHA256SUMS | sha256sum -c -)
    gh attestation verify "$tmp/$zip" --repo abacross/remit >/dev/null
    say "$zip: checksum and provenance verified"
    b=$(bucket)
    if [ "${DRY_RUN:-}" = 1 ] || ! aws s3api head-bucket --bucket "$b" 2>/dev/null; then
      run aws s3api create-bucket --bucket "$b" --region "$REGION"
      run aws s3api put-public-access-block --bucket "$b" --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
      run aws s3api put-bucket-versioning --bucket "$b" --versioning-configuration Status=Enabled
    fi
    run aws s3 cp "$tmp/$zip" "s3://$b/$zip" --only-show-errors
    say "next: broker"
    ;;
  broker)
    need REMIT_VERSION; need REMIT_ROOTS; need REMIT_LOG_POLICY; need REMIT_ROLES
    [ -f "$REMIT_LOG_POLICY" ] || die "no log policy at $REMIT_LOG_POLICY"
    grep -q '^quorum [1-9]' "$REMIT_LOG_POLICY" || die "the log policy must require at least one witness"
    run aws cloudformation deploy --region "$REGION" --stack-name remit-broker \
      --template-file "$HERE/broker-service.yaml" --capabilities CAPABILITY_NAMED_IAM \
      --parameter-overrides CodeBucket="$(bucket)" CodeKey="$(zip_name)" TrustedRoots="$REMIT_ROOTS" \
        LogPolicyBase64="$(base64 -w0 "$REMIT_LOG_POLICY")" ManagedRoleArns="$(role_arns)"
    say "broker service role: $(out remit-broker BrokerRoleArn)"
    say "next: role <name> for each of $REMIT_ROLES"
    ;;
  role)
    name="${2:-}"; [ -n "$name" ] || die "role <name> [ceiling-arn]"
    ceiling="${3:-arn:aws:iam::aws:policy/ReadOnlyAccess}"
    svc=$(out remit-broker BrokerRoleArn)
    [ -n "$svc" ] || die "deploy the broker first"
    run aws cloudformation deploy --region "$REGION" --stack-name "remit-role-$name" \
      --template-file "$HERE/role.yaml" --capabilities CAPABILITY_NAMED_IAM \
      --parameter-overrides RoleName="$name" CeilingPolicyArn="$ceiling" BrokerPrincipalArn="$svc"
    say "role $name: only the broker service may assume it, with a warrant id; its ceiling is $ceiling"
    ;;
  reconciler)
    repo="${2:-}"; [ -n "$repo" ] || die "reconciler <owner/repo>"
    need REMIT_ROLES
    command -v gh >/dev/null || die "gh is needed to read the repository's OIDC subject"
    subject=$(gh api "repos/$repo/actions/oidc/customization/sub" --jq .sub_claim_prefix)
    [ -n "$subject" ] || die "GitHub gave no OIDC subject for $repo"
    say "the role will trust $subject, branch main"
    run aws cloudformation deploy --region "$REGION" --stack-name remit-reconciler \
      --template-file "$HERE/reconciler-role.yaml" --capabilities CAPABILITY_NAMED_IAM \
      --parameter-overrides GitHubSubject="$subject" ManagedRoleArns="$(role_arns)"
    say "reconciler role: $(out remit-reconciler RoleArn); set it as REMIT_AWS_ROLE (deploy/github/README.md)"
    ;;
  status)
    say "broker service:  $(out remit-broker FunctionArn)"
    say "broker role:     $(out remit-broker BrokerRoleArn)   (--broker for remit reconcile)"
    say "invoker user:    $(out remit-broker InvokerUser)"
    say "reconciler role: $(out remit-reconciler RoleArn)"
    say "The invoker needs one access key, made by you and kept on the agent's own system:"
    say "  aws iam create-access-key --user-name $(out remit-broker InvokerUser)"
    say "  then, there: aws configure --profile remit-invoker"
    say "The agent then runs: remit run --broker-function $(out remit-broker FunctionArn) ..."
    ;;
  *) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
