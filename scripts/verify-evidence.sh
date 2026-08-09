#!/usr/bin/env bash
set -euo pipefail

CERT_IDENTITY='https://github.com/0xBahalaNa/cge-p-capstone/.github/workflows/grc-gate.yml@refs/heads/main'
CERT_ISSUER='https://token.actions.githubusercontent.com'

fail() { echo "BROKEN LINK: $1" >&2; rm -rf "$WORKDIR"; exit 1; }

if [[ $# -ne 1 ]]; then
  echo "usage: ${0##*/} s3://bucket/prefix/" >&2
  exit 2
fi

SRC="${1%/}"
WORKDIR="$(mktemp -d)"
cd "$WORKDIR"

aws s3 cp "$SRC/" . --recursive --only-show-errors || fail "fetch: $SRC/"

shopt -s nullglob
tarballs=( *.tar.gz )
shopt -u nullglob
[[ ${#tarballs[@]} -eq 1 ]] || fail "fetch: expected 1 *.tar.gz, found ${#tarballs[@]}"
BUNDLE="${tarballs[0]}"

REST="${SRC#s3://}"
BUCKET="${REST%%/*}"
KEY="${REST#*/}/$BUNDLE"

echo "Verifying $BUNDLE from s3://$BUCKET/$KEY"

# Check 1: integrity
sha256sum -c "${BUNDLE}.sha256" >/dev/null || fail "SHA-256"
echo "ok  integrity   SHA-256 matches ${BUNDLE}.sha256"

# Check 2: provenance
cosign verify-blob \
  --bundle "${BUNDLE}.cosign.bundle" \
  --certificate-identity "$CERT_IDENTITY" \
  --certificate-oidc-issuer "$CERT_ISSUER" \
  "$BUNDLE" >/dev/null || fail "signature"
echo "ok  signature   cosign identity and issuer match"

# Check 3: retention and encryption
META="$(aws s3api head-object --bucket "$BUCKET" --key "$KEY")" || fail "retention: head-object"
MODE="$(jq -r '.ObjectLockMode // empty' <<<"$META")"
RETAIN="$(jq -r '.ObjectLockRetainUntilDate // empty' <<<"$META")"
SSE="$(jq -r '.ServerSideEncryption // empty' <<<"$META")"

[[ "$MODE" == GOVERNANCE ]] || fail "retention: mode ${MODE:-unset}, expected GOVERNANCE"
[[ -n "$RETAIN" ]] || fail "retention: retain-until unset"
[[ "$(date -u -d "$RETAIN" +%s)" -gt "$(date -u +%s)" ]] || fail "retention: lapsed at $RETAIN"
[[ "$SSE" == "aws:kms" ]] || fail "encryption: ${SSE:-none}, expected aws:kms"
echo "ok  retention   GOVERNANCE until $RETAIN"
echo "ok  encryption  aws:kms"

# Check 4: the folder, the file, and the signed manifest all name the same run.
# Without this, a bundle copied from another prefix passes checks 1-3 unchanged.
PREFIX_RUN="${SRC##*/}"
BUNDLE_RUN="${BUNDLE%.tar.gz}"
BUNDLE_RUN="${BUNDLE_RUN#evidence-}"
NAMED_SHA="${BUNDLE_RUN%%-*}"
MANIFEST="$(tar -xzOf "$BUNDLE" manifest.json)" || fail "identity: cannot read manifest.json"
MANIFEST_SHA="$(jq -r '.git_sha' <<<"$MANIFEST")"
MANIFEST_STAMP="$(jq -r '.timestamp_utc' <<<"$MANIFEST")"

# The object name is attacker-controlled, so refuse to bind on a stub of it.
[[ ${#NAMED_SHA} -ge 7 ]] || fail "identity: sha segment '$NAMED_SHA' too short to bind"
[[ "$PREFIX_RUN" == "$BUNDLE_RUN" ]] || fail "identity: prefix names $PREFIX_RUN, bundle names $BUNDLE_RUN"
[[ "$BUNDLE_RUN" == "$NAMED_SHA-$MANIFEST_STAMP" ]] || fail "identity: bundle names $BUNDLE_RUN, manifest stamp is $MANIFEST_STAMP"
[[ "$MANIFEST_SHA" == "$NAMED_SHA"* ]] || fail "identity: bundle names $NAMED_SHA, manifest git_sha is ${MANIFEST_SHA:0:7}"
echo "ok  identity    prefix, bundle, and manifest all name run $BUNDLE_RUN"

rm -rf "$WORKDIR"
echo "CHAIN INTACT"
echo "scope: proves this bundle is intact, signed by the main-branch workflow, and under"
echo "       unexpired GOVERNANCE lock. Does not prove its plan is the plan the PR gate saw."
exit 0
