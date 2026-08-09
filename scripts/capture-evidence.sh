#!/usr/bin/env bash
# Assemble the Layer 3 evidence bundle for Cosign + vault upload.
# usage: scripts/capture-evidence.sh <output-dir>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/capture-evidence.sh <output-dir>" >&2
  exit 2
fi

OUT_DIR=$1
mkdir -p "$OUT_DIR"

# Inputs the workflow (or a local stub) must leave in cwd / APPLY_LOG.
for f in tfplan.json conftest.txt opa-test.txt; do
  if [[ ! -f "$f" ]]; then
    echo "missing input: $f" >&2
    exit 1
  fi
done
if [[ -z "${APPLY_LOG:-}" ]]; then
  echo "missing input: APPLY_LOG (unset)" >&2
  exit 1
fi
if [[ ! -f "$APPLY_LOG" ]]; then
  echo "missing input: $APPLY_LOG" >&2
  exit 1
fi

SHORT_SHA=$(git rev-parse --short HEAD)
UTC_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BASENAME="evidence-${SHORT_SHA}-${UTC_STAMP}"
STAGE=$(mktemp -d)

cp tfplan.json conftest.txt opa-test.txt "$STAGE/"
cp "$APPLY_LOG" "$STAGE/apply.txt"

# Flat manifest: files is a dict keyed by filename for one-lookup hash checks.
H_PLAN=$(sha256sum "$STAGE/tfplan.json" | awk '{print $1}')
H_CONF=$(sha256sum "$STAGE/conftest.txt" | awk '{print $1}')
H_OPA=$(sha256sum "$STAGE/opa-test.txt" | awk '{print $1}')
H_APPLY=$(sha256sum "$STAGE/apply.txt" | awk '{print $1}')
REPO=${GITHUB_REPOSITORY:-$(basename "$(git rev-parse --show-toplevel)")}
GIT_SHA=$(git rev-parse HEAD)
RUN_ID=${GITHUB_RUN_ID:-local}
RUN_URL=${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${RUN_ID}

jq -n \
  --arg repo "$REPO" \
  --arg git_sha "$GIT_SHA" \
  --arg run_id "$RUN_ID" \
  --arg run_url "$RUN_URL" \
  --arg timestamp_utc "$UTC_STAMP" \
  --arg tfplan "$H_PLAN" \
  --arg conftest "$H_CONF" \
  --arg opa "$H_OPA" \
  --arg apply "$H_APPLY" \
  '{
    repo: $repo,
    git_sha: $git_sha,
    run_id: $run_id,
    run_url: $run_url,
    timestamp_utc: $timestamp_utc,
    files: {
      "tfplan.json": $tfplan,
      "conftest.txt": $conftest,
      "opa-test.txt": $opa,
      "apply.txt": $apply
    }
  }' >"$STAGE/manifest.json"

tar -czf "${OUT_DIR}/${BASENAME}.tar.gz" -C "$STAGE" \
  tfplan.json conftest.txt opa-test.txt apply.txt manifest.json
(cd "$OUT_DIR" && sha256sum "${BASENAME}.tar.gz" >"${BASENAME}.tar.gz.sha256")
rm -rf "$STAGE"

# Last line = basename for the workflow to capture with $(...)
echo "$BASENAME"
