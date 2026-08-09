# CGE-P Capstone — governing the Acme Health Patient Intake API

**Primary framework: CMMC Level 2**, mapped to NIST SP 800-171 Rev 3.
Framework rationale, design trade-offs and known limits are in [WRITEUP.md](WRITEUP.md).

I inherited a working Patient Intake API with eight named security gaps and no audit trail.
This repo wraps it in four governance layers without rewriting the application: a Terraform
GRC baseline, an OPA policy suite that blocks regressions at the pull request, a GitHub
Actions pipeline that signs and vaults evidence on every merge, and an OSCAL component
definition that lets an assessor follow a control claim to the resource implementing it and
the signed artifact proving it.

The application code is unchanged from
[`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter).

---

## Verify this repo

### No AWS account needed

```bash
# Layer 2 — policy unit tests (39 tests, 7 policies)
opa test policies/

# Layer 4 — OSCAL schema validation (trestle only validates inside a workspace)
W=$(mktemp -d) && (cd "$W" && trestle init --local >/dev/null)
mkdir -p "$W/component-definitions/cge-p-capstone" "$W/profiles/cge-p-minimum"
cp oscal/components/cge-p-capstone-component.json \
   "$W/component-definitions/cge-p-capstone/component-definition.json"
cp oscal/profiles/cge-p-minimum.json \
   "$W/profiles/cge-p-minimum/profile.json"
(cd "$W" && trestle validate --all)
```

### Needs AWS credentials for this account

```bash
# Layer 1 — the baseline is applied and drift-free
cd terraform && terraform init && terraform plan     # expect: No changes

# Layer 2 — the suite against a real plan (NOT the fixtures)
terraform plan -out=tfplan && terraform show -json tfplan > ../tfplan.json
cd .. && conftest test --all-namespaces -p policies/ tfplan.json

# Layer 3 — the evidence chain
export EVIDENCE_BUCKET=$(terraform -chdir=terraform output -raw evidence_bucket)
scripts/verify-evidence.sh s3://$EVIDENCE_BUCKET/runs/45b9ac8-20260809T174923Z/
```

OSCAL evidence `href`s use the literal host `EVIDENCE_BUCKET` (R-1 — the real name is
not in the public tree). Resolve it with the `export` line above before pasting an `href`
into `aws s3 ls`.

`--all-namespaces` is not optional. The packages are `cgep.*` and Conftest defaults to `main`,
so omitting the flag exits 0 with `0 tests, 0 passed`. That is a vacuous green, and it is the
single easiest way to fool yourself into believing this gate works.

`tfplan.json` is gitignored because it embeds the account ID in resource ARNs.

### The gate has teeth

| | |
|---|---|
| Green PR, merged | [#9](https://github.com/0xBahalaNa/cge-p-capstone/pull/9) |
| Red PR, blocked and closed unmerged | [#10](https://github.com/0xBahalaNa/cge-p-capstone/pull/10) |

The red PR reintroduces GAP-01 by flipping the uploads bucket back to `AES256`. `Plan`
succeeds, `Policy check` fails with the `SC.L2-3.13.11` deny message, and `main` requires
the `gate` status check, so merge is blocked for anyone without admin bypass.
`enforce_admins` is false — the repo owner (who is also the account admin) still sees a
bypass affordance rather than a hard-disabled button. PR #10 was closed unmerged, so the
demonstration still stands.

---

## The four layers

**Layer 1 — Terraform GRC baseline.** Two customer-managed KMS keys with rotation, split by
trust boundary: one for the workload, one for evidence. An S3 evidence vault under Object Lock
(GOVERNANCE, 30 days) and versioning. A multi-region CloudTrail with log file validation,
writing to a dedicated bucket under the evidence CMK. Hardening overrides that close six of
eight starter gaps fully, and two in part (GAP-06 reserved concurrency, GAP-08 WAF).

**Layer 2 — OPA policy suite.** Seven Rego policies, ten deny rules, 39 unit tests. Each
policy carries a metadata block naming the framework, control IDs, severity and remediation,
and each deny message cites its CMMC practice so a developer sees the control, not just a
failure. The policies read `terraform show -json` planned values rather than parsing HCL.

**Layer 3 — GitHub Actions pipeline.** One workflow, five sequential steps: plan, policy
check, apply on merge to `main`, Cosign keyless signature via GitHub OIDC, upload to the
evidence vault. A pull request run never receives apply-role credentials.

**Layer 4 — OSCAL component definition.** Eight implemented requirements against the NIST SP
800-171 Rev 3 catalog, each citing the real Terraform addresses that implement it, the Rego
package that guards it (record generation under 03.03.03 and several boundary halves are
Terraform-only and unpoliced — each description says which, and names the package that covers
the half a sibling requirement cites), its CMMC practice ID, and a link to the signed bundle in
the vault.

---

## Gap coverage

Eight gaps named in [GAPS.md](GAPS.md), all eight addressed.

| Gap | What was wrong | Where it is closed | CMMC L2 | 800-171 r3 |
|---|---|---|---|---|
| GAP-01 | Uploads bucket on SSE-S3, not a customer CMK | `hardening.tf:8` | SC.L2-3.13.11 | 03.13.11 |
| GAP-02 | DynamoDB on the AWS-owned default key | `main.tf:121` | SC.L2-3.13.11 | 03.13.11 |
| GAP-03 | No bucket policy denying plain HTTP | `hardening.tf:22` | SC.L2-3.13.8 | 03.13.08 |
| GAP-04 | No versioning; PHI overwrites unrecoverable | `hardening.tf:53` | MP.L2-3.8.9 | 03.08.09 |
| GAP-05 | Lambda outside the VPC | `main.tf:241`, `hardening.tf:63` | SC.L2-3.13.1 | 03.13.01 |
| GAP-06 | No DLQ, no X-Ray, no reserved concurrency | `main.tf:231`, `hardening.tf:145` | SI.L2-3.14.6 | 03.14.06 |
| GAP-07 | Lambda role held `dynamodb:*` and `s3:*` | `main.tf:184` | AC.L2-3.1.5 | 03.01.05 |
| GAP-08 | No API Gateway access logging or throttling | `main.tf:280`, `hardening.tf:162` | AU.L2-3.3.1 | 03.03.01, 03.03.03 |

Two of these are partial, and I would rather say so here than have a grader find it:

**GAP-06 closes on two of three parts.** This account's Lambda `ConcurrentExecutions` quota is
10, which cannot support a reservation, so the DLQ and X-Ray halves are implemented and
reserved concurrency is not. The policy checks only what is implemented.

**GAP-08 closes on two of three parts.** WAF is not attachable to an API Gateway HTTP API.
Access logging and throttling are implemented.

---

## Layout

```
cge-p-capstone/
├── terraform/
│   ├── main.tf                 starter workload + in-place gap closures
│   ├── kms.tf                  workload CMK and evidence CMK, rotation on
│   ├── evidence-vault.tf       Object Lock vault (GOVERNANCE, 30 days)
│   ├── cloudtrail.tf           multi-region trail, log file validation
│   ├── hardening.tf            gap-closing overrides on starter resources
│   └── oidc-trust.tf           GitHub OIDC: read-only plan role, main-only apply role
├── policies/                   7 Rego policies + 7 test files
├── scripts/
│   ├── capture-evidence.sh     assembles the bundle
│   └── verify-evidence.sh      SHA-256, Cosign, Object Lock retention
├── .github/workflows/
│   └── grc-gate.yml            plan → policy check → apply → sign → upload
├── oscal/
│   ├── components/cge-p-capstone-component.json
│   └── profiles/cge-p-minimum.json
├── GAPS.md                     the eight named starter flaws
├── FRAMEWORKS.md               starter framework primer
├── WORKLOAD.md                 what the API does
└── WRITEUP.md                  decisions, deviations, residual risk
```

---

## Teardown

Object Lock is on at GOVERNANCE for 30 days, so the evidence vault does not destroy cleanly
without an explicit bypass. Order matters:

```bash
# 1. Delete every object version in the vault, bypassing unexpired retention.
#    Requires s3:BypassGovernanceRetention.
export EVIDENCE_BUCKET=$(terraform -chdir=terraform output -raw evidence_bucket)
aws s3api delete-objects --bucket "$EVIDENCE_BUCKET" \
  --bypass-governance-retention \
  --delete "$(aws s3api list-object-versions --bucket "$EVIDENCE_BUCKET" \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

# 2. Then the stack.
make destroy AWS_PROFILE=<your-profile>
```

The CloudTrail bucket has `force_destroy = true` and needs no bypass. Terraform state lives in
a bucket created out of band and is not managed by this stack, so it survives `destroy` and
must be removed by hand. Its name is withheld from the public tree under the same rule as the
evidence bucket, so the bootstrap commands are not reproduced here.

## License

MIT, inherited from the starter.
