# Capstone Writeup — decisions, deviations, and residual risk

The record of *why* this capstone is shaped the way it is: the trade-offs taken, the
places it deliberately departs from the brief, the risk it does not close, and the work
still owed.

GitHub Issues are disabled on this repo, so this file — not an issue tracker — is where
deferred work and accepted risk live. Every entry below was a decision made during
Layers 1–2 (PRs #1–#7).

> **Review status:** consolidated from the PR bodies of #1–#7. The reasoning is accurate
> to what was built, but the wording is drafted, not yet rewritten in my own words. Do a
> defense pass over the *Why it is built this way* section before this is put in front of
> an assessor.

---

## Why it is built this way

### Keys and trust boundaries

**Two CMKs, not one.** A CMK is a trust boundary. A single key would mean the Lambda role
handling patient data also holds `kms:Decrypt` against the audit trail of its own
behavior — the exact separation an evidence vault exists to create. The thing being
audited must not hold the key to its own audit trail.

**Two, not three.** Splitting the trail key from the vault key buys a boundary nothing in
this threat model crosses, at six more resources. The brief names *"too much scope"* as
the first way the capstone fails.

**Every key policy starts with the account-root statement.** Omitting it makes a CMK
permanently unmanageable and undeletable — there is no recovery path, including through
AWS support.

**Least privilege derived from the code, not the resource list.** The Lambda role's
permissions come from the two API calls `terraform/lambda/handler.py` actually makes
(`put_item`, `put_object`), plus the `sqs:SendMessage` grant GAP-06's DLQ requires — not
from the resource names. No `DescribeTable` (boto3's `Table()` is lazy and never calls
it), no `GetObject` (the handler only writes), no `kms:Encrypt`, `kms:ReEncrypt*`, or
`GenerateDataKeyWithoutPlaintext`.

**The bare bucket ARN was dropped, not kept for safety.** `s3:PutObject` evaluates against
`arn:aws:s3:::bucket/key` and can never match a bucket-level ARN. The starter's
`[bucket, bucket/*]` pair was valid only because `s3:*` contained bucket-level actions;
once the action narrows, that entry grants nothing.

**No KMS statement on the Lambda inline policy, deliberately.** The workload key policy
names the Lambda role directly as a `Principal`, which is complete authorization on its
own. DynamoDB never required one — it encrypts under a grant it holds itself rather than
under the caller's identity. Adding the statement would have been defensible as
defense-in-depth; describing it as *required* would not.

**Decrypt is split on the evidence CMK.** Matches AWS's published
`AllowCloudTrailDecryptTrail` shape — service-principal `Decrypt` unconditioned, while
`Encrypt`/`Describe` keep the confused-deputy `aws:SourceArn` pin. Account `:root` already
covers operator decrypt via IAM.

### Evidence vault

**GOVERNANCE retention is a sandbox posture, and the residual risk is stated rather than
dressed up.** Object Lock protects object *versions*, not the bucket, and only until
retention expires. COMPLIANCE mode would close only one of the three open deletion paths
(see *Residual risk*). GOVERNANCE keeps the sandbox destroyable. A production or CJIS
deployment inverts this — retention measured in years makes COMPLIANCE the only
defensible mode.

**The source primitive's `DenyBucketDeletion` bucket policy was dropped on purpose.** In a
single sandbox account, the operator the policy denies is the operator who can rewrite it.
It raises the appearance of enforcement without moving who holds control.

**No `force_destroy` on the vault.** Teardown is deliberately manual — empty, then destroy.
`force_destroy` would hand Terraform exactly the bulk-delete capability the vault exists to
deny. The *trail* bucket does carry `force_destroy = true`: different trust story, high
volume raw logs rather than curated evidence.

**Dedicated trail bucket, not the evidence vault.** The vault holds signed, curated
bundles; the trail holds high-volume raw API logs. Mixing them would apply Object Lock
retention to log noise and muddy chain of custody.

**`aws:SourceArn` pins must agree with the trail name.** Disagree and Terraform still
applies clean while CloudTrail silently stops delivering — `plan` cannot catch it. Trail
name and every `SourceArn` (KMS plus both bucket-policy statements) use one identifier.

### Network

**Gateway endpoints, not a NAT gateway.** S3 and DynamoDB are the only data-plane
dependencies; gateway endpoints are free and keep traffic on the AWS network.

**Private route table with no internet route.** Endpoints inject prefix-list routes;
claiming `0.0.0.0/0` would invent egress the design does not allow.

**Explicit DNS egress to the VPC CIDR.** Replaces default allow-all. Without UDP/TCP 53 to
AmazonProvidedDNS, hostname lookup fails before gateway routing and the intake path times
out.

**`depends_on` on the VPC-access role attachment.** Without ordering, apply can race and
fail `CreateNetworkInterface` even when the attachment is in the same plan.

### CI and state

**Two roles, not one.** `gha_plan` runs on any ref and can only read; `gha_apply` is
restricted to `refs/heads/main`. The separation is enforced by the trust policy's `sub`
condition — not by the workflow file, which anyone with push access can edit.

**SSE-S3 on state, not a CMK.** Keeps `kms:Decrypt` out of `gha_plan`, so the
workload/evidence two-CMK boundary survives CI's read path. Verified rather than
asserted: `simulate-principal-policy` on `gha_plan` returns `implicitDeny` for
`kms:Decrypt`, `s3:PutObject`, and `iam:CreateRole`. It buys nothing against
`gha_apply`, which holds `kms:*` on `Resource "*"` — subsumed by the
admin-equivalence recorded under *Residual risk*.

**`use_lockfile` instead of `dynamodb_table`.** S3-native locking, GA in Terraform 1.11.
The DynamoDB table is deprecated and would be a second resource to manage and grant IAM on.

**`required_version = ">= 1.15.8"` tracks the version recorded in the remote state object,**
not the version that introduced `use_lockfile`. Terraform refuses to read state written by
a newer binary, so a lower floor does not create a working path — it relocates the failure
from a clear error at `init` to a confusing one at `plan`.

### Policy gate

**`--all-namespaces` is mandatory.** The packages are `cgep.*`, and Conftest defaults to
`main`, which exits 0 with zero tests — a silent green. Called out in the README.

**Control mappings are taken verbatim from `GAPS.md`, not invented.** Every deny message
cites its control ID and the GAP it maps to.

### Control-mapping choices

**`SC.L2-3.13.11` and `03.13.11` are labelled as two schemes, not one ID belonging to
both.** The CMMC practice is built on 800-171 Rev 2 numbering; `03.13.11` is the Rev 3
identifier for the same requirement.

**`MP.L2-3.8.9` / `03.08.09` was deliberately *not* used for the evidence vault.** That
practice covers the confidentiality of backup information, says nothing about deletion,
and describes a backup location rather than an evidence store — wrong family, wrong verb.
It is also already assigned to GAP-04, so reusing it would spend one practice twice.

**`get-object-lock-configuration` returning `GOVERNANCE / Days: 30` is evidence the
configuration applied — never evidence the vault is immutable.** It returns the same green
answer on a vault the account can delete. This matters for Layer 4: the brief is blunt that
*"an OSCAL file that doesn't accurately describe the system is worse than having none."*

---

## Declared deviations

Departures from a literal reading of the brief or the acceptance criteria. Each was a
decision, not an oversight.

1. **Reserved concurrency is out of scope.** `GAPS.md` folds it into GAP-06, but this
   account's Lambda `ConcurrentExecutions` quota is 10, which cannot support a
   reservation. GAP-06 closes as DLQ + X-Ray only, and the suite ships **10 deny rules
   rather than eleven**.

2. **Layer 3 AC 9 is a declared deviation, not a pass.** It asks that `terraform plan` show
   the OIDC resources as additions. They were applied before the audit ran, so plan shows
   `No changes`. The equivalent — and stronger — evidence is that plan reports zero
   changes, replacements, or destroys against any Layer 1 resource.

3. **No `terraform apply` inside PRs #1–#4.** The Layer 1 baseline is applied once by hand
   after all four bullets land. Applying between increments would leave a half-built
   baseline.

4. **No `Closes` references anywhere.** GitHub Issues are disabled on this repo by
   choice; tracking is vault-side and this file.

5. **Deliberate non-claims.** No IA practice is claimed for "no long-lived access keys,"
   and no `SC.L2-3.13.*` is claimed for the state bucket's encryption. The control claimed
   should be the one the code implements.

---

## Residual risk and known limits

**`gha_apply` holds `iam:*` on `Resource "*"`, making it account-admin-equivalent.** It can
attach `AdministratorAccess` to itself. Accepted trade-off: assuming the role requires a
token minted from `refs/heads/main`, push access to which is held only by the repo owner,
who is already account admin — so the escalation grants nothing to anyone who lacks it.
Narrowing it to the exact action set the stack needs is deferred until the workflow exists
and that set is known.

**`terraform plan` in CI must run with `-lock=false`.** `ReadOnlyAccess` carries no
`s3:PutObject`, so the plan role cannot write the `.tflock` object. This is a locked
decision — a plan step without `-lock=false` is a build defect, not a discovery.

**Three deletion paths stay open on the evidence vault:**
1. An empty vault is deletable — `DeleteBucket` fails only because Object Lock keeps the
   bucket non-empty.
2. A version older than `evidence_retention_days` is deletable with ordinary
   `s3:DeleteObjectVersion`.
3. Unexpired GOVERNANCE retention is bypassable by a holder of
   `s3:BypassGovernanceRetention` — here, the operator.

**Bucket default retention applies only to PUTs without Object Lock headers.** A writer
holding `s3:PutObjectRetention` can set a short retain-until date, and COMPLIANCE would not
close that either. Reachable today only by the operator already named above; it becomes a
distinct risk once Layer 3 has its own writer.

**Unknown-at-plan-time values.** Terraform omits attributes unknown at plan time from
`planned_values` entirely — they are absent, not empty. On a from-scratch bootstrap plan
this would false-fire every rule that asserts a value Terraform computes at apply time —
a CMK ARN, a log-group ARN, subnet IDs, a rendered bucket policy — and fail one open. It
does not affect the intended path, where the gate plans against remote state of an
applied stack and every ARN is known. Handling it properly means cross-checking
`resource_changes[].change.after_unknown`; documented rather than built.

**The DLQ is inert under the current invocation model.** Lambda writes to
`dead_letter_config` only on *asynchronous* invocation failures, and API Gateway invokes
this function synchronously. The queue is correctly configured and will never receive a
message. GAP-06 closes as the brief specifies; genuine async-failure capture would require
restructuring the intake path. The real `SI.L2-3.14.6` evidence here is the API Gateway
access log, the Lambda `Errors` metric, and the X-Ray trace.

**The trail bucket holds two encryption generations, and no policy in this suite was
watching.** Until 2026-08-08 the trail carried no `kms_key_id`, so CloudTrail PUT each
log object with an explicit `x-amz-server-side-encryption: AES256` header. Bucket default
encryption is a *fallback* — it supplies a setting when the request specifies none, and
has no power to override a caller that states its own. The bucket therefore reported
`aws:kms` with the evidence CMK while its objects were **SSE-S3, under a key S3 manages
internally** — not an AWS-managed KMS key such as `aws/s3`, which would still have a key
policy and an audit trail. Setting `kms_key_id` on the trail fixed it. Encryption is
per-object and not retroactive, so the 754 objects written before the fix should be taken
as remaining `AES256`, with everything after CMK-encrypted.

*Evidence, separated from inference.* **Observed:** `get-bucket-encryption` returned
`aws:kms`; `head-object` returned `AES256` at six points spanning the full delivery
history; after the fix, `LatestDeliveryError` stayed empty, `LatestDeliveryTime` advanced,
and a newly delivered object returned `aws:kms` under the evidence CMK. **Mechanism, not
observation:** those three together are what establish delivery survived, because
`IsLogging` reads `true` even while every delivery fails on a KMS `AccessDenied` — that is
documented CloudTrail behaviour, never reproduced here. **Inferred:** that *all* 754
pre-fix objects were SSE-S3 (six samples plus the mechanism, not an exhaustive scan), and
that the CMK's two CloudTrail key-policy statements were never exercised (sound from the
mechanism, but nothing in the sweep observed KMS usage directly; the CloudTrail
`kms:GenerateDataKey` event history would prove it).

The honest generalisation is narrower than it first looked, and less flattering. **This
was a missing rule, not a limit of plan-time analysis.** `kms_key_id` is an ordinary
Terraform argument that Terraform renders into `planned_values`, so a correctly written
Rego rule on `aws_cloudtrail` fails the gate before a single object is written. No policy
in `policies/` references `aws_cloudtrail` at all. Writing one is Layer 2 work deferred
by choice, not Layer 3 work blocked by architecture.

**The rule has to be written in the guarded form, and the first draft of this section got
that wrong** — which is worth recording, because it is the same defect the M7 audit spent
two rounds removing from the suite. `kms_key_id != ""` **fails open**: on a create plan
the unset optional renders `null`, `null != ""` succeeds in Rego, the helper holds, the
`not` fails, and the gate goes green. Proven by evaluation, not argued:

| predicate | denies on `""` | denies on `null` |
|---|---|---|
| `kms_key_id != ""` | yes | **no** |
| `is_string(kms_key_id)` then `!= ""` | yes | yes |

The suite's own convention is already the guarded shape (`sc_3_13_11_encryption_at_rest.rego:20-36`
denies via `not sse_configured(...)`), and any rule added here must follow it.

**Coverage alone would not have caught this either.** GAP-01's rule filters
`bucket.name == "uploads"` per Decision 43, so it never evaluated the trail bucket — but
had it done so it would have **passed green anyway**, because the bucket's SSE
configuration genuinely was `aws:kms` with the CMK. The scoping is not what let this
through; the *altitude* is. A bucket-level encryption check is not evidence that the
objects in the bucket are encrypted that way. That is the genuine limit here, and it is
why a post-apply `head-object` spot-check is still worth having behind the trail rule.

The real finding underneath all of it: **the suite maps 1:1 to the eight starter gaps and
therefore watches nothing this repo built itself.** The remediations are unpoliced. This
is the first defect that found, and it is unlikely to be the only one.

**Teardown does not work from `make destroy` alone.** At 30 days GOVERNANCE it fails
`BucketNotEmpty` once any evidence object exists; locked versions must be removed first
with `aws s3api delete-object --bypass-governance-retention`, or the retention has to
expire. Separately, the versioning resource's destroy attempts
`PutBucketVersioning Status=Suspended`, which S3 rejects on an Object Lock bucket. Neither
is visible in `terraform plan`.

**`tfplan.json` is gitignored** — it embeds the account ID in ARNs.

---

## Open follow-ups

**Blocking Layer 4:**
- The `AC.L2-3.1.1` → `03.01.01` vs `03.01.02` Rev 3 pairing is unresolved and must be
  settled before Layer 4, where OSCAL dereferences the real catalog.
- Carry `03.13.08` (Transmission and Storage Confidentiality) alongside `03.13.11` in the
  OSCAL component definition — it is the more precise citation for encryption at rest.

**Before the CI workflow lands:**
- `.terraform.lock.hcl` is gitignored; commit it so CI pins the provider version rather
  than resolving the newest `5.x`.
- Revisit `gha_plan`'s `sub` breadth (`repo:OWNER/REPO:*`) once the workflow exists and the
  required patterns are known.

**README debt:**
- Teardown runbook — the empty-then-destroy sequence for the Object Lock vault, and the
  versioning-suspend failure.
- Teardown warning and import note for the OIDC provider: it is the account's only one and
  is now Terraform-managed, so `terraform destroy` here would break GitHub OIDC for
  anything else in the account.

**Not yet applied:**
- `aws:SecureTransport` deny on the evidence bucket (the uploads bucket has it as GAP-03).
- The evidence key's `Allow CloudTrail encrypt trail logs` Sid names a verb rather than
  the two actions it actually grants (`kms:GenerateDataKey*`, `kms:DescribeKey`).

**Verification — done 2026-08-08, against the live account:**
- `make test` returns a valid `submission_id`, so the scoped GAP-07 policy did not break
  the intake path.
- `terraform plan` reports **No changes**; `conftest test --all-namespaces` is 10/10 at
  exit 0; `opa test` is 39/39. All three re-run against the post-fix configuration — the
  first pass graded a plan generated before `kms_key_id` was added, which proved nothing
  about the code being shipped.
- Post-apply checks deferred from PRs #3–#4, all confirmed: trail `IsMultiRegionTrail`,
  `LogFileValidationEnabled`, `IsLogging`; uploads SSE-KMS under the workload CMK,
  versioning `Enabled`, SecureTransport deny present; DynamoDB SSE type `KMS`; Lambda
  `VpcConfig` with 2 subnets and 1 security group, tracing `Active`, DLQ attached; both
  gateway endpoints `available` on the private route table; evidence vault Object Lock
  `GOVERNANCE` / 30 days.
- Added by that sweep, and the reason it was worth running: `head-object` on the trail
  bucket showed `AES256` where the bucket config said `aws:kms`. See *Residual risk*.

**Owed, and reclassified after the 2026-08-08 sweep:**
- **A Rego rule for `aws_cloudtrail` requiring a CMK on the trail.** Layer 2, and it closes
  the defect found above at plan time. It must use the guarded form —
  `is_string(kms_key_id)` before `!= ""`, denied via `not has_trail_cmk(trail)` — because
  a bare `kms_key_id != ""` fails open on the `null` a create plan renders. Deferred by
  choice, not by architecture; see *Residual risk*.
- More broadly: the suite maps 1:1 to the eight starter gaps, so **nothing polices the
  remediations this repo added**. The trail-encryption defect is the first instance found;
  it is unlikely to be the only one.
- A post-apply `head-object` spot-check on the trail bucket, as defence in depth behind
  that rule rather than as the primary control.
