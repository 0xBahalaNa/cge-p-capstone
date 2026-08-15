# Capstone Writeup: decisions, deviations, and residual risk

**The primary framework for this capstone is CMMC Level 2, mapped to NIST SP 800-171
Rev 3.** I chose it over HIPAA and SOC 2 for three reasons. It is the only one of the three
that resolves to a numbered, machine-readable control catalog, which is what Layer 4 needs
to dereference honestly. Its practices map cleanly onto the eight gaps the starter names,
so the policy suite enforces real requirements rather than generic hygiene checks. And it
is the framework closest to the federal and public-safety work I do, so I can defend the
control interpretations rather than reciting them. HIPAA is the obvious primary for a
telehealth intake path, but the starter's own gap list undercuts that choice: GAP-06 cites
SOC 2 and CMMC only, with no HIPAA mapping at all, so HIPAA covers seven of the eight named
flaws while CMMC covers all eight. The scenario also puts a federal pilot on Acme's table as
one of the three flags it is pursuing at once, which makes CMMC a stated business driver
inside the brief rather than an outside preference.

The rest of this file is the record of *why* this capstone is shaped the way it is: the
trade-offs taken, the places it deliberately departs from the brief, the risk it does not
close, and the work still owed.

GitHub Issues are disabled on this repo, so this file, not an issue tracker, is where
deferred work and accepted risk live. Every entry below was a decision made during
Layers 1–2 (PRs #1–#7).

---

## Control coverage

Eight gaps, all eight addressed in Terraform, all eight policed by Rego, seven policies
covering eight gaps (GAP-01 and GAP-02 share `cgep.sc_3_13_11`).

| Gap | Remediated in | Enforced by | CMMC L2 | 800-171 r3 |
|---|---|---|---|---|
| GAP-01 | `hardening.tf:8` | `cgep.sc_3_13_11` | SC.L2-3.13.11 | 03.13.11 |
| GAP-02 | `main.tf:121` | `cgep.sc_3_13_11` | SC.L2-3.13.11 | 03.13.11 |
| GAP-03 | `hardening.tf:22` | `cgep.sc_3_13_08` | SC.L2-3.13.8 | 03.13.08 |
| GAP-04 | `hardening.tf:53` | `cgep.mp_3_08_09` | MP.L2-3.8.9 | 03.08.09 |
| GAP-05 | `main.tf:241`, `hardening.tf:63` | `cgep.sc_3_13_01` | SC.L2-3.13.1 | 03.13.01 |
| GAP-06 | `main.tf:231`, `hardening.tf:145` | `cgep.si_3_14_06` | SI.L2-3.14.6 | 03.14.06 |
| GAP-07 | `main.tf:184` | `cgep.ac_3_01_05` | AC.L2-3.1.5 | 03.01.05 |
| GAP-08 | `main.tf:280`, `hardening.tf:162` | `cgep.au_3_03_01` | AU.L2-3.3.1 | 03.03.01, 03.03.03 |

Every Rev 3 pairing above was resolved through the NIST 800-53 cross-framework mapping
table rather than inferred from the Rev 2 numbering, because Rev 3 consolidated and
renumbered rather than renaming in place. Two of the eight required a judgment call that
the numbering alone does not settle.

**AU.L2-3.3.1 spans two Rev 3 requirements.** CMMC 3.3.1 says create *and retain* audit
records. In Rev 3 that splits across `03.03.01` (event selection, from AU-2) and `03.03.03`
(record generation, from AU-12). The Terraform comments cite `03.03.01` alone. Rather than
churn five files the day before submission, the OSCAL component asserts both, since that is
the artifact where the catalog is actually dereferenced.

**SC.L2-3.13.11 is the cryptographic mechanism, not the at-rest property.** `03.13.11`
maps from SC-13. Protection of information at rest is SC-28. The usfed-compliance
crosswalk returns `03.08.05` for SC-28, but the NIST SP 800-171 Rev 3 catalog this
component declares as its `source` titles `03.08.05` *Media Transport*, nothing in this
system transports media. Rev 3's home for storage confidentiality here is `03.13.08`,
which the component asserts directly (uploads SecureTransport deny plus the uploads SSE-KMS
/ workload CMK addresses). No `related-requirement` prop is needed on `03.13.11`; the
package on `03.13.08` still covers transmission only.

---

## The five decisions the brief asks me to defend

**Region: `us-east-1`.** This is a sandbox holding synthetic data, so no residency
requirement binds. It also removes two small frictions: CloudTrail global service events
land natively, and `create-bucket` needs no `LocationConstraint`. If this held real PHI the
decision would be driven by the customer's data residency obligations, not convenience, and
I would say so in a change record rather than in a README.

**Object Lock: GOVERNANCE at 30 days.** COMPLIANCE is the stronger chain of custody because
nobody, including the account root, can delete a version before retention expires. I chose
GOVERNANCE because this is a teardownable sandbox and COMPLIANCE would make it genuinely
undestroyable for a month. That is a real weakening and I am not going to dress it up: any
holder of `s3:BypassGovernanceRetention` can delete evidence inside the retention window,
and in a single account that is the same operator who runs the pipeline. Retention is 30
days rather than 1 so that a grader checking a week from now still sees active protection.

**Apply strategy: automatic on merge to `main`.** The brief's first grading criterion is a
chain that runs without manual intervention, so a post-merge approval gate would trade the
thing being graded for a control I did not need. What stands between a pull request and a
deploy is therefore the policy gate and branch protection, not a human. I tightened both to
carry that weight: `main` requires the `gate` status check, and the apply role is assumable
only from `refs/heads/main`, so a pull request run cannot deploy even if the workflow were
edited to try.

**Account architecture: single account.** A separate evidence account is the correct answer
and I did not do it. Cost and setup time drove the call, but the honest consequence is that
the separation between workload and evidence in this build is a *key* boundary, not an
*account* boundary. Two CMKs with distinct key policies keep the Lambda role away from
evidence, which is real, but it does not survive an operator with the apply role. In a
production build the evidence vault belongs in an account whose only inbound principal is
the pipeline, and this is the first thing I would change with another sprint.

**Gap remediation: everything is fixed in Terraform; policy enforces that it stays fixed.**
I did not leave any gap open to be caught only by a Rego rule. A policy that blocks a gap
you never remediated does not protect anything, it just fails your own pipeline forever.
The policies exist as regression guards: they read `terraform show -json` planned values, so
they evaluate what is about to be built rather than what the HCL happens to say, and the red
pull request in this repo's history is the proof that they fire.

---

## Why it is built this way

### Keys and trust boundaries

**Two CMKs, not one.** A CMK is a trust boundary. A single key would mean the Lambda role
handling patient data also holds `kms:Decrypt` against the audit trail of its own
behavior, the exact separation an evidence vault exists to create. The thing being
audited must not hold the key to its own audit trail.

**Two, not three.** Splitting the trail key from the vault key buys a boundary nothing in
this threat model crosses, at six more resources. The brief names *"too much scope"* as
the first way the capstone fails.

**Every key policy starts with the account-root statement.** Omitting it makes a CMK
permanently unmanageable and undeletable, there is no recovery path, including through
AWS support.

**Least privilege derived from the code, not the resource list.** The Lambda role's
permissions come from the two API calls `terraform/lambda/handler.py` actually makes
(`put_item`, `put_object`), plus the `sqs:SendMessage` grant GAP-06's DLQ requires, not
from the resource names. No `DescribeTable` (boto3's `Table()` is lazy and never calls
it), no `GetObject` (the handler only writes), no `kms:Encrypt`, `kms:ReEncrypt*`, or
`GenerateDataKeyWithoutPlaintext`.

**The bare bucket ARN was dropped, not kept for safety.** `s3:PutObject` evaluates against
`arn:aws:s3:::bucket/key` and can never match a bucket-level ARN. The starter's
`[bucket, bucket/*]` pair was valid only because `s3:*` contained bucket-level actions;
once the action narrows, that entry grants nothing.

**No KMS statement on the Lambda inline policy, deliberately.** The workload key policy
names the Lambda role directly as a `Principal`, which is complete authorization on its
own. DynamoDB never required one, it encrypts under a grant it holds itself rather than
under the caller's identity. Adding the statement would have been defensible as
defense-in-depth; describing it as *required* would not.

**Decrypt is split on the evidence CMK.** Matches AWS's published
`AllowCloudTrailDecryptTrail` shape, service-principal `Decrypt` unconditioned, while
`Encrypt`/`Describe` keep the confused-deputy `aws:SourceArn` pin. Account `:root` already
covers operator decrypt via IAM.

### Evidence vault

**GOVERNANCE retention is a sandbox posture, and the residual risk is stated rather than
dressed up.** Object Lock protects object *versions*, not the bucket, and only until
retention expires. COMPLIANCE mode would close only one of the three open deletion paths
(see *Residual risk*). GOVERNANCE keeps the sandbox destroyable. A production or CJIS
deployment inverts this, retention measured in years makes COMPLIANCE the only
defensible mode.

**The source primitive's `DenyBucketDeletion` bucket policy was dropped on purpose.** In a
single sandbox account, the operator the policy denies is the operator who can rewrite it.
It raises the appearance of enforcement without moving who holds control.

**No `force_destroy` on the vault.** Teardown is deliberately manual, empty, then destroy.
`force_destroy` would hand Terraform exactly the bulk-delete capability the vault exists to
deny. The *trail* bucket does carry `force_destroy = true`: different trust story, high
volume raw logs rather than curated evidence.

**Dedicated trail bucket, not the evidence vault.** The vault holds signed, curated
bundles; the trail holds high-volume raw API logs. Mixing them would apply Object Lock
retention to log noise and muddy chain of custody.

**`aws:SourceArn` pins must agree with the trail name.** Disagree and Terraform still
applies clean while CloudTrail silently stops delivering, `plan` cannot catch it. Trail
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
condition, not by the workflow file, which anyone with push access can edit.

**SSE-S3 on state, not a CMK.** Keeps `kms:Decrypt` out of `gha_plan`, so the
workload/evidence two-CMK boundary survives CI's read path. Verified rather than
asserted: `simulate-principal-policy` on `gha_plan` returns `implicitDeny` for
`kms:Decrypt`, `s3:PutObject`, and `iam:CreateRole`. It buys nothing against
`gha_apply`, which holds `kms:*` on `Resource "*"`, subsumed by the
admin-equivalence recorded under *Residual risk*.

**`use_lockfile` instead of `dynamodb_table`.** S3-native locking, GA in Terraform 1.11.
The DynamoDB table is deprecated and would be a second resource to manage and grant IAM on.

**`required_version = ">= 1.15.8"` tracks the version recorded in the remote state object,**
not the version that introduced `use_lockfile`. Terraform refuses to read state written by
a newer binary, so a lower floor does not create a working path, it relocates the failure
from a clear error at `init` to a confusing one at `plan`.

### Detection layer

**Two metric filters on CloudTrail management events, not a CIS-14 set.**
`unauthorized_api` watches for AccessDenied / UnauthorizedOperation error codes;
`root_usage` watches for `userIdentity.type = Root`. Those two map to controls this
build already claims (03.14.06 and 03.01.05) and are detectable from the only event
class the trail captures. A larger filter set would pad the Continuous Monitoring
dimension without adding a control claim the OSCAL can defend.

**Alert routing stops at an unsubscribed SNS topic.** Alarms publish to
`aws_sns_topic.security_alerts`; no `aws_sns_topic_subscription` exists in Terraform.
The route is defined and testable with `aws sns publish`; the last hop would put an
email address in a public repo. Subscription is an out-of-band operator step.

**The nightly drift job fails loud.** The `drift` job runs `terraform plan
-detailed-exitcode` with no `continue-on-error`. Exit code 2 means the live account
diverged from the repo, and a red scheduled run *is* the detection. A drift check that
cannot fail is a cosmetic CI step.

### Policy gate

**`--all-namespaces` is mandatory.** The packages are `cgep.*`, and Conftest defaults to
`main`, which exits 0 with zero tests, a silent green. Called out in the README.

**Control mappings are taken verbatim from `GAPS.md`, not invented.** Every deny message
cites its control ID and the GAP it maps to.

### Control-mapping choices

**`SC.L2-3.13.11` and `03.13.11` are labelled as two schemes, not one ID belonging to
both.** The CMMC practice is built on 800-171 Rev 2 numbering; `03.13.11` is the Rev 3
identifier for the same requirement.

**`MP.L2-3.8.9` / `03.08.09` was deliberately *not* used for the evidence vault.** That
practice covers the confidentiality of backup information, says nothing about deletion,
and describes a backup location rather than an evidence store, wrong family, wrong verb.
It is also already assigned to GAP-04, so reusing it would spend one practice twice.

**`get-object-lock-configuration` returning `GOVERNANCE / Days: 30` is evidence the
configuration applied, never evidence the vault is immutable.** It returns the same green
answer on a vault the account can delete. This matters for Layer 4: the brief is blunt that
*"an OSCAL file that doesn't accurately describe the system is worse than having none."*

---

## Pipeline evidence flow, traced end to end

One real run, followed from commit to verifiable artifact. Run
[`31345660086`](https://github.com/0xBahalaNa/cge-p-capstone/actions/runs/31345660086), commit
`5af88e1`.

This run's apply failed on its first attempt. The stack adds `sns:*` to the apply role and
creates the SNS topic in the same `terraform apply`, so the already-assumed session did not
carry the grant it had just written, and `SNS:CreateTopic` returned `AuthorizationError`. The
grant itself persisted, so a re-run assumed a fresh session and completed. The fix is to land
permission changes in an apply ahead of the resources that consume them, which I have not
done. Steps 1 through 5 describe the successful attempt.

1. **Plan.** The `gate` job assumes the read-only OIDC role and runs
   `terraform plan -lock=false`, then renders it with `terraform show -json`. The plan runs
   unlocked because the role carries `ReadOnlyAccess` and the S3 backend's lock file is a
   write. A plan that never mutates state does not need to hold the lock.
2. **Policy check.** `conftest test --all-namespaces -p policies/ tfplan.json` plus
   `opa test policies/`. The job fails on the real exit code. There is no `|| true` and no
   `continue-on-error`, which means the gate is the only thing that decides whether step 3
   ever runs.
3. **Apply.** Only on a push to `main`, and only after `gate` passes. This job is where the
   apply role is first configured, so a pull request run never holds credentials that could
   deploy.
4. **Sign.** `scripts/capture-evidence.sh` assembles the plan JSON, the Conftest output, the
   `opa test` output, the apply log and a manifest into
   `evidence-<sha>-<timestamp>.tar.gz`, then Cosign signs it keylessly through the same
   GitHub OIDC token. No key material exists to be stolen, and the certificate binds the
   signature to this repository's workflow at a specific ref.
5. **Upload.** The tarball, its SHA-256 and the Cosign bundle land at
   `s3://$EVIDENCE_BUCKET/runs/5af88e1-20260810T010058Z/` under the evidence CMK, inheriting the vault's
   30-day GOVERNANCE retention.

Verification, run from a clean shell:

```console
$ scripts/verify-evidence.sh s3://$EVIDENCE_BUCKET/runs/5af88e1-20260810T010058Z/
Verifying evidence-5af88e1-20260810T010058Z.tar.gz from s3://acme-health-intake-evidence-cb45156c/runs/5af88e1-20260810T010058Z/evidence-5af88e1-20260810T010058Z.tar.gz
ok  integrity   SHA-256 matches evidence-5af88e1-20260810T010058Z.tar.gz.sha256
Verified OK
ok  signature   cosign identity and issuer match
ok  retention   GOVERNANCE until 2026-09-09T01:01:05.830000+00:00
ok  encryption  aws:kms
ok  identity    prefix, bundle, and manifest all name run 5af88e1-20260810T010058Z
CHAIN INTACT
scope: proves this bundle is intact, signed by the main-branch workflow, and under
       unexpired GOVERNANCE lock. Does not prove its plan is the plan the PR gate saw.
```

An evidence link committed to a repository can never name the bundle of its own commit. Writing
the link changes the commit, and the next merge produces a different bundle. The resting position
is a one-commit lag: the run cited above is the merge immediately before this one, and this commit
touches only Markdown and JSON, so it cannot have changed the plan the bundle contains. I checked
that claim rather than asserting it, on the last pair of merges where a documentation-only commit
followed a code one. The bundles for `1381094` and the Markdown-only merge after it have
byte-identical `conftest.txt`, `opa-test.txt` and `apply.txt`, and their `tfplan.json` files differ
in exactly one field, the top-level `timestamp`.

**Two seams in this chain, named rather than hidden.**

The gate evaluates a plan for commit X and the apply job re-plans commit X before applying.
It is the same commit against the same state, but it is not provably the same plan file. The
clean fix is to pass the approved plan between jobs as an artifact, which I did not do
because this repository is public and a Terraform plan carries the account ID and can carry
sensitive attribute values. A private repo should pass the artifact.

The signature is verifiable by anyone with the bundle, but the bundle lives in a private
vault. A third party cannot independently verify this chain without read access to the
account. Publishing the tarball would fix that and would also publish the account ID, so I
kept it private. A build that wanted public verifiability should sign a receipt containing
only hashes, publish that, and keep the evidence itself in the vault.

---

## What I did not complete

Named plainly, because the brief says there is no penalty for transparency and a grader will
find these anyway.

- **Reserved concurrency on the intake Lambda.** The account's `ConcurrentExecutions` quota
  is 10, which cannot support a reservation. GAP-06 closes on its DLQ and X-Ray halves only,
  and the policy checks only what is implemented rather than asserting a check it does not
  make.
- **WAF on the API.** Not attachable to an API Gateway HTTP API. GAP-08 closes on access
  logging and throttling.
- **The evidence vault's own control, `03.03.08`, is implemented but not asserted in OSCAL.**
  Object Lock protects audit information, which is AU-9 in Rev 3 terms. I left it out because
  I scoped the component definition to exactly the practices the policy suite enforces, and
  no policy checks the vault. Asserting it would have been defensible; asserting it silently
  would not.
- **No Rego rule guards this repo's own remediations.** The suite maps one to one onto the
  eight starter gaps, which means everything Layers 1 and 3 built is unpoliced. The
  CloudTrail `kms_key_id` defect in PR #8 is exactly what that blind spot produces.
- **754 CloudTrail objects predating PR #8 remain SSE-S3.** Object encryption is set at PUT
  and is not retroactive. Re-encrypting would mean copying every object, which changes their
  delivery timestamps and is worse for an audit trail than the honest note.
- **The uploads and evidence buckets are governed by different rules.** The TLS and
  versioning policies target the bucket `GAPS.md` names. The evidence and trail buckets are
  configured correctly in Layer 1 but no policy enforces it. A universal rule is the next
  sprint's work.
- **The API Gateway access log group is not CMK-encrypted.** Scoped out; the log group holds
  request metadata, not request bodies.

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
   `No changes`. The equivalent, and stronger, evidence is that plan reports zero
   changes, replacements, or destroys against any Layer 1 resource.

3. **No `terraform apply` inside PRs #1–#4.** The Layer 1 baseline is applied once by hand
   after all four bullets land. Applying between increments would leave a half-built
   baseline.

4. **No `Closes` references anywhere.** GitHub Issues are disabled on this repo by
   choice; tracking is vault-side and this file.

5. **Deliberate non-claims.** No IA practice is claimed for "no long-lived access keys,"
   and no `SC.L2-3.13.*` is claimed for the state bucket's encryption. The control claimed
   should be the one the code implements.

6. **No Terraform modules (Decision 63).** The layout stays flat eight `.tf` files. The
   IaC Quality 90–100 band asks for "clean modules & state"; modularising a working
   baseline on submission day trades a small band gain for a real chance of breaking an
   apply that is currently green. Declared here and in the README known-limits section.

7. **`gha_apply` stays broad with documented checkov skips (Decision 61, amending 39).**
   The role gains `sns:*` and `cloudwatch:*` for M11 detection resources, and seven
   checkov skip comments name Decision 39 rather than silencing the findings. Narrowing
   the action set on submission day risks a failed merge apply with no recovery window.

---

## Residual risk and known limits

**`gha_apply` holds `iam:*` on `Resource "*"`, making it account-admin-equivalent.** It can
attach `AdministratorAccess` to itself. Accepted trade-off: assuming the role requires a
token minted from `refs/heads/main`, push access to which is held only by the repo owner,
who is already account admin, so the escalation grants nothing to anyone who lacks it.
Narrowing it to the exact action set the stack needs is deferred until the workflow exists
and that set is known. The M11 checkov skips document that choice; they do not shrink it.

**Two detections are not coverage.** Unauthorized-API and root-usage alarms assert two
targeted signals from management events. They do not watch data-plane abuse, Config
drift rules, GuardDuty findings, or the other CIS filter patterns. An unsubscribed SNS
topic alerts nobody until an operator runs `aws sns subscribe`. A nightly
`terraform plan -detailed-exitcode` is not real-time detection, a hand-change in the
console can sit until 08:00 UTC before the badge turns red.

**`terraform plan` in CI must run with `-lock=false`.** `ReadOnlyAccess` carries no
`s3:PutObject`, so the plan role cannot write the `.tflock` object. This is a locked
decision, a plan step without `-lock=false` is a build defect, not a discovery.

**Three deletion paths stay open on the evidence vault:**
1. An empty vault is deletable, `DeleteBucket` fails only because Object Lock keeps the
   bucket non-empty.
2. A version older than `evidence_retention_days` is deletable with ordinary
   `s3:DeleteObjectVersion`.
3. Unexpired GOVERNANCE retention is bypassable by a holder of
   `s3:BypassGovernanceRetention`, here, the operator.

**Bucket default retention applies only to PUTs without Object Lock headers.** A writer
holding `s3:PutObjectRetention` can set a short retain-until date, and COMPLIANCE would not
close that either. Reachable today only by the operator already named above; it becomes a
distinct risk once Layer 3 has its own writer.

**Unknown-at-plan-time values.** Terraform omits attributes unknown at plan time from
`planned_values` entirely, they are absent, not empty. On a from-scratch bootstrap plan
this would false-fire every rule that asserts a value Terraform computes at apply time,
a CMK ARN, a log-group ARN, subnet IDs, a rendered bucket policy, and fail one open. It
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
encryption is a *fallback*, it supplies a setting when the request specifies none, and
has no power to override a caller that states its own. The bucket therefore reported
`aws:kms` with the evidence CMK while its objects were **SSE-S3, under a key S3 manages
internally**, not an AWS-managed KMS key such as `aws/s3`, which would still have a key
policy and an audit trail. Setting `kms_key_id` on the trail fixed it. Encryption is
per-object and not retroactive, so the 754 objects written before the fix should be taken
as remaining `AES256`, with everything after CMK-encrypted.

*Evidence, separated from inference.* **Observed:** `get-bucket-encryption` returned
`aws:kms`; `head-object` returned `AES256` at six points spanning the full delivery
history; after the fix, `LatestDeliveryError` stayed empty, `LatestDeliveryTime` advanced,
and a newly delivered object returned `aws:kms` under the evidence CMK. **Mechanism, not
observation:** those three together are what establish delivery survived, because
`IsLogging` reads `true` even while every delivery fails on a KMS `AccessDenied`, that is
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
that wrong**, which is worth recording, because it is the same defect the M7 audit spent
two rounds removing from the suite. A bare `kms_key_id != ""` **fails open on `null`**:
in Rego, `null != ""` succeeds, the helper holds, `not helper` fails, and the gate goes
green. Proven on a *synthetic* input (not this repo's live plan shape):

| predicate | denies on `""` | denies on `null` |
|---|---|---|
| `kms_key_id != ""` | yes | **no** |
| `is_string(kms_key_id)` then `!= ""` | yes | yes |

The guarded shape, deny via `not helper(...)` after the helper rejects both `""` and
`null` with `is_string`, is the convention any *new* rule (including a trail
`kms_key_id` check) must follow. This repo's live plan does **not** currently exercise
that hole for the three existing helpers: `sse_configured` sees `kms_master_key_id: ""`
on AES256 (so `!= ""` is false and the GAP-01 deny fires), `has_dynamodb_cmk` sees an
omitted `kms_key_arn` key (bare reference undefined → GAP-02 deny fires), and
`destination_arn` is Required when `access_log_settings` exists. The provider *does*
emit `null` for other optional attributes in the same plan; on a synthetic null input the
unguarded form goes vacuous. Do not copy `!= ""` into a new rule.

**Coverage alone would not have caught this either.** GAP-01's rule filters
`bucket.name == "uploads"` per Decision 43, so it never evaluated the trail bucket, but
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

**`tfplan.json` is gitignored**, it embeds the account ID in ARNs.

---

## Open follow-ups

**Settled, not yet applied to the Terraform comments:**
- `terraform/oidc-trust.tf:3` pairs `AC.L2-3.1.1` with `03.01.01` (Account Management, from
  AC-2). OIDC trust conditions are access *enforcement*, which is AC-3, so the correct
  pairing is `03.01.02`. Confirmed against the 800-53 mapping table. It is a one-line
  comment fix and it is not worth a submission-day PR on its own.
- `03.13.08` alongside `03.13.11` for encryption at rest is resolved and reflected in the
  OSCAL component. See *Control coverage* above.

**Before the CI workflow lands:**
- `.terraform.lock.hcl` is gitignored; commit it so CI pins the provider version rather
  than resolving the newest `5.x`.
- Revisit `gha_plan`'s `sub` breadth (`repo:OWNER/REPO:*`) once the workflow exists and the
  required patterns are known.

**README debt:**
- Teardown runbook, the empty-then-destroy sequence for the Object Lock vault, and the
  versioning-suspend failure.
- Teardown warning and import note for the OIDC provider: it is the account's only one and
  is now Terraform-managed, so `terraform destroy` here would break GitHub OIDC for
  anything else in the account.

**Not yet applied:**
- `aws:SecureTransport` deny on the evidence bucket (the uploads bucket has it as GAP-03).
- The evidence key's `Allow CloudTrail encrypt trail logs` Sid names a verb rather than
  the two actions it actually grants (`kms:GenerateDataKey*`, `kms:DescribeKey`).

**Verification, done 2026-08-08, against the live account:**
- `make test` returns a valid `submission_id`, so the scoped GAP-07 policy did not break
  the intake path.
- `terraform plan` reports **No changes**; `conftest test --all-namespaces` is 10/10 at
  exit 0; `opa test` is 39/39. All three re-run against the post-fix configuration, the
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
  the defect found above at plan time. It must use the guarded form:
  `is_string(kms_key_id)` before `!= ""`, denied via `not has_trail_cmk(trail)`, because
  a bare `kms_key_id != ""` fails open on the `null` a create plan renders. Deferred by
  choice, not by architecture; see *Residual risk*.
- More broadly: the suite maps 1:1 to the eight starter gaps, so **nothing polices the
  remediations this repo added**. The trail-encryption defect is the first instance found;
  it is unlikely to be the only one.
- A post-apply `head-object` spot-check on the trail bucket, as defence in depth behind
  that rule rather than as the primary control.

**Owed: confirmed Rego fail-open defects (M9 audit, 2026-08-09).** Named specifically
because the OSCAL still cites these packages as enforcement. Fixing them is a Layer 2
suite rewrite plus tests; `policies/` is out of this PR's staged set. Same finding class
as the trail rule above.

- **O1: uploads companions join by Terraform label, not bucket id.**
  `versioning_enabled` (`mp_3_08_09:20`), `sse_configured` (`sc_3_13_11:21`), and
  `secure_transport_on_bucket` (`sc_3_13_08:35`) match `resource.name == "uploads"`, never
  `values.bucket`. Repoint a companion at another bucket while keeping the Terraform label
  and all three packages return `[]`, GAP-01, GAP-03 and GAP-04 live at once with the gate
  green.
- **O2: `cgep.ac_3_01_05` collapses when `policy` is unknown at plan time.** On a
  greenfield plan (the state the README teardown section invites a grader to produce)
  Terraform omits `policy` from `planned_values`, `json.unmarshal` at
  `ac_3_01_05_least_privilege.rego:38` is undefined, and the rule returns `[]` even for
  `Action: "*"`. The suite reports green on the exact first apply that stands up the
  wildcard policy.
- **O3: `cgep.ac_3_01_05` is blind to `NotAction`.**
  `{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}` returns `[]`. Broader
  than the `dynamodb:*` wildcard GAP-07 describes.
- **O4: `has_dynamodb_cmk` never checks `enabled`.**
  `{"enabled": false, "kms_key_arn": "arn:..."}` passes while DynamoDB encrypts under the
  AWS-owned key, GAP-02 verbatim.
- **O5: `has_dlq` is the bare-reference form sibling policies wrote comments against.**
  `fn.values.dead_letter_config[_]` (`si_3_14_06`); contrast `au_3_03_01:15` ("assert the
  HCL literals, not list presence") and `sc_3_13_01:15` ("count, not bare ref").
  `[{"target_arn": ""}]` returns `[]`.
- **O6: null-vs-`""` convention (pairs with the Residual-risk truth table).** The
  unguarded `!= ""` form fails open on synthetic `null` input. These three helpers are
  *not* currently reached by that shape in this repo's plan (`""`, omitted key, or
  Required field), keep the recommendation for any new rule; do not claim the defect is
  live today.
