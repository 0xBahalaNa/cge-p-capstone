# METADATA
# title: SC.L2-3.13.11 — customer-managed keys on PHI data stores
# custom:
#   framework: CMMC-L2
#   controls:
#     - "SC.L2-3.13.11"
#   gaps:
#     - GAP-01
#     - GAP-02
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm aws:kms, and set server_side_encryption with kms_key_arn on the DynamoDB table."
package cgep.sc_3_13_11

import rego.v1

# GAP-01 helper: SSE resource shares Terraform name with the bucket (Decision 38).
# Nested blocks are lists in planned_values JSON — walk with [_].
sse_configured(bucket_name) if {
	sse := input.planned_values.root_module.resources[_]
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
	sse.name == bucket_name
	default_sse := sse.values.rule[_].apply_server_side_encryption_by_default[_]
	default_sse.sse_algorithm == "aws:kms"

	# Bare reference accepts "" — provider renders unset optional strings as empty.
	default_sse.kms_master_key_id != ""
}

# GAP-01: uploads bucket only (Decision 43) — not evidence/trail.
deny contains msg if {
	bucket := input.planned_values.root_module.resources[_]
	bucket.type == "aws_s3_bucket"
	bucket.name == "uploads"
	not sse_configured(bucket.name)
	msg := sprintf("SC.L2-3.13.11 (GAP-01): aws_s3_bucket.%s has no SSE-KMS configuration with a customer CMK", [bucket.name])
}

has_dynamodb_cmk(table) if {
	enc := table.values.server_side_encryption[_]

	# Bare reference accepts "" — unset optional strings render as empty in plan JSON.
	enc.kms_key_arn != ""
}

deny contains msg if {
	table := input.planned_values.root_module.resources[_]
	table.type == "aws_dynamodb_table"
	not has_dynamodb_cmk(table)
	msg := sprintf("SC.L2-3.13.11 (GAP-02): aws_dynamodb_table.%s missing CMK server_side_encryption", [table.name])
}
