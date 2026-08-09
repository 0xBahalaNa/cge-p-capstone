# METADATA
# title: SC.L2-3.13.8 — TLS-only access to uploads bucket
# custom:
#   framework: CMMC-L2
#   controls:
#     - "SC.L2-3.13.8"
#   gaps:
#     - GAP-03
#   severity: high
#   remediation: "Add a Deny statement on the uploads bucket policy with Condition Bool aws:SecureTransport false."
package cgep.sc_3_13_08

import rego.v1

# true when unmarshaled policy has a Deny that requires TLS.
# Bool value may be a string ("false") or a single-element list — both appear in AWS JSON.
has_secure_transport_deny(policy_res) if {
	doc := json.unmarshal(policy_res.values.policy)
	stmt := doc.Statement[_]
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

has_secure_transport_deny(policy_res) if {
	doc := json.unmarshal(policy_res.values.policy)
	stmt := doc.Statement[_]
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"][_] == "false"
}

# Companion policy shares Terraform name with the bucket (Decision 38 pattern).
secure_transport_on_bucket(bucket_name) if {
	pol := input.planned_values.root_module.resources[_]
	pol.type == "aws_s3_bucket_policy"
	pol.name == bucket_name
	has_secure_transport_deny(pol)
}

# Anchor on the bucket — iterating only aws_s3_bucket_policy fails open when it is deleted.
deny contains msg if {
	bucket := input.planned_values.root_module.resources[_]
	bucket.type == "aws_s3_bucket"
	bucket.name == "uploads"
	not secure_transport_on_bucket(bucket.name)
	msg := sprintf("SC.L2-3.13.8 (GAP-03): aws_s3_bucket.%s missing aws:SecureTransport deny on bucket policy", [bucket.name])
}
