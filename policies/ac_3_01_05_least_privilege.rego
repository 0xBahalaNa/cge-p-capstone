# METADATA
# title: AC.L2-3.1.5 — least privilege on IAM role policies
# description: >
#   Skips Terraform resources whose name starts with gha_ (Decision 39) —
#   the OIDC apply role uses service wildcards by design (accepted control-plane risk).
# custom:
#   framework: CMMC-L2
#   controls:
#     - "AC.L2-3.1.5"
#   gaps:
#     - GAP-07
#   severity: high
#   remediation: "On aws_iam_role_policy.lambda_inline, replace Action wildcards (dynamodb:*, s3:*) with the specific API actions the Lambda needs (e.g. dynamodb:PutItem, s3:PutObject)."
package cgep.ac_3_01_05

import rego.v1

# Action may be a JSON string or a list — normalize to a list for iteration.
actions_list(stmt) := stmt.Action if {
	is_array(stmt.Action)
}

actions_list(stmt) := [stmt.Action] if {
	is_string(stmt.Action)
}

# Prefix forms (s3:Get*, dynamodb:Batch*) are wildcards too — any "*" in Action.
is_action_wildcard(action) if {
	contains(action, "*")
}

# Match Action wildcards only — Resource=* is OK (X-Ray, apply role).
# Skip gha_* Terraform names (Decision 39). Scan Allow only — Deny tightens privilege.
deny contains msg if {
	res := input.planned_values.root_module.resources[_]
	res.type == "aws_iam_role_policy"
	not startswith(res.name, "gha_")
	policy := json.unmarshal(res.values.policy)
	stmt := policy.Statement[_]
	stmt.Effect == "Allow"
	action := actions_list(stmt)[_]
	is_action_wildcard(action)
	msg := sprintf("AC.L2-3.1.5 (GAP-07): aws_iam_role_policy.%s grants Action wildcard %q", [res.name, action])
}
