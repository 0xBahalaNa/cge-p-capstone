# METADATA
# title: SC.L2-3.13.1 — Lambda VPC boundary placement
# custom:
#   framework: CMMC-L2
#   controls:
#     - "SC.L2-3.13.1"
#   gaps:
#     - GAP-05
#   severity: high
#   remediation: "Add vpc_config on aws_lambda_function.intake with private subnet_ids and security_group_ids."
package cgep.sc_3_13_01

import rego.v1

# Empty subnet/SG lists bind on [_] — require non-empty lists (count, not bare ref).
has_vpc_config(fn) if {
	cfg := fn.values.vpc_config[_]
	count(cfg.subnet_ids) > 0
	count(cfg.security_group_ids) > 0
}

deny contains msg if {
	fn := input.planned_values.root_module.resources[_]
	fn.type == "aws_lambda_function"
	not has_vpc_config(fn)
	msg := sprintf("SC.L2-3.13.1 (GAP-05): aws_lambda_function.%s missing vpc_config", [fn.name])
}
