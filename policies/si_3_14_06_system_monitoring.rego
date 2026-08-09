# METADATA
# title: SI.L2-3.14.6 — Lambda DLQ and X-Ray tracing
# custom:
#   framework: CMMC-L2
#   controls:
#     - "SI.L2-3.14.6"
#   gaps:
#     - GAP-06
#   severity: high
#   remediation: "On aws_lambda_function.intake set dead_letter_config and tracing_config mode Active."
package cgep.si_3_14_06

import rego.v1

has_active_tracing(fn) if {
	fn.values.tracing_config[_].mode == "Active"
}

has_dlq(fn) if {
	fn.values.dead_letter_config[_]
}

deny contains msg if {
	fn := input.planned_values.root_module.resources[_]
	fn.type == "aws_lambda_function"
	not has_active_tracing(fn)
	msg := sprintf("SI.L2-3.14.6 (GAP-06): aws_lambda_function.%s tracing not Active", [fn.name])
}

deny contains msg if {
	fn := input.planned_values.root_module.resources[_]
	fn.type == "aws_lambda_function"
	not has_dlq(fn)
	msg := sprintf("SI.L2-3.14.6 (GAP-06): aws_lambda_function.%s missing dead_letter_config", [fn.name])
}
