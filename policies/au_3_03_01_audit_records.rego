# METADATA
# title: AU.L2-3.3.1 — API Gateway access logging and throttling
# custom:
#   framework: CMMC-L2
#   controls:
#     - "AU.L2-3.3.1"
#   gaps:
#     - GAP-08
#   severity: high
#   remediation: "On aws_apigatewayv2_stage.default, set access_log_settings to a CloudWatch log group and default_route_settings with throttling_burst_limit and throttling_rate_limit."
package cgep.au_3_03_01

import rego.v1

# Provider emits empty blocks when unset — assert the HCL literals, not list presence.
has_access_logs(stage) if {
	s := stage.values.access_log_settings[_]
	s.destination_arn != ""
}

has_throttling(stage) if {
	s := stage.values.default_route_settings[_]
	s.throttling_rate_limit > 0
	s.throttling_burst_limit > 0
}

deny contains msg if {
	stage := input.planned_values.root_module.resources[_]
	stage.type == "aws_apigatewayv2_stage"
	not has_access_logs(stage)
	msg := sprintf("AU.L2-3.3.1 (GAP-08): aws_apigatewayv2_stage.%s missing access_log_settings", [stage.name])
}

deny contains msg if {
	stage := input.planned_values.root_module.resources[_]
	stage.type == "aws_apigatewayv2_stage"
	not has_throttling(stage)
	msg := sprintf("AU.L2-3.3.1 (GAP-08): aws_apigatewayv2_stage.%s missing default_route_settings throttling", [stage.name])
}
