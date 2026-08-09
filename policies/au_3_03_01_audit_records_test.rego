package cgep.au_3_03_01_test

import data.cgep.au_3_03_01 as policy
import rego.v1

compliant_stage := {"planned_values": {"root_module": {"resources": [{
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"values": {
		"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:synthetic:log-group:/aws/apigateway/test", "format": "{}"}],
		"default_route_settings": [{"throttling_burst_limit": 50, "throttling_rate_limit": 100}],
	},
}]}}}

# Provider-default shape when throttling is unconfigured (not key-absent).
_zeroed_route_settings := [{"throttling_burst_limit": 0, "throttling_rate_limit": 0, "logging_level": ""}]

test_gap08_fires_when_access_logs_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_apigatewayv2_stage",
		"name": "default",
		"values": {"default_route_settings": [{"throttling_burst_limit": 50, "throttling_rate_limit": 100}]},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-08")
	contains(msg, "access_log_settings")
	contains(msg, "AU.L2-3.3.1")
}

test_gap08_silent_when_access_logs_present if {
	count(policy.deny) == 0 with input as compliant_stage
}

test_gap08_fires_when_throttling_zeroed if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_apigatewayv2_stage",
		"name": "default",
		"values": {
			"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:synthetic:log-group:/aws/apigateway/test", "format": "{}"}],
			"default_route_settings": _zeroed_route_settings,
		},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-08")
	contains(msg, "default_route_settings")
}

test_gap08_silent_when_throttling_present if {
	count(policy.deny) == 0 with input as compliant_stage
}

test_gap08_fires_when_both_blocks_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_apigatewayv2_stage",
		"name": "default",
		"values": {},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 2
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
