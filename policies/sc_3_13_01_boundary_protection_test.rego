package cgep.sc_3_13_01_test

import data.cgep.sc_3_13_01 as policy
import rego.v1

test_gap05_fires_when_vpc_config_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_lambda_function",
		"name": "intake",
		"values": {},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-05")
	contains(msg, "SC.L2-3.13.1")
}

test_gap05_silent_when_vpc_config_present if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_lambda_function",
		"name": "intake",
		"values": {"vpc_config": [{"subnet_ids": ["subnet-aaa"], "security_group_ids": ["sg-aaa"]}]},
	}]}}}
	count(policy.deny) == 0 with input as inp
}

# Provider-shaped empty lists — [_] binds, but count == 0 must still deny.
test_gap05_fires_when_vpc_config_lists_empty if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_lambda_function",
		"name": "intake",
		"values": {"vpc_config": [{"subnet_ids": [], "security_group_ids": [], "vpc_id": ""}]},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-05")
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
