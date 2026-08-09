package cgep.si_3_14_06_test

import data.cgep.si_3_14_06 as policy
import rego.v1

# Decision B: GAP-06 = DLQ + X-Ray only (no reserved concurrency deny).

compliant_lambda := {"planned_values": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"values": {
		"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:synthetic:acme-health-dlq-test"}],
		"tracing_config": [{"mode": "Active"}],
	},
}]}}}

test_gap06_fires_when_tracing_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_lambda_function",
		"name": "intake",
		"values": {"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:synthetic:acme-health-dlq-test"}]},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-06")
	contains(msg, "tracing")
}

test_gap06_silent_when_tracing_active if {
	count(policy.deny) == 0 with input as compliant_lambda
}

test_gap06_fires_when_dlq_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_lambda_function",
		"name": "intake",
		"values": {"tracing_config": [{"mode": "Active"}]},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-06")
	contains(msg, "dead_letter_config")
}

test_gap06_silent_when_dlq_present if {
	count(policy.deny) == 0 with input as compliant_lambda
}

test_gap06_fires_when_both_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_lambda_function",
		"name": "intake",
		"values": {},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 2
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
