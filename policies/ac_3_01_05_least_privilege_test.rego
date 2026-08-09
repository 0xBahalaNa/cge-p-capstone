package cgep.ac_3_01_05_test

import data.cgep.ac_3_01_05 as policy
import rego.v1

test_gap07_fires_on_action_wildcard if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "lambda_inline",
		"values": {"policy": json.marshal({"Statement": [{
			"Effect": "Allow",
			"Action": ["dynamodb:*", "s3:PutObject"],
			"Resource": "*",
		}]})},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-07")
	contains(msg, "AC.L2-3.1.5")
	contains(msg, "dynamodb:*")
}

test_gap07_silent_on_specific_actions if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "lambda_inline",
		"values": {"policy": json.marshal({"Statement": [{
			"Effect": "Allow",
			"Action": ["dynamodb:PutItem", "s3:PutObject"],
			"Resource": "arn:aws:dynamodb:us-east-1:synthetic:table/acme-health-submissions-test",
		}]})},
	}]}}}
	count(policy.deny) == 0 with input as inp
}

# Decision 39: gha_* policies may carry service wildcards
test_gap07_silent_on_gha_apply_wildcards if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "gha_apply",
		"values": {"policy": json.marshal({"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:*", "sqs:*"],
			"Resource": "*",
		}]})},
	}]}}}
	count(policy.deny) == 0 with input as inp
}

test_gap07_fires_on_star_action if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "lambda_inline",
		"values": {"policy": json.marshal({"Statement": [{
			"Effect": "Allow",
			"Action": "*",
			"Resource": "*",
		}]})},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-07")
}

# Prefix wildcards (s3:Get*) must fire — not only "*" / "service:*"
test_gap07_fires_on_prefix_wildcard if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "lambda_inline",
		"values": {"policy": json.marshal({"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:Get*", "dynamodb:PutItem"],
			"Resource": "*",
		}]})},
	}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "s3:Get*")
}

# Explicit Deny with a wildcard tightens privilege — must stay silent.
test_gap07_silent_on_deny_wildcard if {
	inp := {"planned_values": {"root_module": {"resources": [{
		"type": "aws_iam_role_policy",
		"name": "lambda_inline",
		"values": {"policy": json.marshal({"Statement": [
			{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "*"},
			{"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
		]})},
	}]}}}
	count(policy.deny) == 0 with input as inp
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
