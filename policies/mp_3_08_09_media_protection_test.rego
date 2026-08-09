package cgep.mp_3_08_09_test

import data.cgep.mp_3_08_09 as policy
import rego.v1

test_gap04_fires_when_versioning_not_enabled if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_versioning",
			"name": "uploads",
			"values": {"versioning_configuration": [{"status": "Suspended"}]},
		},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-04")
	contains(msg, "MP.L2-3.8.9")
}

test_gap04_silent_when_enabled if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_versioning",
			"name": "uploads",
			"values": {"versioning_configuration": [{"status": "Enabled"}]},
		},
	]}}}
	count(policy.deny) == 0 with input as inp
}

# R-8: versioning resource removed entirely (real GAP-04 re-introduction)
test_gap04_fires_when_versioning_resource_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-04")
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
