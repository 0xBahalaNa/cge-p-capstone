package cgep.sc_3_13_08_test

import data.cgep.sc_3_13_08 as policy
import rego.v1

_secure_policy := json.marshal({"Statement": [{
	"Effect": "Deny",
	"Action": "s3:*",
	"Principal": "*",
	"Resource": ["arn:aws:s3:::acme-health-uploads-test", "arn:aws:s3:::acme-health-uploads-test/*"],
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}]})

_insecure_policy := json.marshal({"Statement": [{
	"Effect": "Allow",
	"Action": "s3:GetObject",
	"Principal": "*",
	"Resource": "arn:aws:s3:::acme-health-uploads-test/*",
}]})

test_gap03_fires_when_secure_transport_absent if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_policy",
			"name": "uploads",
			"values": {"policy": _insecure_policy},
		},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-03")
	contains(msg, "SC.L2-3.13.8")
}

test_gap03_silent_when_secure_transport_deny if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_policy",
			"name": "uploads",
			"values": {"policy": _secure_policy},
		},
	]}}}
	count(policy.deny) == 0 with input as inp
}

test_gap03_fires_when_policy_document_empty_statements if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_policy",
			"name": "uploads",
			"values": {"policy": json.marshal({"Statement": []})},
		},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-03")
}

# R-8: bucket policy resource removed entirely (real GAP-03 re-introduction)
test_gap03_fires_when_bucket_policy_absent if {
	inp := {"planned_values": {"root_module": {"resources": [{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}}]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-03")
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
