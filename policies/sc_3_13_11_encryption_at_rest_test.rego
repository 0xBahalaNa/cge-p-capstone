package cgep.sc_3_13_11_test

import data.cgep.sc_3_13_11 as policy
import rego.v1

# Compliant: uploads SSE-KMS + DynamoDB CMK present
compliant_input := {"planned_values": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
	{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": "aws:kms",
			"kms_master_key_id": "arn:aws:kms:us-east-1:synthetic:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		}]}]},
	},
	{
		"type": "aws_dynamodb_table",
		"name": "intake",
		"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:synthetic:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]},
	},
]}}}

test_gap01_fires_when_sse_absent if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_dynamodb_table",
			"name": "intake",
			"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:synthetic:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]},
		},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-01")
}

test_gap01_silent_when_sse_kms if {
	count(policy.deny) == 0 with input as compliant_input
}

test_gap02_fires_when_encryption_block_absent if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "aws:kms",
				"kms_master_key_id": "arn:aws:kms:us-east-1:synthetic:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			}]}]},
		},
		{"type": "aws_dynamodb_table", "name": "intake", "values": {}},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-02")
}

test_gap01_fires_when_kms_master_key_id_empty if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "aws:kms",
				"kms_master_key_id": "",
			}]}]},
		},
		{
			"type": "aws_dynamodb_table",
			"name": "intake",
			"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:synthetic:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]},
		},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-01")
}

test_gap02_fires_when_kms_key_arn_empty if {
	inp := {"planned_values": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads", "values": {"bucket": "acme-health-uploads-test"}},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "aws:kms",
				"kms_master_key_id": "arn:aws:kms:us-east-1:synthetic:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			}]}]},
		},
		{"type": "aws_dynamodb_table", "name": "intake", "values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": ""}]}},
	]}}}
	msgs := policy.deny with input as inp
	count(msgs) == 1
	some msg in msgs
	contains(msg, "GAP-02")
}

test_gap02_silent_when_cmk_present if {
	count(policy.deny) == 0 with input as compliant_input
}

test_empty_resources_no_deny if {
	count(policy.deny) == 0 with input as {"planned_values": {"root_module": {"resources": []}}}
}
