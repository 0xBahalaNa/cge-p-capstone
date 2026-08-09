# METADATA
# title: MP.L2-3.8.9 — versioning on uploads bucket
# custom:
#   framework: CMMC-L2
#   controls:
#     - "MP.L2-3.8.9"
#   gaps:
#     - GAP-04
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning on uploads with versioning_configuration status Enabled."
package cgep.mp_3_08_09

import rego.v1

# Anchor on the bucket (same pattern as sc_3_13_11). Iterating only the versioning
# resource fails open when that resource is deleted — which IS GAP-04.
versioning_enabled(bucket_name) if {
	v := input.planned_values.root_module.resources[_]
	v.type == "aws_s3_bucket_versioning"
	v.name == bucket_name
	v.values.versioning_configuration[_].status == "Enabled"
}

deny contains msg if {
	bucket := input.planned_values.root_module.resources[_]
	bucket.type == "aws_s3_bucket"
	bucket.name == "uploads"
	not versioning_enabled(bucket.name)
	msg := sprintf("MP.L2-3.8.9 (GAP-04): aws_s3_bucket.%s has no Enabled versioning configuration", [bucket.name])
}
