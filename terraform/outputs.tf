output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "Evidence vault bucket name."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.mgmt.name
  description = "CloudTrail trail name."
}

output "workload_kms_key_arn" {
  value       = aws_kms_key.workload.arn
  description = "Workload CMK ARN (uploads + DynamoDB)."
}

output "evidence_kms_key_arn" {
  value       = aws_kms_key.evidence.arn
  description = "Evidence CMK ARN (vault + trail)."
}

output "gha_plan_role_arn" {
  value       = aws_iam_role.gha_plan.arn
  description = "GitHub Actions OIDC role for terraform plan (ReadOnlyAccess)."
}

output "gha_apply_role_arn" {
  value       = aws_iam_role.gha_apply.arn
  description = "GitHub Actions OIDC role for terraform apply (main branch only)."
}
