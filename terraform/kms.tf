######################################################################
# KMS — two CMKs (trust boundaries).
# Workload: uploads bucket + DynamoDB (GAP-01/02). Evidence: vault + CloudTrail.
# CMMC L2: SC.L2-3.13.11 · NIST SP 800-171 Rev 3: 03.13.11 (Cryptographic Protection)
######################################################################

# Account ID for key-policy ARNs — never hardcode (S-1).
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "workload" {
  description             = "CMK for intake uploads bucket and DynamoDB submissions table"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days

  # Inline jsonencode matches main.tf.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Trap: omit :root → key unmanageable. :root = account principal, not root user.
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "Allow Lambda use of the key"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action = [
          "kms:DescribeKey",
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Name = "${local.name_prefix}-workload-cmk" }
}

resource "aws_kms_alias" "workload" {
  name          = "alias/${local.name_prefix}-workload-${local.suffix}"
  target_key_id = aws_kms_key.workload.key_id
}

resource "aws_kms_key" "evidence" {
  description             = "CMK for evidence vault and CloudTrail log bucket"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # CloudTrail encrypt (M3). SourceArn = confused-deputy guard. Trail name must match cloudtrail.tf.
        # https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html
        Sid       = "Allow CloudTrail encrypt trail logs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-mgmt-${local.suffix}"
          }
        }
      },
      {
        Sid       = "Allow CloudTrail decrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:Decrypt"
        Resource  = "*"
      }
    ]
  })

  tags = { Name = "${local.name_prefix}-evidence-cmk" }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence-${local.suffix}"
  target_key_id = aws_kms_key.evidence.key_id
}
