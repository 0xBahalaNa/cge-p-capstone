######################################################################
# CloudTrail — multi-region management events to dedicated log bucket.
# CMMC L2: AU.L2-3.3.1 · NIST SP 800-171 Rev 3: 03.03.01 (Audit and Accountability)
# CMMC L2: SC.L2-3.13.11 · NIST SP 800-171 Rev 3: 03.13.11 (Cryptographic Protection —
#          log objects SSE-KMS under the evidence CMK; see kms_key_id below for why the
#          bucket's default encryption is not sufficient on its own)
######################################################################

resource "aws_s3_bucket" "trail" {
  bucket        = "${local.name_prefix}-cloudtrail-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-mgmt-${local.suffix}"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-mgmt-${local.suffix}"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

resource "aws_cloudtrail" "mgmt" {
  name                          = "${local.name_prefix}-mgmt-${local.suffix}"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Must be set HERE, not left to the bucket's default encryption. Without it
  # CloudTrail PUTs with an explicit `x-amz-server-side-encryption: AES256`
  # header, and an explicit header overrides bucket default encryption — every
  # log object lands SSE-S3, under a key S3 manages internally, while the bucket
  # config still reads `aws:kms`. Verified against the live account 2026-08-08.
  kms_key_id = aws_kms_key.evidence.arn

  # Deliver management events to CloudWatch Logs for metric filters (M11a).
  # The :* suffix on the group ARN is required by the CloudTrail API.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn

  depends_on = [aws_s3_bucket_policy.trail]
}

# Trail-bucket retention (M11d / Decision 60) — versioning + 365-day lifecycle.
# force_destroy remains true; an operator can still delete the bucket.
resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "retain-365"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}
