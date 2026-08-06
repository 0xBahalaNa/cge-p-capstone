######################################################################
# Evidence vault — S3 Object Lock (GOVERNANCE / 1-day default).
# Layer 1 deliverable (brief bullet 2). Not a starter-gap close;
# GAP-01–05/07 land in M4–M5; GAP-06/08 are out of this increment.
# CMMC L2: AU.L2-3.3.8 · NIST SP 800-171 Rev 3: 03.03.08 (Audit and Accountability)
#
# Known limit: Object Lock protects object versions, not the bucket, and only
# until retention expires — an empty vault is deletable, a version older than
# evidence_retention_days (1) is deletable by anyone with s3:DeleteObjectVersion,
# and unexpired GOVERNANCE retention is bypassable by any holder of
# s3:BypassGovernanceRetention (here, the operator). COMPLIANCE mode closes only
# the bypass; the empty-bucket and expiry paths survive it.

# object_lock_enabled MUST be set at create — cannot add later (recreate).
resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled" # Object Lock prerequisite
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  depends_on = [aws_s3_bucket_versioning.evidence]

  rule {
    default_retention {
      mode = var.evidence_lock_mode
      days = var.evidence_retention_days
    }
  }
}

# Port change vs cge-p-portfolio: AES256 → SSE-KMS with the evidence CMK.
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
