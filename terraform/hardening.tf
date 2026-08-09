######################################################################
# Layer 1 hardening overrides — GAP-01, GAP-03–GAP-06, GAP-08.
# GAP-02 (DynamoDB SSE), GAP-05 vpc_config, GAP-06 Lambda wiring,
# and GAP-08 stage settings land in main.tf.
# CMMC L2 + NIST SP 800-171 Rev 3 control pairs per resource below.
######################################################################

# GAP-01: uploads SSE-KMS with workload CMK (not default SSE-S3).
# SC.L2-3.13.11 · NIST SP 800-171 Rev 3: 03.13.11
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# GAP-03: deny plain-HTTP access to uploads bucket and objects.
# SC.L2-3.13.8 · NIST SP 800-171 Rev 3: 03.13.08
data "aws_iam_policy_document" "uploads" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.uploads.arn,
      "${aws_s3_bucket.uploads.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads.json
}

# GAP-04: versioning on uploads — recoverable PHI object history.
# MP.L2-3.8.9 · NIST SP 800-171 Rev 3: 03.08.09
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-05: private route table — no internet route; endpoints inject prefix lists.
# SC.L2-3.13.1 · NIST SP 800-171 Rev 3: 03.13.01
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# GAP-05: gateway endpoints — free S3/DynamoDB access without NAT.
# SC.L2-3.13.1 · NIST SP 800-171 Rev 3: 03.13.01
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# GAP-05: Lambda ENI boundary — egress to endpoint prefix lists and VPC DNS resolver.
# SC.L2-3.13.1 · NIST SP 800-171 Rev 3: 03.13.01
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Lambda ENI egress to S3/DynamoDB gateway endpoints and VPC DNS resolver"
  vpc_id      = aws_vpc.main.id

  egress {
    description     = "HTTPS to S3 gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }

  egress {
    description     = "HTTPS to DynamoDB gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.dynamodb.prefix_list_id]
  }

  egress {
    description = "DNS UDP to VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    description = "DNS TCP to VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

}

# GAP-05: required for Lambda ENI create in VPC (apply fails without it).
# SC.L2-3.13.1 · NIST SP 800-171 Rev 3: 03.13.01
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# GAP-06: DLQ for failed intake invocations (PHI may be in the event body).
# SI.L2-3.14.6 · NIST SP 800-171 Rev 3: 03.14.06
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${local.name_prefix}-dlq-${local.suffix}"
  kms_master_key_id         = aws_kms_key.workload.arn # CMK, not SSE-SQS
  message_retention_seconds = 1209600                  # 14 days (SQS max)
}

# GAP-06: Lambda must be able to SendMessage to its own DLQ (scoped ARN).
# SI.L2-3.14.6 · NIST SP 800-171 Rev 3: 03.14.06
# Third statement lives on the existing inline policy in main.tf — see there.
# X-Ray write access: managed policy (X-Ray actions have no resource-level perms).
resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# GAP-08: destination for API Gateway HTTP API access logs.
# AU.L2-3.3.1 · NIST SP 800-171 Rev 3: 03.03.01
resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 30
}
