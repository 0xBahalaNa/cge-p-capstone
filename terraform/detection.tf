######################################################################
# Continuous monitoring & detection — metric filters, alarms, flow logs.
# CMMC L2: SI.L2-3.14.6 · NIST SP 800-171 Rev 3: 03.14.06 (system monitoring)
# CMMC L2: AC.L2-3.1.5 · NIST SP 800-171 Rev 3: 03.01.05 (root usage alarm)
# Alert routing terminates at an unsubscribed SNS topic (Decision 58).
######################################################################

# CloudTrail delivery target for metric filters (SI.L2-3.14.6 · 03.14.06).
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.evidence.arn
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${local.name_prefix}-trail-cw-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Scoped to the trail log group — not Resource "*".
# The :* suffix is required so CreateLogStream/PutLogEvents can target streams under the group.
#tfsec:ignore:AVD-AWS-0057 # log-stream ARN suffix under a single group, not account-wide *
resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "cloudtrail-to-cloudwatch"
  role = aws_iam_role.cloudtrail_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

# Alert route endpoint. No subscription resource (Decision 58).
resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name_prefix}-security-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.evidence.arn
}

# SI.L2-3.14.6 · NIST SP 800-171 Rev 3: 03.14.06
# Drive slot waived — pattern + metric_transformation agent-implemented.
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${local.name_prefix}-unauthorized-api-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name          = "UnauthorizedAPICalls"
    namespace     = "CGEP/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${local.name_prefix}-unauthorized-api-${local.suffix}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CGEP/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  alarm_description   = "Unauthorized or access-denied API calls in management events"
}

# AC.L2-3.1.5 · NIST SP 800-171 Rev 3: 03.01.05
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "${local.name_prefix}-root-usage-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = "{ $.userIdentity.type = \"Root\" }"

  metric_transformation {
    name          = "RootAccountUsage"
    namespace     = "CGEP/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${local.name_prefix}-root-usage-${local.suffix}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CGEP/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  alarm_description   = "Root account activity in management events"
}

# VPC flow logs — SI.L2-3.14.6 · NIST SP 800-171 Rev 3: 03.14.06
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc-flow-logs/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.evidence.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name_prefix}-flow-logs-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "vpc-flow-logs-to-cloudwatch"
  role = aws_iam_role.flow_logs.id

  # Decision 64 (amended): writes stay on the two log-group ARN forms; only
  # logs:DescribeLogGroups is Resource "*", because IAM denies that collection
  # action against every log-group ARN form (verified via simulate-custom-policy).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = [
          aws_cloudwatch_log_group.flow.arn,
          "${aws_cloudwatch_log_group.flow.arn}:*",
        ]
      },
      {
        # DescribeLogGroups is collection-level: IAM denies it against every log-group
        # ARN form, including "…:log-group:*". Verified with iam simulate-custom-policy.
        # "*" is the only resource form AWS accepts for this one action.
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
    ]
  })
}

resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_logs.arn
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
}
