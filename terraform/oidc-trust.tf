######################################################################
# GitHub Actions OIDC — plan (any ref) vs apply (main only).
# CMMC L2: AC.L2-3.1.1 · NIST SP 800-171 Rev 3: 03.01.01  (authorized access enforcement — trust conditions)
# CMMC L2: AC.L2-3.1.5 · NIST SP 800-171 Rev 3: 03.01.05  (least privilege — read-only plan vs apply)
######################################################################

# thumbprint_list omitted: Optional in hashicorp/aws >= 5.81 (we pin ~> 5.0 → 5.100.0).
# AWS trusts GitHub's CA library for this issuer; a thumbprint would be inert.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

# Plan role: any ref on this repo may assume (StringLike on sub).
# Permissions: AWS managed ReadOnlyAccess only — no inline policy.
resource "aws_iam_role" "gha_plan" {
  name = "${local.name_prefix}-gha-plan-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:0xBahalaNa/cge-p-capstone:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "gha_plan_readonly" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Apply role: main branch only (StringEquals on sub — drive-slot Condition).
# Inline policy: ten namespaces this stack uses; Resource "*" (Decision 29).
# Tenth namespace: sqs:* for the GAP-06 Lambda DLQ (M7).
resource "aws_iam_role" "gha_apply" {
  name = "${local.name_prefix}-gha-apply-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:0xBahalaNa/cge-p-capstone:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "gha_apply" {
  name = "gha-apply-stack"
  role = aws_iam_role.gha_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:*",
        "kms:*",
        "dynamodb:*",
        "lambda:*",
        "apigateway:*",
        "ec2:*",
        "cloudtrail:*",
        "logs:*",
        "iam:*",
        "sqs:*"
      ]
      Resource = "*"
    }]
  })
}
