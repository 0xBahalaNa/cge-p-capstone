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
        # GitHub emits the immutable, ID-qualified subject for this repo:
        #   repo:<owner>@120359627/<repo>@1320990934:pull_request
        # Confirmed by decoding the token's sub claim in a workflow run on
        # 2026-08-09, after the name-based pattern failed to match. The numeric
        # IDs are the point: they survive a rename and cannot be claimed by
        # someone who later registers a released repo name.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:0xBahalaNa@120359627/cge-p-capstone@1320990934:*"
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
          "token.actions.githubusercontent.com:sub" = "repo:0xBahalaNa@120359627/cge-p-capstone@1320990934:ref:refs/heads/main"
        }
      }
    }]
  })
}

#tfsec:ignore:AVD-AWS-0057 # Decision 39 — accepted control-plane risk, main-branch OIDC only
resource "aws_iam_role_policy" "gha_apply" {
  name = "gha-apply-stack"
  role = aws_iam_role.gha_apply.id

  # Decision 39 — the OIDC apply role is deliberately broad. It is assumable only from
  # refs/heads/main via GitHub OIDC, it exists to apply this stack, and narrowing it is
  # tracked as accepted control-plane risk in WRITEUP.md. Documented, not silenced.
  #checkov:skip=CKV_AWS_286:Decision 39 — accepted control-plane risk, main-branch OIDC only
  #checkov:skip=CKV_AWS_287:Decision 39 — accepted control-plane risk, main-branch OIDC only
  #checkov:skip=CKV_AWS_288:Decision 39 — accepted control-plane risk, main-branch OIDC only
  #checkov:skip=CKV_AWS_289:Decision 39 — accepted control-plane risk, main-branch OIDC only
  #checkov:skip=CKV_AWS_290:Decision 39 — accepted control-plane risk, main-branch OIDC only
  #checkov:skip=CKV_AWS_355:Decision 39 — accepted control-plane risk, main-branch OIDC only
  #checkov:skip=CKV2_AWS_40:Decision 39 — accepted control-plane risk, main-branch OIDC only
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
        "sqs:*",
        "sns:*",
        "cloudwatch:*"
      ]
      Resource = "*"
    }]
  })
}
