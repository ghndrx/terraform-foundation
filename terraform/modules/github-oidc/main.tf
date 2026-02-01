################################################################################
# GitHub OIDC Module
#
# AWS/Terraform/Security Best Practices:
# - Least privilege IAM policies
# - Input validation
# - Explicit denies for dangerous actions
# - Session duration limits
# - CloudTrail monitoring integration
# - Permissions boundary support
# - No wildcard repos by default
#
# Security scanning: tfsec, checkov, tflint-aws
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

################################################################################
# Local Variables & Validation
################################################################################

locals {
  account_id   = data.aws_caller_identity.current.account_id
  region       = data.aws_region.current.id
  partition    = data.aws_partition.current.partition

  # Validate permissions boundary requirement
  boundary_check = var.require_permissions_boundary && var.permissions_boundary == null ? tobool("Permissions boundary is required but not set") : true

  # Normalize repo names with org prefix
  normalize_repo = { for k, v in var.roles : k => merge(v, {
    repos = [for repo in v.repos :
      !contains(split("/", repo), "/") && var.github_org != ""
        ? "${var.github_org}/${repo}"
        : repo
    ]
    # Cap session duration at limit
    max_session_hours = min(v.max_session_hours, var.max_session_hours_limit)
  })}

  # Validate no wildcard repos unless workflow_ref is set
  wildcard_check = var.deny_wildcard_repos ? alltrue([
    for k, v in var.roles : !contains(v.repos, "*") || v.workflow_ref != ""
  ]) : true

  _ = local.wildcard_check ? true : tobool("Wildcard repos (*) require workflow_ref restriction or deny_wildcard_repos=false")

  # Common tags
  common_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Module    = "github-oidc"
  })
}

################################################################################
# OIDC Provider
################################################################################

data "tls_certificate" "github" {
  count = var.create_provider ? 1 : 0
  url   = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github[0].certificates[0].sha1_fingerprint]

  tags = merge(local.common_tags, {
    Name        = "github-actions-oidc"
    Description = "GitHub Actions OIDC Identity Provider"
  })
}

locals {
  provider_arn = var.create_provider ? aws_iam_openid_connect_provider.github[0].arn : var.provider_arn
}

################################################################################
# Custom Roles
################################################################################

resource "aws_iam_role" "github" {
  for_each = local.normalize_repo

  name                 = "${var.name_prefix}-${each.key}"
  path                 = var.path
  description          = "GitHub Actions: ${join(", ", each.value.repos)}"
  max_session_duration = each.value.max_session_hours * 3600
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubActionsOIDC"
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = local.provider_arn
      }
      Condition = merge(
        {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = distinct(compact(concat(
              # Branch-based subjects
              flatten([for repo in each.value.repos :
                length(each.value.branches) > 0
                  ? [for branch in each.value.branches : "repo:${repo}:ref:refs/heads/${branch}"]
                  : length(each.value.tags) == 0 && length(each.value.environments) == 0 && !each.value.pull_request
                    ? ["repo:${repo}:*"]
                    : []
              ]),
              # Tag-based subjects
              flatten([for repo in each.value.repos :
                [for tag in each.value.tags : "repo:${repo}:ref:refs/tags/${tag}"]
              ]),
              # Environment-based subjects
              flatten([for repo in each.value.repos :
                [for env in each.value.environments : "repo:${repo}:environment:${env}"]
              ]),
              # Pull request subjects
              each.value.pull_request
                ? [for repo in each.value.repos : "repo:${repo}:pull_request"]
                : []
            )))
          }
        },
        # Workflow ref condition (for reusable workflows)
        each.value.workflow_ref != "" ? {
          StringEquals = merge(
            { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" },
            { "token.actions.githubusercontent.com:job_workflow_ref" = each.value.workflow_ref }
          )
        } : {},
        # Extra conditions
        each.value.extra_conditions
      )
    }]
  })

  tags = merge(local.common_tags, {
    Name        = "${var.name_prefix}-${each.key}"
    GitHubRepos = join(",", slice(each.value.repos, 0, min(5, length(each.value.repos))))
    Purpose     = "github-actions-oidc"
  })
}

# Managed policy attachments
resource "aws_iam_role_policy_attachment" "github" {
  for_each = {
    for pair in flatten([
      for role_name, role in local.normalize_repo : [
        for policy_arn in role.policy_arns : {
          role_name  = role_name
          policy_arn = policy_arn
        }
      ]
    ]) : "${pair.role_name}-${md5(pair.policy_arn)}" => pair
  }

  role       = aws_iam_role.github[each.value.role_name].name
  policy_arn = each.value.policy_arn
}

# Inline policies (raw JSON)
resource "aws_iam_role_policy" "github_inline" {
  for_each = { for k, v in local.normalize_repo : k => v if v.inline_policy != "" }

  name   = "inline"
  role   = aws_iam_role.github[each.key].id
  policy = each.value.inline_policy
}

# Generated policies from statements
resource "aws_iam_role_policy" "github_generated" {
  for_each = { for k, v in local.normalize_repo : k => v if length(v.policy_statements) > 0 }

  name = "generated"
  role = aws_iam_role.github[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [for stmt in each.value.policy_statements : {
      Sid      = stmt.sid != "" ? stmt.sid : null
      Effect   = stmt.effect
      Action   = stmt.actions
      Resource = stmt.resources
      Condition = length(stmt.conditions) > 0 ? {
        for cond in stmt.conditions : cond.test => {
          "${cond.variable}" = cond.values
        }
      } : null
    }]
  })
}

################################################################################
# Terraform Deploy Role (Template)
################################################################################

locals {
  tf_role_enabled = try(var.terraform_deploy_role.enabled, false)
  tf_repos = try(var.terraform_deploy_role.repos, [])
  tf_repos_normalized = [for repo in local.tf_repos :
    !contains(split("/", repo), "/") && var.github_org != ""
      ? "${var.github_org}/${repo}"
      : repo
  ]
}

resource "aws_iam_role" "terraform" {
  count = local.tf_role_enabled ? 1 : 0

  name                 = "${var.name_prefix}-terraform"
  path                 = var.path
  description          = "GitHub Actions - Terraform deployment"
  max_session_duration = min(2, var.max_session_hours_limit) * 3600
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubActionsTerraform"
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = concat(
            flatten([for repo in local.tf_repos_normalized :
              length(try(var.terraform_deploy_role.branches, [])) > 0
                ? [for branch in var.terraform_deploy_role.branches : "repo:${repo}:ref:refs/heads/${branch}"]
                : ["repo:${repo}:*"]
            ]),
            flatten([for repo in local.tf_repos_normalized :
              [for env in try(var.terraform_deploy_role.environments, []) : "repo:${repo}:environment:${env}"]
            ])
          )
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-terraform"
    Purpose = "terraform-deployment"
  })
}

resource "aws_iam_role_policy" "terraform_state" {
  count = local.tf_role_enabled && try(var.terraform_deploy_role.state_bucket, "") != "" ? 1 : 0

  name = "terraform-state"
  role = aws_iam_role.terraform[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:${local.partition}:s3:::${var.terraform_deploy_role.state_bucket}/${try(var.terraform_deploy_role.state_bucket_key_prefix, "*")}"
      },
      {
        Sid    = "TerraformStateBucketList"
        Effect = "Allow"
        Action = ["s3:ListBucket"]
        Resource = "arn:${local.partition}:s3:::${var.terraform_deploy_role.state_bucket}"
        Condition = {
          StringLike = {
            "s3:prefix" = [try(var.terraform_deploy_role.state_bucket_key_prefix, "*")]
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "terraform_lock" {
  count = local.tf_role_enabled && try(var.terraform_deploy_role.dynamodb_table, "") != "" ? 1 : 0

  name = "terraform-lock"
  role = aws_iam_role.terraform[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "TerraformLockTable"
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem"
      ]
      Resource = "arn:${local.partition}:dynamodb:*:${local.account_id}:table/${var.terraform_deploy_role.dynamodb_table}"
    }]
  })
}

# Service-specific permissions (least privilege approach)
resource "aws_iam_role_policy" "terraform_services" {
  count = local.tf_role_enabled && length(try(var.terraform_deploy_role.allowed_services, [])) > 0 ? 1 : 0

  name = "terraform-services"
  role = aws_iam_role.terraform[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowedServices"
      Effect   = "Allow"
      Action   = flatten([for svc in var.terraform_deploy_role.allowed_services : "${svc}:*"])
      Resource = "*"
    }]
  })
}

# Explicit denies for dangerous actions
resource "aws_iam_role_policy" "terraform_deny" {
  count = local.tf_role_enabled && length(try(var.terraform_deploy_role.denied_actions, [])) > 0 ? 1 : 0

  name = "terraform-deny"
  role = aws_iam_role.terraform[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ExplicitDeny"
      Effect   = "Deny"
      Action   = var.terraform_deploy_role.denied_actions
      Resource = "*"
    }]
  })
}

################################################################################
# ECR Push Role (Template)
################################################################################

locals {
  ecr_role_enabled = try(var.ecr_push_role.enabled, false)
  ecr_repos_gh = try(var.ecr_push_role.repos, [])
  ecr_repos_normalized = [for repo in local.ecr_repos_gh :
    !contains(split("/", repo), "/") && var.github_org != ""
      ? "${var.github_org}/${repo}"
      : repo
  ]
}

resource "aws_iam_role" "ecr" {
  count = local.ecr_role_enabled ? 1 : 0

  name                 = "${var.name_prefix}-ecr-push"
  path                 = var.path
  description          = "GitHub Actions - ECR push"
  max_session_duration = 3600
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubActionsECR"
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = flatten([for repo in local.ecr_repos_normalized :
            length(try(var.ecr_push_role.branches, [])) > 0
              ? [for branch in var.ecr_push_role.branches : "repo:${repo}:ref:refs/heads/${branch}"]
              : ["repo:${repo}:*"]
          ])
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-ecr-push"
    Purpose = "ecr-push"
  })
}

resource "aws_iam_role_policy" "ecr" {
  count = local.ecr_role_enabled ? 1 : 0

  name = "ecr-push"
  role = aws_iam_role.ecr[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"  # Required - GetAuthorizationToken doesn't support resource constraints
      }],
      [{
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages"
        ]
        Resource = [for repo in try(var.ecr_push_role.ecr_repos, []) :
          "arn:${local.partition}:ecr:*:${local.account_id}:repository/${repo}"
        ]
      }],
      try(var.ecr_push_role.allow_create, false) ? [{
        Sid    = "ECRCreate"
        Effect = "Allow"
        Action = ["ecr:CreateRepository", "ecr:TagResource"]
        Resource = "arn:${local.partition}:ecr:*:${local.account_id}:repository/*"
      }] : [],
      try(var.ecr_push_role.allow_delete, false) ? [{
        Sid    = "ECRDelete"
        Effect = "Allow"
        Action = ["ecr:DeleteRepository", "ecr:BatchDeleteImage"]
        Resource = [for repo in try(var.ecr_push_role.ecr_repos, []) :
          "arn:${local.partition}:ecr:*:${local.account_id}:repository/${repo}"
        ]
      }] : []
    )
  })
}

################################################################################
# S3 Deploy Role (Template)
################################################################################

locals {
  s3_role_enabled = try(var.s3_deploy_role.enabled, false)
  s3_repos = try(var.s3_deploy_role.repos, [])
  s3_repos_normalized = [for repo in local.s3_repos :
    !contains(split("/", repo), "/") && var.github_org != ""
      ? "${var.github_org}/${repo}"
      : repo
  ]
}

resource "aws_iam_role" "s3_deploy" {
  count = local.s3_role_enabled ? 1 : 0

  name                 = "${var.name_prefix}-s3-deploy"
  path                 = var.path
  description          = "GitHub Actions - S3 deployment"
  max_session_duration = 3600
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubActionsS3Deploy"
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = flatten([for repo in local.s3_repos_normalized :
            length(try(var.s3_deploy_role.branches, [])) > 0
              ? [for branch in var.s3_deploy_role.branches : "repo:${repo}:ref:refs/heads/${branch}"]
              : ["repo:${repo}:*"]
          ])
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-s3-deploy"
    Purpose = "s3-static-site"
  })
}

resource "aws_iam_role_policy" "s3_deploy" {
  count = local.s3_role_enabled ? 1 : 0

  name = "s3-deploy"
  role = aws_iam_role.s3_deploy[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid    = "S3Deploy"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:GetObjectAcl",
          "s3:PutObjectAcl"
        ]
        Resource = flatten([for bucket in try(var.s3_deploy_role.bucket_arns, []) : [
          for prefix in try(var.s3_deploy_role.allowed_prefixes, ["*"]) :
            "${bucket}/${prefix}"
        ]])
      }],
      [{
        Sid    = "S3List"
        Effect = "Allow"
        Action = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = try(var.s3_deploy_role.bucket_arns, [])
      }],
      length(try(var.s3_deploy_role.cloudfront_arns, [])) > 0 ? [{
        Sid      = "CloudFrontInvalidate"
        Effect   = "Allow"
        Action   = "cloudfront:CreateInvalidation"
        Resource = var.s3_deploy_role.cloudfront_arns
      }] : []
    )
  })
}

################################################################################
# Lambda Deploy Role (Template)
################################################################################

locals {
  lambda_role_enabled = try(var.lambda_deploy_role.enabled, false)
  lambda_repos = try(var.lambda_deploy_role.repos, [])
  lambda_repos_normalized = [for repo in local.lambda_repos :
    !contains(split("/", repo), "/") && var.github_org != ""
      ? "${var.github_org}/${repo}"
      : repo
  ]
}

resource "aws_iam_role" "lambda_deploy" {
  count = local.lambda_role_enabled ? 1 : 0

  name                 = "${var.name_prefix}-lambda-deploy"
  path                 = var.path
  description          = "GitHub Actions - Lambda deployment"
  max_session_duration = 3600
  permissions_boundary = var.permissions_boundary

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubActionsLambda"
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = flatten([for repo in local.lambda_repos_normalized :
            length(try(var.lambda_deploy_role.branches, [])) > 0
              ? [for branch in var.lambda_deploy_role.branches : "repo:${repo}:ref:refs/heads/${branch}"]
              : ["repo:${repo}:*"]
          ])
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name    = "${var.name_prefix}-lambda-deploy"
    Purpose = "lambda-deployment"
  })
}

resource "aws_iam_role_policy" "lambda_deploy" {
  count = local.lambda_role_enabled ? 1 : 0

  name = "lambda-deploy"
  role = aws_iam_role.lambda_deploy[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration",
          "lambda:PublishVersion",
          "lambda:ListVersionsByFunction"
        ]
        Resource = try(var.lambda_deploy_role.function_arns, [])
      }],
      try(var.lambda_deploy_role.allow_create, false) ? [{
        Sid    = "LambdaCreate"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:DeleteFunction",
          "lambda:TagResource",
          "lambda:AddPermission",
          "lambda:RemovePermission"
        ]
        Resource = "arn:${local.partition}:lambda:*:${local.account_id}:function:*"
      }] : [],
      try(var.lambda_deploy_role.allow_create, false) ? [{
        Sid      = "IAMPassRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:${local.partition}:iam::${local.account_id}:role/*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "lambda.amazonaws.com"
          }
        }
      }] : [],
      try(var.lambda_deploy_role.allow_logs, true) ? [{
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents"
        ]
        Resource = "arn:${local.partition}:logs:*:${local.account_id}:log-group:/aws/lambda/*"
      }] : []
    )
  })
}

################################################################################
# Security Monitoring (Optional)
################################################################################

resource "aws_cloudwatch_log_metric_filter" "oidc_assume_role" {
  count = var.enable_cloudtrail_logging && var.alarm_sns_topic_arn != "" ? 1 : 0

  name           = "github-oidc-assume-role"
  pattern        = "{ ($.eventName = AssumeRoleWithWebIdentity) && ($.requestParameters.roleArn = \"*${var.name_prefix}*\") }"
  log_group_name = "aws-cloudtrail-logs"  # Adjust to your CloudTrail log group

  metric_transformation {
    name      = "GitHubOIDCAssumeRole"
    namespace = "Security/OIDC"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "oidc_high_usage" {
  count = var.enable_cloudtrail_logging && var.alarm_sns_topic_arn != "" ? 1 : 0

  alarm_name          = "github-oidc-high-usage"
  alarm_description   = "High number of GitHub OIDC role assumptions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "GitHubOIDCAssumeRole"
  namespace           = "Security/OIDC"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.alarm_sns_topic_arn]

  tags = local.common_tags
}
