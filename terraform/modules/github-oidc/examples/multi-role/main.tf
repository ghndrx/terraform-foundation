################################################################################
# GitHub OIDC - Multi-Role Example
#
# Multiple roles with different permission levels
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Permissions boundary for defense-in-depth
resource "aws_iam_policy" "github_boundary" {
  name        = "GitHubActionsBoundary"
  description = "Permissions boundary for GitHub Actions roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowedServices"
        Effect   = "Allow"
        Action   = ["s3:*", "ecr:*", "lambda:*", "logs:*", "cloudwatch:*"]
        Resource = "*"
      },
      {
        Sid    = "DenyDangerous"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "organizations:*",
          "account:*"
        ]
        Resource = "*"
      }
    ]
  })
}

module "github_oidc" {
  source = "../../"

  github_org           = "example-org"
  name_prefix          = "github"
  permissions_boundary = aws_iam_policy.github_boundary.arn

  # Security settings
  max_session_hours_limit = 2
  deny_wildcard_repos     = true

  roles = {
    # Read-only for PR validation
    validate = {
      repos        = ["infrastructure", "application"]
      pull_request = true
      policy_arns  = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      max_session_hours = 1
    }

    # Deploy from main branch only
    deploy = {
      repos        = ["infrastructure"]
      branches     = ["main"]
      environments = ["production"]
      policy_statements = [
        {
          sid       = "DeployAccess"
          actions   = ["s3:*", "cloudfront:*", "lambda:*"]
          resources = ["*"]
        }
      ]
      max_session_hours = 2
    }

    # Release automation from tags
    release = {
      repos    = ["application"]
      tags     = ["v*", "release-*"]
      branches = []  # Only tags
      policy_statements = [
        {
          sid       = "ECRPush"
          actions   = ["ecr:*"]
          resources = ["arn:aws:ecr:*:*:repository/application"]
        }
      ]
    }

    # Reusable workflow restriction
    shared = {
      repos        = ["*"]  # Any repo
      workflow_ref = "example-org/shared-workflows/.github/workflows/deploy.yml@main"
      policy_statements = [
        {
          sid       = "SharedDeploy"
          actions   = ["s3:PutObject"]
          resources = ["arn:aws:s3:::artifacts-bucket/*"]
        }
      ]
    }
  }

  tags = {
    Environment = "production"
    CostCenter  = "platform"
  }
}

output "all_roles" {
  value = module.github_oidc.all_role_arns
}

output "security_status" {
  value = module.github_oidc.security_recommendations
}
