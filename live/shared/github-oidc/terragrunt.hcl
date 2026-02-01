# GitHub OIDC Configuration
# Implements AWS/Terraform/Security best practices
#
# Security features enabled:
# - Explicit repository restrictions (no wildcards)
# - Branch/environment protection
# - Session duration limits
# - Least-privilege policies
# - CloudTrail monitoring

terraform {
  source = "../../../terraform/modules/github-oidc"
}

include "root" {
  path = find_in_parent_folders("terragrunt.hcl")
}

inputs = {
  # GitHub organization
  github_org  = "ghndrx"  # Update to your org
  name_prefix = "github"

  # Security settings
  path                       = "/github-actions/"  # Isolated IAM path
  max_session_hours_limit    = 2                   # Cap all sessions at 2 hours
  deny_wildcard_repos        = true                # No * repos allowed
  require_permissions_boundary = false             # Enable in production
  # permissions_boundary = "arn:aws:iam::ACCOUNT:policy/GitHubActionsBoundary"

  # Monitoring (requires CloudTrail)
  enable_cloudtrail_logging = false  # Set true when CloudTrail is configured
  # alarm_sns_topic_arn     = "arn:aws:sns:us-east-1:ACCOUNT:security-alerts"

  # Custom roles with explicit restrictions
  roles = {
    # Infrastructure deployment - main branch only
    infra = {
      repos        = ["terraform-foundation", "infrastructure"]
      branches     = ["main"]
      environments = ["production"]
      policy_statements = [
        {
          sid       = "ReadOnly"
          actions   = ["ec2:Describe*", "s3:List*", "s3:Get*", "iam:Get*", "iam:List*"]
          resources = ["*"]
        }
      ]
      max_session_hours = 1
    }

    # PR validation - read-only
    validate = {
      repos        = ["terraform-foundation"]
      pull_request = true
      policy_statements = [
        {
          sid       = "ReadOnlyValidation"
          effect    = "Allow"
          actions   = ["ec2:Describe*", "s3:List*", "iam:Get*", "iam:List*"]
          resources = ["*"]
        }
      ]
      max_session_hours = 1
    }

    # Release automation - tag-based
    release = {
      repos    = ["terraform-foundation"]
      tags     = ["v*"]
      branches = []  # Only tags, not branches
      policy_statements = [
        {
          sid       = "ReleaseArtifacts"
          actions   = ["s3:PutObject"]
          resources = ["arn:aws:s3:::release-artifacts/*"]
        }
      ]
    }
  }

  # Terraform deployment with least privilege
  terraform_deploy_role = {
    enabled        = true
    repos          = ["terraform-foundation"]
    branches       = ["main"]
    environments   = ["production"]
    state_bucket   = "your-terraform-state-bucket"  # Update
    state_bucket_key_prefix = "terraform/*"         # Limit to specific paths
    dynamodb_table = "terraform-locks"
    allowed_services = [
      "ec2", "s3", "iam", "lambda", "apigateway",
      "cloudwatch", "logs", "route53", "acm"
    ]
    denied_actions = [
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:DeleteAccountPasswordPolicy",
      "organizations:*",
      "account:*",
      "sts:AssumeRole"  # Prevent role chaining
    ]
  }

  # ECR with explicit repos
  ecr_push_role = {
    enabled      = true
    repos        = ["backend-api", "frontend-app"]
    branches     = ["main", "develop"]
    ecr_repos    = ["backend-api", "frontend-app"]  # Explicit ECR repos
    allow_create = false
    allow_delete = false
  }

  # S3 static sites
  s3_deploy_role = {
    enabled          = true
    repos            = ["website", "docs"]
    branches         = ["main"]
    bucket_arns      = ["arn:aws:s3:::www.example.com"]  # Update
    allowed_prefixes = ["assets/*", "*.html", "*.js", "*.css"]
    cloudfront_arns  = []  # Add if using CloudFront
  }

  # Lambda deployments
  lambda_deploy_role = {
    enabled       = true
    repos         = ["serverless-api"]
    branches      = ["main"]
    function_arns = [
      "arn:aws:lambda:us-east-1:*:function:api-*"  # Update
    ]
    allow_create = false
    allow_logs   = true
  }

  tags = {
    Environment = "shared"
    ManagedBy   = "terraform"
    Component   = "github-oidc"
    CostCenter  = "platform"
  }
}
