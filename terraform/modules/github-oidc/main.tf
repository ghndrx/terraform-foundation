################################################################################
# GitHub OIDC Module
#
# Secure CI/CD access without long-lived credentials:
# - GitHub Actions OIDC provider
# - IAM roles for repository access
# - Fine-grained permissions per repo/branch/environment
#
# Usage:
#   module "github_oidc" {
#     source = "../modules/github-oidc"
#     
#     # Create roles for specific repos
#     roles = {
#       deploy = {
#         repos       = ["myorg/myrepo"]
#         branches    = ["main"]
#         policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]
#       }
#       terraform = {
#         repos       = ["myorg/infra"]
#         policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
#       }
#     }
#   }
#
# GitHub Actions workflow:
#   jobs:
#     deploy:
#       permissions:
#         id-token: write
#         contents: read
#       steps:
#         - uses: aws-actions/configure-aws-credentials@v4
#           with:
#             role-to-assume: arn:aws:iam::123456789012:role/github-deploy
#             aws-region: us-east-1
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

variable "create_provider" {
  type        = bool
  default     = true
  description = "Create the OIDC provider (set false if already exists)"
}

variable "provider_arn" {
  type        = string
  default     = ""
  description = "Existing OIDC provider ARN (if create_provider = false)"
}

variable "roles" {
  type = map(object({
    repos             = list(string)           # GitHub repos (owner/repo format)
    branches          = optional(list(string), []) # Branch restrictions (empty = all)
    environments      = optional(list(string), []) # Environment restrictions
    pull_request      = optional(bool, false)  # Allow from pull_request events
    policy_arns       = optional(list(string), []) # Managed policies to attach
    inline_policy     = optional(string, "")   # Inline policy JSON
    max_session_hours = optional(number, 1)    # Max session duration
  }))
  default     = {}
  description = "Map of role name -> configuration"
}

variable "name_prefix" {
  type        = string
  default     = "github"
  description = "Prefix for role names"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}

# Get GitHub's OIDC thumbprint
data "tls_certificate" "github" {
  count = var.create_provider ? 1 : 0
  url   = "https://token.actions.githubusercontent.com"
}

################################################################################
# OIDC Provider
################################################################################

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_provider ? 1 : 0

  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [data.tls_certificate.github[0].certificates[0].sha1_fingerprint]

  tags = merge(var.tags, { Name = "github-actions" })
}

locals {
  provider_arn = var.create_provider ? aws_iam_openid_connect_provider.github[0].arn : var.provider_arn
}

################################################################################
# IAM Roles
################################################################################

resource "aws_iam_role" "github" {
  for_each = var.roles

  name        = "${var.name_prefix}-${each.key}"
  description = "GitHub Actions role for ${join(", ", each.value.repos)}"

  max_session_duration = each.value.max_session_hours * 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = local.provider_arn
      }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = concat(
            # Standard ref-based subjects
            flatten([
              for repo in each.value.repos : (
                length(each.value.branches) > 0 
                ? [for branch in each.value.branches : "repo:${repo}:ref:refs/heads/${branch}"]
                : ["repo:${repo}:*"]
              )
            ]),
            # Environment-based subjects
            flatten([
              for repo in each.value.repos : [
                for env in each.value.environments : "repo:${repo}:environment:${env}"
              ]
            ]),
            # Pull request subjects
            each.value.pull_request ? [
              for repo in each.value.repos : "repo:${repo}:pull_request"
            ] : []
          )
        }
      }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

################################################################################
# Policy Attachments
################################################################################

resource "aws_iam_role_policy_attachment" "github" {
  for_each = {
    for pair in flatten([
      for role_name, role in var.roles : [
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

resource "aws_iam_role_policy" "github_inline" {
  for_each = { for k, v in var.roles : k => v if v.inline_policy != "" }

  name   = "inline"
  role   = aws_iam_role.github[each.key].id
  policy = each.value.inline_policy
}

################################################################################
# Outputs
################################################################################

output "provider_arn" {
  value       = local.provider_arn
  description = "OIDC provider ARN"
}

output "role_arns" {
  value       = { for k, v in aws_iam_role.github : k => v.arn }
  description = "Role ARNs"
}

output "role_names" {
  value       = { for k, v in aws_iam_role.github : k => v.name }
  description = "Role names"
}

output "workflow_example" {
  value = length(var.roles) > 0 ? <<-EOF
    # .github/workflows/deploy.yml
    jobs:
      deploy:
        runs-on: ubuntu-latest
        permissions:
          id-token: write
          contents: read
        steps:
          - uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: ${values(aws_iam_role.github)[0].arn}
              aws-region: us-east-1
          - run: aws sts get-caller-identity
  EOF
  : null
  description = "Example GitHub Actions workflow"
}
