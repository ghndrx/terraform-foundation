################################################################################
# IAM Role Module
#
# Common IAM role patterns:
# - Service roles (EC2, Lambda, ECS, etc.)
# - Cross-account roles (OrganizationAccountAccessRole pattern)
# - OIDC roles (GitHub Actions, EKS service accounts)
# - Instance profiles
#
# Usage:
#   # Lambda execution role
#   module "lambda_role" {
#     source = "../modules/iam-role"
#     
#     name            = "my-lambda"
#     role_type       = "service"
#     service         = "lambda.amazonaws.com"
#     managed_policies = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
#   }
#
#   # GitHub Actions OIDC
#   module "github_role" {
#     source = "../modules/iam-role"
#     
#     name      = "github-deploy"
#     role_type = "oidc"
#     oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
#     oidc_subjects = ["repo:myorg/myrepo:*"]
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type        = string
  description = "Role name"
}

variable "role_type" {
  type        = string
  default     = "service"
  description = "Type: service, cross-account, oidc"

  validation {
    condition     = contains(["service", "cross-account", "oidc"], var.role_type)
    error_message = "Must be service, cross-account, or oidc"
  }
}

variable "description" {
  type        = string
  default     = ""
  description = "Role description"
}

variable "path" {
  type        = string
  default     = "/"
  description = "IAM path"
}

variable "max_session_duration" {
  type        = number
  default     = 3600
  description = "Maximum session duration in seconds (1-12 hours)"
}

# Service role settings
variable "service" {
  type        = string
  default     = ""
  description = "AWS service principal (e.g., lambda.amazonaws.com)"
}

variable "services" {
  type        = list(string)
  default     = []
  description = "Multiple service principals"
}

# Cross-account settings
variable "trusted_account_ids" {
  type        = list(string)
  default     = []
  description = "Account IDs that can assume this role"
}

variable "trusted_role_arns" {
  type        = list(string)
  default     = []
  description = "Specific role ARNs that can assume this role"
}

variable "require_mfa" {
  type        = bool
  default     = false
  description = "Require MFA for cross-account assumption"
}

variable "require_external_id" {
  type        = string
  default     = ""
  description = "External ID required for assumption"
}

# OIDC settings
variable "oidc_provider_arn" {
  type        = string
  default     = ""
  description = "OIDC provider ARN"
}

variable "oidc_subjects" {
  type        = list(string)
  default     = []
  description = "Allowed OIDC subjects (e.g., repo:org/repo:*)"
}

variable "oidc_audiences" {
  type        = list(string)
  default     = ["sts.amazonaws.com"]
  description = "OIDC audiences"
}

# Policies
variable "managed_policies" {
  type        = list(string)
  default     = []
  description = "List of managed policy ARNs to attach"
}

variable "inline_policies" {
  type        = map(string)
  default     = {}
  description = "Map of inline policy name -> JSON policy document"
}

# Instance profile
variable "create_instance_profile" {
  type        = bool
  default     = false
  description = "Create an instance profile (for EC2)"
}

# Permissions boundary
variable "permissions_boundary" {
  type        = string
  default     = ""
  description = "Permissions boundary ARN"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}

locals {
  service_principals = var.service != "" ? [var.service] : var.services
  
  description = var.description != "" ? var.description : (
    var.role_type == "service" ? "Service role for ${join(", ", local.service_principals)}" :
    var.role_type == "cross-account" ? "Cross-account role" :
    "OIDC role"
  )
}

################################################################################
# Assume Role Policy
################################################################################

data "aws_iam_policy_document" "assume_role" {
  # Service role trust
  dynamic "statement" {
    for_each = var.role_type == "service" && length(local.service_principals) > 0 ? [1] : []
    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "Service"
        identifiers = local.service_principals
      }
    }
  }

  # Cross-account trust (account IDs)
  dynamic "statement" {
    for_each = var.role_type == "cross-account" && length(var.trusted_account_ids) > 0 ? [1] : []
    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = [for id in var.trusted_account_ids : "arn:aws:iam::${id}:root"]
      }

      dynamic "condition" {
        for_each = var.require_mfa ? [1] : []
        content {
          test     = "Bool"
          variable = "aws:MultiFactorAuthPresent"
          values   = ["true"]
        }
      }

      dynamic "condition" {
        for_each = var.require_external_id != "" ? [1] : []
        content {
          test     = "StringEquals"
          variable = "sts:ExternalId"
          values   = [var.require_external_id]
        }
      }
    }
  }

  # Cross-account trust (specific roles)
  dynamic "statement" {
    for_each = var.role_type == "cross-account" && length(var.trusted_role_arns) > 0 ? [1] : []
    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.trusted_role_arns
      }
    }
  }

  # OIDC trust
  dynamic "statement" {
    for_each = var.role_type == "oidc" && var.oidc_provider_arn != "" ? [1] : []
    content {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [var.oidc_provider_arn]
      }

      dynamic "condition" {
        for_each = length(var.oidc_subjects) > 0 ? [1] : []
        content {
          test     = "StringLike"
          variable = "${replace(var.oidc_provider_arn, "/.*oidc-provider\\//", "")}:sub"
          values   = var.oidc_subjects
        }
      }

      condition {
        test     = "StringEquals"
        variable = "${replace(var.oidc_provider_arn, "/.*oidc-provider\\//", "")}:aud"
        values   = var.oidc_audiences
      }
    }
  }
}

################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "main" {
  name                 = var.name
  description          = local.description
  path                 = var.path
  max_session_duration = var.max_session_duration
  
  assume_role_policy    = data.aws_iam_policy_document.assume_role.json
  permissions_boundary  = var.permissions_boundary != "" ? var.permissions_boundary : null

  tags = merge(var.tags, { Name = var.name })
}

################################################################################
# Managed Policies
################################################################################

resource "aws_iam_role_policy_attachment" "managed" {
  for_each   = toset(var.managed_policies)
  role       = aws_iam_role.main.name
  policy_arn = each.value
}

################################################################################
# Inline Policies
################################################################################

resource "aws_iam_role_policy" "inline" {
  for_each = var.inline_policies
  name     = each.key
  role     = aws_iam_role.main.id
  policy   = each.value
}

################################################################################
# Instance Profile
################################################################################

resource "aws_iam_instance_profile" "main" {
  count = var.create_instance_profile ? 1 : 0
  name  = var.name
  role  = aws_iam_role.main.name

  tags = merge(var.tags, { Name = var.name })
}

################################################################################
# Outputs
################################################################################

output "role_arn" {
  value       = aws_iam_role.main.arn
  description = "Role ARN"
}

output "role_name" {
  value       = aws_iam_role.main.name
  description = "Role name"
}

output "role_id" {
  value       = aws_iam_role.main.unique_id
  description = "Role unique ID"
}

output "instance_profile_arn" {
  value       = var.create_instance_profile ? aws_iam_instance_profile.main[0].arn : null
  description = "Instance profile ARN"
}

output "instance_profile_name" {
  value       = var.create_instance_profile ? aws_iam_instance_profile.main[0].name : null
  description = "Instance profile name"
}

output "assume_role_command" {
  value       = var.role_type == "cross-account" ? "aws sts assume-role --role-arn ${aws_iam_role.main.arn} --role-session-name my-session" : null
  description = "CLI command to assume the role"
}
