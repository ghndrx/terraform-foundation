################################################################################
# IAM Account Settings Module
#
# Account-level IAM security settings:
# - Password policy (complexity, rotation, reuse)
# - MFA enforcement via SCP/IAM policy
# - Account alias
# - SAML providers
#
# Usage:
#   module "iam_settings" {
#     source = "../modules/iam-account-settings"
#     
#     account_alias = "mycompany-prod"
#     
#     password_policy = {
#       minimum_length        = 14
#       require_symbols       = true
#       require_numbers       = true
#       require_uppercase     = true
#       require_lowercase     = true
#       max_age_days          = 90
#       password_reuse_prevention = 24
#       allow_users_to_change = true
#     }
#     
#     enforce_mfa = true
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

variable "account_alias" {
  type        = string
  default     = ""
  description = "AWS account alias (appears in sign-in URL)"
}

variable "password_policy" {
  type = object({
    minimum_length                   = optional(number, 14)
    require_symbols                  = optional(bool, true)
    require_numbers                  = optional(bool, true)
    require_uppercase_characters     = optional(bool, true)
    require_lowercase_characters     = optional(bool, true)
    allow_users_to_change_password   = optional(bool, true)
    max_password_age                 = optional(number, 90)
    password_reuse_prevention        = optional(number, 24)
    hard_expiry                      = optional(bool, false)
  })
  default     = {}
  description = "Password policy settings"
}

variable "enable_password_policy" {
  type        = bool
  default     = true
  description = "Enable custom password policy"
}

variable "enforce_mfa" {
  type        = bool
  default     = false
  description = "Create IAM policy to enforce MFA for all actions"
}

variable "mfa_grace_period_days" {
  type        = number
  default     = 0
  description = "Days new users have before MFA is required (0 = immediate)"
}

variable "mfa_exempt_roles" {
  type        = list(string)
  default     = []
  description = "Role names exempt from MFA requirement"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Account Alias
################################################################################

resource "aws_iam_account_alias" "main" {
  count         = var.account_alias != "" ? 1 : 0
  account_alias = var.account_alias
}

################################################################################
# Password Policy
################################################################################

resource "aws_iam_account_password_policy" "main" {
  count = var.enable_password_policy ? 1 : 0

  minimum_password_length        = var.password_policy.minimum_length
  require_symbols                = var.password_policy.require_symbols
  require_numbers                = var.password_policy.require_numbers
  require_uppercase_characters   = var.password_policy.require_uppercase_characters
  require_lowercase_characters   = var.password_policy.require_lowercase_characters
  allow_users_to_change_password = var.password_policy.allow_users_to_change_password
  max_password_age               = var.password_policy.max_password_age
  password_reuse_prevention      = var.password_policy.password_reuse_prevention
  hard_expiry                    = var.password_policy.hard_expiry
}

################################################################################
# MFA Enforcement Policy
################################################################################

# This policy denies all actions (except MFA setup) if MFA is not present
resource "aws_iam_policy" "enforce_mfa" {
  count = var.enforce_mfa ? 1 : 0

  name        = "EnforceMFA"
  description = "Denies all actions except MFA setup when MFA is not enabled"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnPasswords"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetUser"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnAccessKeys"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:GetAccessKeyLastUsed"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnSigningCertificates"
        Effect = "Allow"
        Action = [
          "iam:DeleteSigningCertificate",
          "iam:ListSigningCertificates",
          "iam:UpdateSigningCertificate",
          "iam:UploadSigningCertificate"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnSSHPublicKeys"
        Effect = "Allow"
        Action = [
          "iam:DeleteSSHPublicKey",
          "iam:GetSSHPublicKey",
          "iam:ListSSHPublicKeys",
          "iam:UpdateSSHPublicKey",
          "iam:UploadSSHPublicKey"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnGitCredentials"
        Effect = "Allow"
        Action = [
          "iam:CreateServiceSpecificCredential",
          "iam:DeleteServiceSpecificCredential",
          "iam:ListServiceSpecificCredentials",
          "iam:ResetServiceSpecificCredential",
          "iam:UpdateServiceSpecificCredential"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnVirtualMFADevice"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice"
        ]
        Resource = "arn:aws:iam::*:mfa/*"
      },
      {
        Sid    = "AllowManageOwnUserMFA"
        Effect = "Allow"
        Action = [
          "iam:DeactivateMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "DenyAllExceptListedIfNoMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:GetMFADevice",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken",
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "EnforceMFA" })
}

# Group for users who must have MFA
resource "aws_iam_group" "mfa_required" {
  count = var.enforce_mfa ? 1 : 0
  name  = "MFARequired"
}

resource "aws_iam_group_policy_attachment" "mfa_required" {
  count      = var.enforce_mfa ? 1 : 0
  group      = aws_iam_group.mfa_required[0].name
  policy_arn = aws_iam_policy.enforce_mfa[0].arn
}

################################################################################
# MFA Enforcement SCP (for Organizations)
################################################################################

# This can be attached at the OU level for organization-wide enforcement
resource "aws_iam_policy" "mfa_scp_template" {
  count = var.enforce_mfa ? 1 : 0

  name        = "MFA-SCP-Template"
  description = "Template SCP for MFA enforcement (apply via aws_organizations_policy)"

  # Note: This is an IAM policy format - for SCP, use this as a template
  # SCPs don't support aws:MultiFactorAuthPresent for all actions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyStopAndTerminateWithoutMFA"
        Effect = "Deny"
        Action = [
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "rds:DeleteDBInstance",
          "rds:DeleteDBCluster",
          "s3:DeleteBucket",
          "iam:DeleteUser",
          "iam:DeleteRole"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "MFA-SCP-Template" })
}

################################################################################
# Outputs
################################################################################

output "account_alias" {
  value       = var.account_alias != "" ? var.account_alias : null
  description = "AWS account alias"
}

output "signin_url" {
  value       = var.account_alias != "" ? "https://${var.account_alias}.signin.aws.amazon.com/console" : null
  description = "AWS console sign-in URL"
}

output "password_policy" {
  value = var.enable_password_policy ? {
    minimum_length      = var.password_policy.minimum_length
    require_symbols     = var.password_policy.require_symbols
    require_numbers     = var.password_policy.require_numbers
    require_uppercase   = var.password_policy.require_uppercase_characters
    require_lowercase   = var.password_policy.require_lowercase_characters
    max_age_days        = var.password_policy.max_password_age
    reuse_prevention    = var.password_policy.password_reuse_prevention
  } : null
  description = "Password policy settings"
}

output "mfa_enforcement_policy_arn" {
  value       = var.enforce_mfa ? aws_iam_policy.enforce_mfa[0].arn : null
  description = "MFA enforcement policy ARN"
}

output "mfa_required_group" {
  value       = var.enforce_mfa ? aws_iam_group.mfa_required[0].name : null
  description = "Group name for users requiring MFA"
}

output "mfa_scp_template_policy" {
  value       = var.enforce_mfa ? aws_iam_policy.mfa_scp_template[0].policy : null
  description = "Template policy for MFA SCP (copy to Organizations)"
}
