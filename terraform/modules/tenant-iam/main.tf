################################################################################
# Tenant IAM Module
#
# Creates tenant-specific IAM roles with isolation:
# - Tenant admin role with permissions boundary
# - Tenant developer role
# - Tenant readonly role
# - Permissions boundary for tenant isolation
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

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Resource prefix for tenant isolation
  resource_prefix = var.resource_prefix != "" ? var.resource_prefix : "${var.tenant_id}-"
}

################################################################################
# Permissions Boundary
################################################################################

resource "aws_iam_policy" "boundary" {
  count = var.create_permissions_boundary ? 1 : 0

  name        = "${var.tenant_id}-permissions-boundary"
  path        = var.iam_path
  description = "Permissions boundary for ${var.tenant_name} tenant"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Allow specified services
      [{
        Sid    = "AllowedServices"
        Effect = "Allow"
        Action = [for svc in var.allowed_services : "${svc}:*"]
        Resource = "*"
        Condition = {
          StringLikeIfExists = {
            "aws:ResourceTag/Tenant" = [var.tenant_id, var.tenant_name]
          }
        }
      }],
      # Restrict to tenant-prefixed resources where possible
      [{
        Sid    = "RestrictToTenantResources"
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "lambda:*",
          "sqs:*",
          "sns:*"
        ]
        Resource = [
          "arn:${local.partition}:s3:::${local.resource_prefix}*",
          "arn:${local.partition}:dynamodb:*:${local.account_id}:table/${local.resource_prefix}*",
          "arn:${local.partition}:lambda:*:${local.account_id}:function:${local.resource_prefix}*",
          "arn:${local.partition}:sqs:*:${local.account_id}:${local.resource_prefix}*",
          "arn:${local.partition}:sns:*:${local.account_id}:${local.resource_prefix}*"
        ]
      }],
      # Deny modifying boundary or escalating privileges
      [{
        Sid    = "DenyBoundaryModification"
        Effect = "Deny"
        Action = [
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion"
        ]
        Resource = "arn:${local.partition}:iam::${local.account_id}:policy/${var.tenant_id}-permissions-boundary"
      }],
      # Deny creating roles/users without boundary
      [{
        Sid    = "DenyCreatingRolesWithoutBoundary"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:CreateUser"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "iam:PermissionsBoundary" = "arn:${local.partition}:iam::${local.account_id}:policy/${var.tenant_id}-permissions-boundary"
          }
        }
      }],
      # Deny modifying other tenants' resources
      [{
        Sid    = "DenyAccessToOtherTenants"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:ResourceTag/Tenant" = [var.tenant_id, var.tenant_name, ""]
          }
          Null = {
            "aws:ResourceTag/Tenant" = "false"
          }
        }
      }],
      # Deny disabling security services
      [{
        Sid    = "DenySecurityServiceModification"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "securityhub:DisableSecurityHub",
          "config:DeleteConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging"
        ]
        Resource = "*"
      }]
    )
  })

  tags = merge(var.tags, {
    Name   = "${var.tenant_id}-permissions-boundary"
    Tenant = var.tenant_name
  })
}

################################################################################
# Admin Role
################################################################################

resource "aws_iam_role" "admin" {
  count = var.create_admin_role ? 1 : 0

  name                 = "${var.tenant_id}-admin"
  path                 = var.iam_path
  permissions_boundary = var.create_permissions_boundary ? aws_iam_policy.boundary[0].arn : var.permissions_boundary_arn
  max_session_duration = var.admin_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_principals
      }
      Condition = var.require_mfa ? {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      } : {}
    }]
  })

  tags = merge(var.tags, {
    Name   = "${var.tenant_id}-admin"
    Tenant = var.tenant_name
    Role   = "admin"
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  count = var.create_admin_role ? 1 : 0

  role       = aws_iam_role.admin[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/PowerUserAccess"
}

################################################################################
# Developer Role
################################################################################

resource "aws_iam_role" "developer" {
  count = var.create_developer_role ? 1 : 0

  name                 = "${var.tenant_id}-developer"
  path                 = var.iam_path
  permissions_boundary = var.create_permissions_boundary ? aws_iam_policy.boundary[0].arn : var.permissions_boundary_arn
  max_session_duration = var.developer_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_principals
      }
    }]
  })

  tags = merge(var.tags, {
    Name   = "${var.tenant_id}-developer"
    Tenant = var.tenant_name
    Role   = "developer"
  })
}

resource "aws_iam_role_policy" "developer" {
  count = var.create_developer_role ? 1 : 0

  name = "developer-access"
  role = aws_iam_role.developer[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DeveloperAccess"
        Effect = "Allow"
        Action = [for svc in var.allowed_services : "${svc}:*"]
        Resource = "*"
      },
      {
        Sid    = "DenyAdmin"
        Effect = "Deny"
        Action = [
          "iam:*",
          "organizations:*",
          "account:*"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Readonly Role
################################################################################

resource "aws_iam_role" "readonly" {
  count = var.create_readonly_role ? 1 : 0

  name                 = "${var.tenant_id}-readonly"
  path                 = var.iam_path
  permissions_boundary = var.create_permissions_boundary ? aws_iam_policy.boundary[0].arn : var.permissions_boundary_arn
  max_session_duration = var.readonly_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.trusted_principals
      }
    }]
  })

  tags = merge(var.tags, {
    Name   = "${var.tenant_id}-readonly"
    Tenant = var.tenant_name
    Role   = "readonly"
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  count = var.create_readonly_role ? 1 : 0

  role       = aws_iam_role.readonly[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}
