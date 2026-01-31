################################################################################
# Layer 01: Organization (Multi-Account Mode Only)
# 
# Creates:
# - AWS Organization with SCPs and Tag Policies
# - OUs: Security, Infrastructure, Platform, Workloads, Sandbox
# - Core accounts: audit, log-archive, network
# - Service Control Policies
#
# Depends on: 00-bootstrap
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  backend "s3" {
    key = "01-organization/terraform.tfstate"
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Layer     = "01-organization"
      ManagedBy = "terraform"
    }
  }
}

################################################################################
# Variables
################################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "email_domain" {
  description = "Domain for account emails (e.g., example.com)"
  type        = string
}

variable "email_prefix" {
  description = "Prefix for account emails"
  type        = string
  default     = "aws"
}

variable "allowed_regions" {
  type    = list(string)
  default = ["us-east-1", "us-west-2"]
}

################################################################################
# Organization
################################################################################

resource "aws_organizations_organization" "main" {
  feature_set = "ALL"

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
  ]

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "ram.amazonaws.com",
    "sso.amazonaws.com",
  ]
}

################################################################################
# Organizational Units
################################################################################

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "platform" {
  name      = "Platform"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "prod" {
  name      = "Production"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "nonprod" {
  name      = "Non-Production"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = aws_organizations_organization.main.roots[0].id
}

################################################################################
# Core Accounts
################################################################################

resource "aws_organizations_account" "audit" {
  name      = "audit"
  email     = "${var.email_prefix}+audit@${var.email_domain}"
  parent_id = aws_organizations_organizational_unit.security.id
  role_name = "OrganizationAccountAccessRole"

  lifecycle { ignore_changes = [role_name] }
}

resource "aws_organizations_account" "log_archive" {
  name      = "log-archive"
  email     = "${var.email_prefix}+logs@${var.email_domain}"
  parent_id = aws_organizations_organizational_unit.security.id
  role_name = "OrganizationAccountAccessRole"

  lifecycle { ignore_changes = [role_name] }
}

resource "aws_organizations_account" "network" {
  name      = "network"
  email     = "${var.email_prefix}+network@${var.email_domain}"
  parent_id = aws_organizations_organizational_unit.infrastructure.id
  role_name = "OrganizationAccountAccessRole"

  lifecycle { ignore_changes = [role_name] }
}

################################################################################
# SCPs - Security Baseline
################################################################################

# Deny root user access in member accounts
resource "aws_organizations_policy" "deny_root" {
  name        = "deny-root"
  description = "Deny all actions by the root user in member accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyRoot"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
      Condition = { StringLike = { "aws:PrincipalArn" = "arn:aws:iam::*:root" } }
    }]
  })
}

resource "aws_organizations_policy_attachment" "deny_root" {
  policy_id = aws_organizations_policy.deny_root.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

# Restrict to approved regions
resource "aws_organizations_policy" "restrict_regions" {
  name        = "restrict-regions"
  description = "Restrict resource creation to approved regions"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyOtherRegions"
      Effect    = "Deny"
      NotAction = [
        "iam:*",
        "organizations:*",
        "support:*",
        "sts:*",
        "cloudfront:*",
        "route53:*",
        "route53domains:*",
        "budgets:*",
        "ce:*",
        "waf:*",
        "wafv2:*",
        "health:*",
        "globalaccelerator:*",
        "importexport:*",
        "pricing:*",
        "trustedadvisor:*"
      ]
      Resource  = "*"
      Condition = { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } }
    }]
  })
}

resource "aws_organizations_policy_attachment" "restrict_regions" {
  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

# Require tags on resource creation
resource "aws_organizations_policy" "require_tags" {
  name        = "require-tags"
  description = "Require Tenant and Environment tags on resource creation"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "RequireTags"
      Effect = "Deny"
      Action = [
        "ec2:RunInstances",
        "ec2:CreateVolume",
        "ec2:CreateSecurityGroup",
        "rds:CreateDBInstance",
        "rds:CreateDBCluster",
        "s3:CreateBucket",
        "lambda:CreateFunction",
        "ecs:CreateCluster",
        "eks:CreateCluster",
        "elasticache:CreateCacheCluster",
        "sqs:CreateQueue",
        "sns:CreateTopic"
      ]
      Resource = "*"
      Condition = {
        Null = {
          "aws:RequestTag/Tenant"      = "true"
          "aws:RequestTag/Environment" = "true"
        }
      }
    }]
  })
}

resource "aws_organizations_policy_attachment" "require_tags" {
  policy_id = aws_organizations_policy.require_tags.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

################################################################################
# SCPs - Data Protection
################################################################################

# Require encryption on S3 buckets
resource "aws_organizations_policy" "require_s3_encryption" {
  name        = "require-s3-encryption"
  description = "Deny unencrypted S3 object uploads"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyUnencryptedUploads"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      },
      {
        Sid      = "DenyNonAESEncryption"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption" = ["AES256", "aws:kms"]
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "require_s3_encryption" {
  policy_id = aws_organizations_policy.require_s3_encryption.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

# Prevent disabling of encryption
resource "aws_organizations_policy" "protect_encryption" {
  name        = "protect-encryption"
  description = "Prevent disabling encryption on critical services"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedRDS"
        Effect = "Deny"
        Action = [
          "rds:CreateDBInstance",
          "rds:CreateDBCluster"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedEBS"
        Effect = "Deny"
        Action = [
          "ec2:CreateVolume",
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "protect_encryption" {
  policy_id = aws_organizations_policy.protect_encryption.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

################################################################################
# SCPs - Network Security
################################################################################

# Prevent public access
resource "aws_organizations_policy" "deny_public_access" {
  name        = "deny-public-access"
  description = "Prevent creation of publicly accessible resources"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyPublicRDS"
        Effect = "Deny"
        Action = [
          "rds:CreateDBInstance",
          "rds:ModifyDBInstance"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:PubliclyAccessible" = "true"
          }
        }
      },
      {
        Sid    = "DenyPublicS3"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPublicAccessBlock"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:BlockPublicAcls"       = "true"
            "s3:BlockPublicPolicy"     = "true"
            "s3:IgnorePublicAcls"      = "true"
            "s3:RestrictPublicBuckets" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "deny_public_access" {
  policy_id = aws_organizations_policy.deny_public_access.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

# Require IMDSv2
resource "aws_organizations_policy" "require_imdsv2" {
  name        = "require-imdsv2"
  description = "Require IMDSv2 for EC2 instances"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "RequireIMDSv2"
      Effect   = "Deny"
      Action   = "ec2:RunInstances"
      Resource = "arn:aws:ec2:*:*:instance/*"
      Condition = {
        StringNotEquals = {
          "ec2:MetadataHttpTokens" = "required"
        }
      }
    }]
  })
}

resource "aws_organizations_policy_attachment" "require_imdsv2" {
  policy_id = aws_organizations_policy.require_imdsv2.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

################################################################################
# SCPs - Audit Protection
################################################################################

# Protect CloudTrail and GuardDuty
resource "aws_organizations_policy" "protect_security_services" {
  name        = "protect-security-services"
  description = "Prevent disabling of security monitoring services"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors"
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DeleteMembers",
          "guardduty:StopMonitoringMembers"
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectConfig"
        Effect = "Deny"
        Action = [
          "config:DeleteConfigRule",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:StopConfigurationRecorder"
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectSecurityHub"
        Effect = "Deny"
        Action = [
          "securityhub:DisableSecurityHub",
          "securityhub:DeleteMembers",
          "securityhub:DisassociateFromMasterAccount"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "protect_security_services" {
  policy_id = aws_organizations_policy.protect_security_services.id
  target_id = aws_organizations_organization.main.roots[0].id
}

################################################################################
# SCPs - Sandbox (Relaxed Controls)
################################################################################

# More permissive policy for sandbox accounts
resource "aws_organizations_policy" "sandbox_controls" {
  name        = "sandbox-controls"
  description = "Relaxed controls for sandbox experimentation"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowAll"
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "sandbox_controls" {
  policy_id = aws_organizations_policy.sandbox_controls.id
  target_id = aws_organizations_organizational_unit.sandbox.id
}

################################################################################
# Tag Policy
################################################################################

resource "aws_organizations_policy" "tags" {
  name = "mandatory-tags"
  type = "TAG_POLICY"

  content = jsonencode({
    tags = {
      Tenant      = { tag_key = { "@@assign" = "Tenant" } }
      Environment = { tag_key = { "@@assign" = "Environment" }, tag_value = { "@@assign" = ["prod", "staging", "dev", "sandbox"] } }
      App         = { tag_key = { "@@assign" = "App" } }
    }
  })
}

resource "aws_organizations_policy_attachment" "tags" {
  policy_id = aws_organizations_policy.tags.id
  target_id = aws_organizations_organization.main.roots[0].id
}

################################################################################
# Outputs
################################################################################

output "organization_id" {
  value = aws_organizations_organization.main.id
}

output "ou_ids" {
  value = {
    security       = aws_organizations_organizational_unit.security.id
    infrastructure = aws_organizations_organizational_unit.infrastructure.id
    platform       = aws_organizations_organizational_unit.platform.id
    workloads      = aws_organizations_organizational_unit.workloads.id
    production     = aws_organizations_organizational_unit.prod.id
    nonproduction  = aws_organizations_organizational_unit.nonprod.id
    sandbox        = aws_organizations_organizational_unit.sandbox.id
  }
}

output "account_ids" {
  value = {
    audit       = aws_organizations_account.audit.id
    log_archive = aws_organizations_account.log_archive.id
    network     = aws_organizations_account.network.id
  }
}
