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
# SCPs
################################################################################

resource "aws_organizations_policy" "deny_root" {
  name = "deny-root"
  type = "SERVICE_CONTROL_POLICY"

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

resource "aws_organizations_policy" "restrict_regions" {
  name = "restrict-regions"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyOtherRegions"
      Effect    = "Deny"
      NotAction = ["iam:*", "organizations:*", "support:*", "sts:*", "cloudfront:*", "route53:*", "budgets:*", "ce:*", "waf:*", "health:*"]
      Resource  = "*"
      Condition = { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } }
    }]
  })
}

resource "aws_organizations_policy_attachment" "restrict_regions" {
  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_policy" "require_tags" {
  name = "require-tags"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "RequireTags"
      Effect   = "Deny"
      Action   = ["ec2:RunInstances", "ec2:CreateVolume", "rds:CreateDBInstance", "s3:CreateBucket", "lambda:CreateFunction"]
      Resource = "*"
      Condition = { Null = { "aws:RequestTag/Tenant" = "true", "aws:RequestTag/Environment" = "true" } }
    }]
  })
}

resource "aws_organizations_policy_attachment" "require_tags" {
  policy_id = aws_organizations_policy.require_tags.id
  target_id = aws_organizations_organizational_unit.workloads.id
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
