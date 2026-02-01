################################################################################
# App Account Module
#
# Account vending machine for provisioning new workload accounts:
# - Creates AWS account via Organizations
# - Applies account baseline
# - Sets up cross-account IAM roles
# - Configures budget alerts
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

data "aws_organizations_organization" "this" {}

locals {
  # Generate account email if not provided
  account_email = var.account_email != "" ? var.account_email : "${var.email_prefix}+${var.account_name}@${var.email_domain}"

  # Standard account tags
  account_tags = {
    AccountName     = var.account_name
    Environment     = var.environment
    Owner           = var.owner
    CostCenter      = var.cost_center
    OrganizationUnit = var.organizational_unit
    ManagedBy       = "terraform"
  }
}

################################################################################
# AWS Account
################################################################################

resource "aws_organizations_account" "this" {
  name      = var.account_name
  email     = local.account_email
  parent_id = var.organizational_unit_id

  # IAM user access to billing (usually disabled)
  iam_user_access_to_billing = var.iam_user_access_to_billing ? "ALLOW" : "DENY"

  # Role name for cross-account access from management account
  role_name = var.admin_role_name

  # Don't close account on destroy (safety)
  close_on_deletion = var.close_on_deletion

  tags = merge(var.tags, local.account_tags)

  lifecycle {
    # Prevent accidental deletion
    prevent_destroy = false  # Set to true in production

    # Email cannot be changed
    ignore_changes = [email, role_name]
  }
}

################################################################################
# Cross-Account IAM Role (in new account)
# Note: This creates a role that can be assumed from the management account
################################################################################

# Provider for the new account (assumes role created during account creation)
provider "aws" {
  alias  = "new_account"
  region = var.region

  assume_role {
    role_arn     = "arn:aws:iam::${aws_organizations_account.this.id}:role/${var.admin_role_name}"
    session_name = "terraform-account-setup"
  }
}

# Readonly role for cross-account access
resource "aws_iam_role" "cross_account_readonly" {
  provider = aws.new_account
  count    = var.create_cross_account_roles ? 1 : 0

  name = "cross-account-readonly"
  path = "/cross-account/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.readonly_trusted_principals
      }
    }]
  })

  tags = merge(var.tags, {
    Name = "cross-account-readonly"
  })

  depends_on = [aws_organizations_account.this]
}

resource "aws_iam_role_policy_attachment" "cross_account_readonly" {
  provider = aws.new_account
  count    = var.create_cross_account_roles ? 1 : 0

  role       = aws_iam_role.cross_account_readonly[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Admin role for cross-account access (requires MFA)
resource "aws_iam_role" "cross_account_admin" {
  provider = aws.new_account
  count    = var.create_cross_account_roles ? 1 : 0

  name = "cross-account-admin"
  path = "/cross-account/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = var.admin_trusted_principals
      }
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })

  max_session_duration = 3600

  tags = merge(var.tags, {
    Name = "cross-account-admin"
  })

  depends_on = [aws_organizations_account.this]
}

resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  provider = aws.new_account
  count    = var.create_cross_account_roles ? 1 : 0

  role       = aws_iam_role.cross_account_admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

################################################################################
# Account Baseline (in new account)
################################################################################

module "account_baseline" {
  source = "../account-baseline"
  count  = var.apply_baseline ? 1 : 0

  providers = {
    aws = aws.new_account
  }

  name = var.account_name

  enable_ebs_encryption  = true
  enable_s3_block_public = true
  enable_password_policy = true
  enable_access_analyzer = true

  # Security services typically managed by delegated admin
  enable_securityhub = false
  enable_guardduty   = false
  enable_config      = false

  tags = merge(var.tags, local.account_tags)

  depends_on = [aws_organizations_account.this]
}

################################################################################
# Budget (in new account)
################################################################################

resource "aws_budgets_budget" "this" {
  provider = aws.new_account
  count    = var.budget_limit > 0 ? 1 : 0

  name         = "${var.account_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.owner_email != "" ? var.owner_email : local.account_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.owner_email != "" ? var.owner_email : local.account_email]
  }

  tags = merge(var.tags, {
    Name = "${var.account_name}-monthly-budget"
  })

  depends_on = [aws_organizations_account.this]
}
