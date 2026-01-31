################################################################################
# Tenant Onboarding Module
# Creates: Tenant OUs, App Accounts, IAM Groups, Budgets
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_organizations_organization" "main" {}

data "aws_ssoadmin_instances" "main" {}

################################################################################
# Tenant OUs
################################################################################

resource "aws_organizations_organizational_unit" "tenant_prod" {
  name      = "tenant-${var.tenant}-prod"
  parent_id = var.production_ou_id
}

resource "aws_organizations_organizational_unit" "tenant_nonprod" {
  name      = "tenant-${var.tenant}-nonprod"
  parent_id = var.nonproduction_ou_id
}

################################################################################
# App Accounts
################################################################################

locals {
  # Generate all app/environment combinations
  app_accounts = {
    for combo in setproduct(keys(var.apps), var.environments) :
    "${combo[0]}-${combo[1]}" => {
      app = combo[0]
      env = combo[1]
    }
  }
}

resource "aws_organizations_account" "app" {
  for_each = local.app_accounts

  name      = "${var.tenant}-${each.value.app}-${each.value.env}"
  email     = "${var.email_prefix}+${var.tenant}-${each.value.app}-${each.value.env}@${var.email_domain}"
  role_name = "OrganizationAccountAccessRole"

  parent_id = each.value.env == "prod" ? (
    aws_organizations_organizational_unit.tenant_prod.id
  ) : (
    aws_organizations_organizational_unit.tenant_nonprod.id
  )

  tags = {
    Tenant      = var.tenant
    App         = each.value.app
    Environment = each.value.env
    ManagedBy   = "terraform"
  }

  lifecycle {
    ignore_changes = [role_name]
  }
}

################################################################################
# IAM Identity Center - Tenant Group
################################################################################

resource "aws_identitystore_group" "tenant" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
  display_name      = "Tenant-${var.tenant}"
  description       = "All users for tenant ${var.tenant}"
}

# Create role-specific groups
resource "aws_identitystore_group" "tenant_admins" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
  display_name      = "Tenant-${var.tenant}-Admins"
  description       = "Admins for tenant ${var.tenant}"
}

resource "aws_identitystore_group" "tenant_developers" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
  display_name      = "Tenant-${var.tenant}-Developers"
  description       = "Developers for tenant ${var.tenant}"
}

resource "aws_identitystore_group" "tenant_readonly" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
  display_name      = "Tenant-${var.tenant}-ReadOnly"
  description       = "Read-only users for tenant ${var.tenant}"
}

################################################################################
# Account Assignments - Admin access to all tenant accounts
################################################################################

resource "aws_ssoadmin_account_assignment" "admin" {
  for_each = aws_organizations_account.app

  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = var.permission_set_admin_arn

  principal_id   = aws_identitystore_group.tenant_admins.group_id
  principal_type = "GROUP"

  target_id   = each.value.id
  target_type = "AWS_ACCOUNT"
}

# Developer access to non-prod only
resource "aws_ssoadmin_account_assignment" "developer" {
  for_each = {
    for k, v in aws_organizations_account.app : k => v
    if local.app_accounts[k].env != "prod"
  }

  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = var.permission_set_developer_arn

  principal_id   = aws_identitystore_group.tenant_developers.group_id
  principal_type = "GROUP"

  target_id   = each.value.id
  target_type = "AWS_ACCOUNT"
}

# Read-only access to all accounts
resource "aws_ssoadmin_account_assignment" "readonly" {
  for_each = aws_organizations_account.app

  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = var.permission_set_readonly_arn

  principal_id   = aws_identitystore_group.tenant_readonly.group_id
  principal_type = "GROUP"

  target_id   = each.value.id
  target_type = "AWS_ACCOUNT"
}

################################################################################
# Budgets
################################################################################

resource "aws_budgets_budget" "tenant" {
  name         = "${var.tenant}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["Tenant$${var.tenant}"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = var.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = var.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "FORECASTED"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = var.alert_emails
  }
}

# Per-app budgets
resource "aws_budgets_budget" "app" {
  for_each = var.apps

  name         = "${var.tenant}-${each.key}-budget"
  budget_type  = "COST"
  limit_amount = each.value.monthly_budget
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["App$${each.key}"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = [each.value.owner_email]
  }
}

################################################################################
# Outputs
################################################################################

output "tenant_ou_ids" {
  value = {
    prod    = aws_organizations_organizational_unit.tenant_prod.id
    nonprod = aws_organizations_organizational_unit.tenant_nonprod.id
  }
}

output "account_ids" {
  value = {
    for k, v in aws_organizations_account.app : k => v.id
  }
}

output "group_ids" {
  value = {
    all        = aws_identitystore_group.tenant.group_id
    admins     = aws_identitystore_group.tenant_admins.group_id
    developers = aws_identitystore_group.tenant_developers.group_id
    readonly   = aws_identitystore_group.tenant_readonly.group_id
  }
}
