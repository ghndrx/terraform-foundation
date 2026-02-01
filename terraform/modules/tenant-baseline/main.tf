################################################################################
# Tenant Baseline Module
#
# Composite module that provisions a complete tenant environment:
# - Tenant IAM roles with permissions boundary
# - Tenant budget alerts
# - Tenant VPC (optional)
# - Standard tagging
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

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Standard tenant tags
  tenant_tags = merge(var.tags, {
    Tenant      = var.tenant_name
    TenantId    = var.tenant_id
    Environment = var.environment
    CostCenter  = var.cost_center
    Owner       = var.owner_email
    ManagedBy   = "terraform"
  })
}

################################################################################
# Tenant IAM
################################################################################

module "tenant_iam" {
  source = "../tenant-iam"

  tenant_name = var.tenant_name
  tenant_id   = var.tenant_id

  create_permissions_boundary = var.create_permissions_boundary
  create_admin_role           = var.create_admin_role
  create_developer_role       = var.create_developer_role
  create_readonly_role        = var.create_readonly_role

  trusted_principals = var.trusted_principals
  allowed_services   = var.allowed_services
  require_mfa        = var.require_mfa

  tags = local.tenant_tags
}

################################################################################
# Tenant Budget
################################################################################

module "tenant_budget" {
  source = "../tenant-budget"

  name         = var.tenant_name
  budget_limit = var.budget_limit

  alert_thresholds         = var.budget_alert_thresholds
  enable_forecasted_alerts = var.enable_forecasted_alerts
  notification_emails      = var.budget_notification_emails

  cost_filter_tags = {
    Tenant = var.tenant_name
  }

  tags = local.tenant_tags
}

################################################################################
# Tenant VPC (Optional)
################################################################################

module "tenant_vpc" {
  source = "../tenant-vpc"
  count  = var.create_vpc ? 1 : 0

  tenant_name = var.tenant_name
  cidr        = var.vpc_cidr
  azs         = var.vpc_azs

  public_subnets  = var.vpc_public_subnets
  private_subnets = var.vpc_private_subnets

  enable_nat = var.vpc_enable_nat
  nat_mode   = var.vpc_nat_mode

  transit_gateway_id = var.transit_gateway_id
  enable_flow_logs   = var.enable_flow_logs

  tags = local.tenant_tags
}
