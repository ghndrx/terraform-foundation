################################################################################
# RAM Share Module
#
# Shares resources across accounts via AWS Resource Access Manager:
# - VPC subnets
# - Transit Gateway
# - Route53 Resolver rules
# - Any RAM-supported resource
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

data "aws_organizations_organization" "this" {
  count = var.share_with_organization ? 1 : 0
}

locals {
  # Organization ARN for org-wide sharing
  org_arn = var.share_with_organization ? data.aws_organizations_organization.this[0].arn : null
}

################################################################################
# Resource Share
################################################################################

resource "aws_ram_resource_share" "this" {
  name                      = var.name
  allow_external_principals = var.allow_external_principals

  # Enable org sharing if specified
  permission_arns = var.permission_arns

  tags = merge(var.tags, {
    Name = var.name
  })
}

################################################################################
# Resource Associations
################################################################################

resource "aws_ram_resource_association" "this" {
  for_each = toset(var.resource_arns)

  resource_arn       = each.value
  resource_share_arn = aws_ram_resource_share.this.arn
}

################################################################################
# Principal Associations
################################################################################

# Share with organization
resource "aws_ram_principal_association" "organization" {
  count = var.share_with_organization ? 1 : 0

  principal          = local.org_arn
  resource_share_arn = aws_ram_resource_share.this.arn
}

# Share with specific OUs
resource "aws_ram_principal_association" "ous" {
  for_each = toset(var.principal_ous)

  principal          = each.value
  resource_share_arn = aws_ram_resource_share.this.arn
}

# Share with specific accounts
resource "aws_ram_principal_association" "accounts" {
  for_each = toset(var.principal_accounts)

  principal          = each.value
  resource_share_arn = aws_ram_resource_share.this.arn
}
