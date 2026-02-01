################################################################################
# Layer 04: Tenant - <TENANT_NAME>
# 
# Creates tenant-specific resources:
# - Security Groups (tenant-scoped, blocks cross-tenant traffic)
# - IAM Roles with ABAC (can only access Tenant=X resources)
# - Budgets with alerts
#
# Usage:
#   ./scripts/new-tenant.sh acme
#   cd terraform/04-tenants/acme
#   # Edit locals below
#   terraform init -backend-config=../../00-bootstrap/backend.hcl
#   terraform apply -var="state_bucket=YOUR_BUCKET"
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
    key = "04-tenants/<TENANT_NAME>/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Tenant name (max 20 chars, lowercase, alphanumeric + hyphen)
  tenant = "<TENANT_NAME>"

  # Environment
  env = "prod" # prod, staging, dev

  # Short prefix for resources (tenant-env, max 28 chars total)
  prefix = "${local.tenant}-${local.env}"

  # Apps with ports and budgets
  apps = {
    api = {
      port   = 8080
      budget = 200
      owner  = "team@example.com"
    }
    web = {
      port   = 3000
      budget = 100
      owner  = "team@example.com"
    }
  }

  # Budget
  budget       = 500
  alert_emails = ["ops@example.com"]
}

################################################################################
# Variables
################################################################################

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "state_bucket" {
  type = string
}

################################################################################
# Provider
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Tenant      = local.tenant
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "02-network/terraform.tfstate"
    region = var.region
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Security Group - Base (intra-tenant)
################################################################################

resource "aws_security_group" "base" {
  name        = "${local.prefix}-base"
  description = "Base SG for ${local.tenant} - intra-tenant only"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description = "Self"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-base" }
}

################################################################################
# Security Group - Web (public)
################################################################################

resource "aws_security_group" "web" {
  name        = "${local.prefix}-web"
  description = "Web SG for ${local.tenant}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-web" }
}

################################################################################
# Security Group - Database
################################################################################

resource "aws_security_group" "db" {
  name        = "${local.prefix}-db"
  description = "DB SG for ${local.tenant}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description     = "PostgreSQL"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.base.id]
  }

  ingress {
    description     = "MySQL"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.base.id]
  }

  ingress {
    description     = "Redis"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.base.id]
  }

  tags = { Name = "${local.prefix}-db" }
}

################################################################################
# Security Groups - Per App
################################################################################

resource "aws_security_group" "app" {
  for_each = { for k, v in local.apps : k => v if v.port > 0 }

  name        = "${local.prefix}-${each.key}"
  description = "SG for ${local.tenant} ${each.key}"
  vpc_id      = data.terraform_remote_state.network.outputs.vpc_id

  ingress {
    description     = "App port"
    from_port       = each.value.port
    to_port         = each.value.port
    protocol        = "tcp"
    security_groups = [aws_security_group.base.id]
  }

  ingress {
    description = "Self"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.prefix}-${each.key}"
    App  = each.key
  }
}

################################################################################
# IAM Role - Admin (ABAC)
################################################################################

resource "aws_iam_role" "admin" {
  name = "${local.prefix}-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })

  tags = { Name = "${local.prefix}-admin" }
}

resource "aws_iam_role_policy" "admin" {
  name = "abac"
  role = aws_iam_role.admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowTagged"
        Effect   = "Allow"
        Action   = ["ec2:*", "ecs:*", "ecr:*", "lambda:*", "rds:*", "s3:*", "dynamodb:*", "logs:*", "cloudwatch:*", "ssm:*", "secretsmanager:*", "elasticloadbalancing:*"]
        Resource = "*"
        Condition = { StringEquals = { "aws:ResourceTag/Tenant" = local.tenant } }
      },
      {
        Sid      = "AllowDescribe"
        Effect   = "Allow"
        Action   = ["ec2:Describe*", "ecs:Describe*", "ecs:List*", "rds:Describe*", "s3:ListAllMyBuckets", "lambda:List*", "logs:Describe*", "elasticloadbalancing:Describe*"]
        Resource = "*"
      },
      {
        Sid      = "AllowCreateTagged"
        Effect   = "Allow"
        Action   = ["ec2:RunInstances", "ec2:CreateVolume", "rds:CreateDBInstance", "s3:CreateBucket", "lambda:CreateFunction", "ecs:CreateCluster"]
        Resource = "*"
        Condition = { StringEquals = { "aws:RequestTag/Tenant" = local.tenant } }
      },
      {
        Sid      = "AllowTagging"
        Effect   = "Allow"
        Action   = ["ec2:CreateTags", "rds:AddTagsToResource", "s3:PutBucketTagging", "lambda:TagResource"]
        Resource = "*"
        Condition = { StringEquals = { "aws:RequestTag/Tenant" = local.tenant } }
      }
    ]
  })
}

################################################################################
# IAM Role - Developer (limited)
################################################################################

resource "aws_iam_role" "developer" {
  name = "${local.prefix}-dev"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })

  tags = { Name = "${local.prefix}-dev" }
}

resource "aws_iam_role_policy" "developer" {
  name = "dev-access"
  role = aws_iam_role.developer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOnly"
        Effect   = "Allow"
        Action   = ["ec2:Describe*", "ecs:Describe*", "ecs:List*", "logs:*", "cloudwatch:Get*", "cloudwatch:List*", "ssm:GetParameter*"]
        Resource = "*"
      },
      {
        Sid      = "DeployLambda"
        Effect   = "Allow"
        Action   = ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"]
        Resource = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${local.tenant}-*"
      }
    ]
  })
}

################################################################################
# IAM Role - ReadOnly
################################################################################

resource "aws_iam_role" "readonly" {
  name                = "${local.prefix}-ro"
  managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })

  tags = { Name = "${local.prefix}-ro" }
}

################################################################################
# Budget - Tenant Total
################################################################################

resource "aws_budgets_budget" "tenant" {
  name         = "${local.prefix}-total"
  budget_type  = "COST"
  limit_amount = tostring(local.budget)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["Tenant$${local.tenant}"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = local.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = local.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "FORECASTED"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = local.alert_emails
  }
}

################################################################################
# Budget - Per App
################################################################################

resource "aws_budgets_budget" "app" {
  for_each = local.apps

  name         = "${local.prefix}-${each.key}"
  budget_type  = "COST"
  limit_amount = tostring(each.value.budget)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["App$${each.key}"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 90
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = [each.value.owner]
  }
}

################################################################################
# Outputs
################################################################################

output "tenant" {
  value = local.tenant
}

output "security_groups" {
  value = {
    base = aws_security_group.base.id
    web  = aws_security_group.web.id
    db   = aws_security_group.db.id
    apps = { for k, v in aws_security_group.app : k => v.id }
  }
}

output "iam_roles" {
  value = {
    admin     = aws_iam_role.admin.arn
    developer = aws_iam_role.developer.arn
    readonly  = aws_iam_role.readonly.arn
  }
}

output "subnets" {
  value = data.terraform_remote_state.network.outputs.private_subnet_ids
}

output "vpc_id" {
  value = data.terraform_remote_state.network.outputs.vpc_id
}
