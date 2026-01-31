################################################################################
# Workload: SSM Parameter Store
# 
# Configuration management (cheaper than Secrets Manager for non-secrets):
# - String, StringList, SecureString parameters
# - Hierarchical paths for organization
# - KMS encryption for SecureString
# - Parameter policies (expiration, notification)
# - Cross-account access
#
# Cost: Free for standard parameters, $0.05/10K API calls for advanced
# Use Secrets Manager for: rotation, cross-region replication, RDS integration
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
    key = "05-workloads/<TENANT>-<NAME>-params/terraform.tfstate"
  }
}

################################################################################
# Configuration - UPDATE THESE
################################################################################

locals {
  # Naming
  tenant = "<TENANT>"
  name   = "<NAME>"
  env    = "prod"
  
  prefix = "/${local.tenant}/${local.env}/${local.name}"

  # KMS key for SecureString (null = AWS managed key)
  kms_key_arn = null

  # Parameter tier: Standard (free, 4KB) or Advanced ($0.05/param/mo, 8KB)
  tier = "Standard"

  # Parameters to create
  parameters = {
    # Application config
    "config/app_name" = {
      type        = "String"
      value       = local.name
      description = "Application name"
    }
    
    "config/environment" = {
      type        = "String"
      value       = local.env
      description = "Environment name"
    }
    
    "config/log_level" = {
      type        = "String"
      value       = "INFO"
      description = "Application log level"
    }
    
    "config/feature_flags" = {
      type        = "String"
      value       = jsonencode({
        new_checkout    = true
        dark_mode       = false
        beta_features   = false
      })
      description = "Feature flags JSON"
    }

    # Database config (non-secret parts)
    "database/host" = {
      type        = "String"
      value       = "db.example.internal"
      description = "Database hostname"
    }
    
    "database/port" = {
      type        = "String"
      value       = "5432"
      description = "Database port"
    }
    
    "database/name" = {
      type        = "String"
      value       = "myapp"
      description = "Database name"
    }

    # Secure values (encrypted with KMS)
    # Note: Update this value after deployment via CLI:
    # aws ssm put-parameter --name "/<tenant>/<env>/<app>/secrets/api_key" --value "real-secret" --type SecureString --overwrite
    "secrets/api_key" = {
      type        = "SecureString"
      value       = "initial-value-update-after-deploy"
      description = "External API key"
    }

    # List example
    "config/allowed_origins" = {
      type        = "StringList"
      value       = "https://example.com,https://app.example.com"
      description = "CORS allowed origins"
    }
  }

  # Parameters with expiration policies (Advanced tier only)
  expiring_parameters = {
    # "tokens/temp_token" = {
    #   type        = "SecureString"
    #   value       = "temp-value"
    #   description = "Temporary token"
    #   expiration  = "2024-12-31T23:59:59Z"
    # }
  }
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
      App         = local.name
      Environment = local.env
      ManagedBy   = "terraform"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# SSM Parameters
################################################################################

resource "aws_ssm_parameter" "params" {
  for_each = local.parameters

  name        = "${local.prefix}/${each.key}"
  description = lookup(each.value, "description", "Parameter ${each.key}")
  type        = each.value.type
  value       = each.value.value
  tier        = local.tier

  key_id = each.value.type == "SecureString" ? local.kms_key_arn : null

  tags = { 
    Name = "${local.prefix}/${each.key}"
    Type = each.value.type
  }

  # Uncomment to prevent Terraform from updating SecureString values
  # (useful when managing secrets externally via CLI/console)
  # lifecycle {
  #   ignore_changes = [value]
  # }
}

################################################################################
# Parameters with Expiration (Advanced Tier)
################################################################################

resource "aws_ssm_parameter" "expiring" {
  for_each = local.expiring_parameters

  name        = "${local.prefix}/${each.key}"
  description = lookup(each.value, "description", "Parameter ${each.key}")
  type        = each.value.type
  value       = each.value.value
  tier        = "Advanced" # Required for policies
  overwrite   = true       # Allow updates to existing parameters

  key_id = each.value.type == "SecureString" ? local.kms_key_arn : null

  # Note: Parameter policies (expiration, notification) require AWS SDK/CLI
  # Use aws ssm put-parameter with --policies flag for expiration:
  # aws ssm put-parameter --name "/path/param" --policies '[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2024-12-31T23:59:59.000Z"}}]'

  tags = { 
    Name       = "${local.prefix}/${each.key}"
    Type       = each.value.type
    Expiration = lookup(each.value, "expiration", "none")
  }
}

################################################################################
# IAM Policy for Reading Parameters
################################################################################

resource "aws_iam_policy" "read" {
  name        = "${local.tenant}-${local.name}-ssm-read"
  description = "Read access to ${local.prefix} parameters"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeParameters"
        Effect = "Allow"
        Action = [
          "ssm:DescribeParameters"
        ]
        Resource = "*"
      },
      {
        Sid    = "GetParameters"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${local.prefix}/*"
      },
      {
        Sid    = "DecryptSecureStrings"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = local.kms_key_arn != null ? [local.kms_key_arn] : ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"]
      }
    ]
  })

  tags = { Name = "${local.tenant}-${local.name}-ssm-read" }
}

resource "aws_iam_policy" "write" {
  name        = "${local.tenant}-${local.name}-ssm-write"
  description = "Write access to ${local.prefix} parameters"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageParameters"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:DeleteParameter",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:DescribeParameters"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${local.prefix}/*"
      },
      {
        Sid    = "EncryptDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = local.kms_key_arn != null ? [local.kms_key_arn] : ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"]
      }
    ]
  })

  tags = { Name = "${local.tenant}-${local.name}-ssm-write" }
}

################################################################################
# Outputs
################################################################################

output "parameter_arns" {
  value       = { for k, v in aws_ssm_parameter.params : k => v.arn }
  description = "Parameter ARNs"
}

output "parameter_names" {
  value       = { for k, v in aws_ssm_parameter.params : k => v.name }
  description = "Full parameter names (paths)"
}

output "prefix" {
  value       = local.prefix
  description = "Parameter path prefix"
}

output "read_policy_arn" {
  value       = aws_iam_policy.read.arn
  description = "IAM policy ARN for reading parameters"
}

output "write_policy_arn" {
  value       = aws_iam_policy.write.arn
  description = "IAM policy ARN for writing parameters"
}

output "sdk_examples" {
  value = {
    get_single = "aws ssm get-parameter --name '${local.prefix}/config/app_name' --query Parameter.Value --output text"
    get_secure = "aws ssm get-parameter --name '${local.prefix}/secrets/api_key' --with-decryption --query Parameter.Value --output text"
    get_path   = "aws ssm get-parameters-by-path --path '${local.prefix}/config' --recursive --query 'Parameters[*].[Name,Value]' --output table"
    put_param  = "aws ssm put-parameter --name '${local.prefix}/config/new_param' --value 'my-value' --type String --overwrite"
  }
  description = "Example CLI commands"
}

output "cost_estimate" {
  value = {
    standard_params = "Free (up to 10,000 parameters)"
    advanced_params = "$0.05/parameter/month"
    api_calls       = "Free for standard, $0.05 per 10,000 for advanced"
    note            = "SecureString encryption uses KMS (may have additional costs)"
  }
  description = "Cost information"
}
