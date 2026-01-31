################################################################################
# Workload: Secrets Manager
# 
# Secure secret storage:
# - KMS encryption
# - Automatic rotation (RDS, Redshift, DocumentDB, custom Lambda)
# - Cross-account access policies
# - Versioning and recovery
# - Replication to other regions
#
# Use cases: DB credentials, API keys, certificates, config
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }

  backend "s3" {
    key = "05-workloads/<TENANT>-<NAME>-secrets/terraform.tfstate"
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
  
  prefix = "${local.tenant}/${local.env}"

  # KMS encryption (null uses AWS managed key)
  kms_key_arn = null

  # Recovery window (days) - 0 for immediate deletion
  recovery_window_days = 30

  # Secrets to create
  secrets = {
    # Database credentials (auto-generated)
    "db/main" = {
      description = "Main database credentials"
      generate_password = true
      password_length   = 32
      exclude_characters = "\"@/\\"
      secret_string_template = jsonencode({
        username = "admin"
        engine   = "postgres"
        host     = "db.example.internal"
        port     = 5432
        dbname   = "main"
      })
      # RDS rotation
      rotation = {
        enabled = false
        # lambda_arn = "arn:aws:lambda:..."  # Rotation Lambda
        # days = 30
      }
    }

    # API keys (manual or generated)
    "api/stripe" = {
      description = "Stripe API keys"
      secret_string = jsonencode({
        publishable_key = "pk_live_placeholder"
        secret_key      = "sk_live_placeholder"
      })
    }

    # Generic config
    "config/app" = {
      description = "Application configuration"
      secret_string = jsonencode({
        feature_flags = {
          new_checkout = true
          beta_features = false
        }
        limits = {
          max_upload_mb = 100
          rate_limit_rpm = 1000
        }
      })
    }
  }

  # Cross-account access
  allowed_accounts = [
    # "123456789012",  # Dev account
    # "234567890123",  # Staging account
  ]

  # IAM principals allowed to read secrets
  allowed_principals = [
    # "arn:aws:iam::123456789012:role/app-role",
  ]

  # Replication to other regions
  replica_regions = [
    # "us-west-2",
    # "eu-west-1",
  ]
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
# KMS Key (optional - for customer managed encryption)
################################################################################

resource "aws_kms_key" "secrets" {
  count = local.kms_key_arn == null ? 1 : 0

  description             = "KMS key for ${local.prefix} secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Name = "${local.prefix}-secrets" }
}

resource "aws_kms_alias" "secrets" {
  count         = local.kms_key_arn == null ? 1 : 0
  name          = "alias/${replace(local.prefix, "/", "-")}-secrets"
  target_key_id = aws_kms_key.secrets[0].key_id
}

locals {
  effective_kms_key = local.kms_key_arn != null ? local.kms_key_arn : aws_kms_key.secrets[0].arn
}

################################################################################
# Random Passwords
################################################################################

resource "random_password" "secrets" {
  for_each = { for k, v in local.secrets : k => v if lookup(v, "generate_password", false) }

  length           = lookup(each.value, "password_length", 32)
  special          = true
  override_special = lookup(each.value, "override_special", "!#$%&*()-_=+[]{}<>:?")

  # Exclude problematic characters
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
  min_special = 1
}

################################################################################
# Secrets
################################################################################

resource "aws_secretsmanager_secret" "secrets" {
  for_each = local.secrets

  name        = "${local.prefix}/${each.key}"
  description = lookup(each.value, "description", "Secret for ${each.key}")
  kms_key_id  = local.effective_kms_key

  recovery_window_in_days = local.recovery_window_days

  # Replication
  dynamic "replica" {
    for_each = local.replica_regions
    content {
      region     = replica.value
      kms_key_id = null # Use default key in replica region
    }
  }

  tags = { Name = "${local.prefix}/${each.key}" }
}

################################################################################
# Secret Values
################################################################################

resource "aws_secretsmanager_secret_version" "secrets" {
  for_each = local.secrets

  secret_id = aws_secretsmanager_secret.secrets[each.key].id

  secret_string = lookup(each.value, "generate_password", false) ? jsonencode(merge(
    jsondecode(lookup(each.value, "secret_string_template", "{}")),
    { password = random_password.secrets[each.key].result }
  )) : lookup(each.value, "secret_string", "{}")
}

################################################################################
# Secret Rotation
################################################################################

resource "aws_secretsmanager_secret_rotation" "secrets" {
  for_each = { for k, v in local.secrets : k => v if lookup(lookup(v, "rotation", {}), "enabled", false) }

  secret_id           = aws_secretsmanager_secret.secrets[each.key].id
  rotation_lambda_arn = each.value.rotation.lambda_arn

  rotation_rules {
    automatically_after_days = lookup(each.value.rotation, "days", 30)
  }
}

################################################################################
# Resource Policy (Cross-Account Access)
################################################################################

resource "aws_secretsmanager_secret_policy" "cross_account" {
  for_each = length(local.allowed_accounts) > 0 || length(local.allowed_principals) > 0 ? local.secrets : {}

  secret_arn = aws_secretsmanager_secret.secrets[each.key].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      length(local.allowed_accounts) > 0 ? [{
        Sid    = "AllowCrossAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = [for acct in local.allowed_accounts : "arn:aws:iam::${acct}:root"]
        }
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      }] : [],
      length(local.allowed_principals) > 0 ? [{
        Sid    = "AllowPrincipalAccess"
        Effect = "Allow"
        Principal = {
          AWS = local.allowed_principals
        }
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      }] : []
    )
  })
}

################################################################################
# IAM Policy for Reading Secrets
################################################################################

resource "aws_iam_policy" "read_secrets" {
  name        = "${replace(local.prefix, "/", "-")}-secrets-read"
  description = "Read access to ${local.prefix} secrets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [for s in aws_secretsmanager_secret.secrets : s.arn]
      },
      {
        Sid    = "DecryptSecrets"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [local.effective_kms_key]
      }
    ]
  })

  tags = { Name = "${local.prefix}-secrets-read" }
}

resource "aws_iam_policy" "write_secrets" {
  name        = "${replace(local.prefix, "/", "-")}-secrets-write"
  description = "Write access to ${local.prefix} secrets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecret"
        ]
        Resource = [for s in aws_secretsmanager_secret.secrets : s.arn]
      },
      {
        Sid    = "EncryptDecryptSecrets"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [local.effective_kms_key]
      }
    ]
  })

  tags = { Name = "${local.prefix}-secrets-write" }
}

################################################################################
# Outputs
################################################################################

output "secret_arns" {
  value       = { for k, v in aws_secretsmanager_secret.secrets : k => v.arn }
  description = "Secret ARNs"
}

output "secret_names" {
  value       = { for k, v in aws_secretsmanager_secret.secrets : k => v.name }
  description = "Secret names"
}

output "kms_key_arn" {
  value       = local.effective_kms_key
  description = "KMS key ARN used for encryption"
}

output "read_policy_arn" {
  value       = aws_iam_policy.read_secrets.arn
  description = "IAM policy ARN for reading secrets"
}

output "write_policy_arn" {
  value       = aws_iam_policy.write_secrets.arn
  description = "IAM policy ARN for writing secrets"
}

output "secret_retrieval_commands" {
  value = {
    for k, v in aws_secretsmanager_secret.secrets : k =>
    "aws secretsmanager get-secret-value --secret-id ${v.name} --query SecretString --output text | jq ."
  }
  description = "CLI commands to retrieve each secret"
}
