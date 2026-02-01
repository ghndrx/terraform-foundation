################################################################################
# Layer 00: Bootstrap
# 
# First layer - creates foundational resources needed by all other layers:
# - Terraform state bucket
# - DynamoDB lock table
# - KMS key for encryption
#
# Supports two deployment modes:
#   - single-account: Everything in one account (small scale / startup)
#   - multi-account:  Separate accounts per environment (enterprise)
#
# Run: terraform init && terraform apply
# Next: 01-organization (multi-account) or 02-network (single-account)
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # First run uses local state, then migrate to S3
  # backend "s3" {
  #   bucket         = "your-org-terraform-state"
  #   key            = "00-bootstrap/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Layer     = "00-bootstrap"
      ManagedBy = "terraform"
      Project   = var.project_name
    }
  }
}

################################################################################
# Variables
################################################################################

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name (used for naming resources)"
  type        = string
}

variable "deployment_mode" {
  description = "Deployment mode: 'single-account' or 'multi-account'"
  type        = string
  default     = "single-account"

  validation {
    condition     = contains(["single-account", "multi-account"], var.deployment_mode)
    error_message = "deployment_mode must be 'single-account' or 'multi-account'"
  }
}

################################################################################
# S3 Bucket for Terraform State
################################################################################

resource "aws_s3_bucket" "terraform_state" {
  bucket = "${var.project_name}-terraform-state"

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name = "Terraform State"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# S3 Bucket for Access Logs (Audit Trail)
################################################################################

resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "Access Logs"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # S3-managed keys for log delivery compatibility
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years for compliance
    }
  }
}

# Policy to allow various AWS services to write logs
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSSLRequestsOnly"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource = aws_s3_bucket.logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "ELBLogDelivery"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.elb_account_id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/alb/*"
      }
    ]
  })
}

# ELB account IDs by region (for ALB access logging)
locals {
  elb_account_ids = {
    us-east-1      = "127311923021"
    us-east-2      = "033677994240"
    us-west-1      = "027434742980"
    us-west-2      = "797873946194"
    eu-west-1      = "156460612806"
    eu-west-2      = "652711504416"
    eu-central-1   = "054676820928"
    ap-southeast-1 = "114774131450"
    ap-southeast-2 = "783225319266"
    ap-northeast-1 = "582318560864"
  }
  elb_account_id = lookup(local.elb_account_ids, var.region, "127311923021")
}

data "aws_caller_identity" "current" {}

################################################################################
# DynamoDB Table for State Locking
################################################################################

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "${var.project_name}-terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  # Encryption at rest with AWS managed key (free) or use KMS for compliance
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform.arn
  }

  # Point-in-time recovery for compliance
  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "Terraform Lock Table"
  }
}

################################################################################
# KMS Key for State Encryption
################################################################################

resource "aws_kms_key" "terraform" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "Terraform State Key"
  }
}

resource "aws_kms_alias" "terraform" {
  name          = "alias/${var.project_name}-terraform"
  target_key_id = aws_kms_key.terraform.key_id
}

################################################################################
# Outputs
################################################################################

output "state_bucket" {
  value = aws_s3_bucket.terraform_state.id
}

output "lock_table" {
  value = aws_dynamodb_table.terraform_locks.id
}

output "kms_key_arn" {
  value = aws_kms_key.terraform.arn
}

output "region" {
  value = var.region
}

output "project_name" {
  value = var.project_name
}

output "deployment_mode" {
  value = var.deployment_mode
}

output "logs_bucket" {
  value = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}

################################################################################
# Backend Config Generator
################################################################################

resource "local_file" "backend_config" {
  filename = "${path.module}/backend.hcl"
  content  = <<-EOT
    bucket         = "${aws_s3_bucket.terraform_state.id}"
    region         = "${var.region}"
    dynamodb_table = "${aws_dynamodb_table.terraform_locks.id}"
    encrypt        = true
  EOT
}

################################################################################
# Next Steps
################################################################################

output "next_steps" {
  value = var.deployment_mode == "single-account" ? <<-EOT
    
    Single-Account Mode Selected
    ============================
    Skip 01-organization, go directly to:
    
    cd ../02-network
    terraform init -backend-config=../00-bootstrap/backend.hcl
    terraform apply -var="state_bucket=${aws_s3_bucket.terraform_state.id}" -var="deployment_mode=single-account"
    
  EOT
  : <<-EOT
    
    Multi-Account Mode Selected
    ===========================
    Next step:
    
    cd ../01-organization
    terraform init -backend-config=../00-bootstrap/backend.hcl
    terraform apply
    
  EOT
}
