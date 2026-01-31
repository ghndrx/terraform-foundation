################################################################################
# Workload: S3 Bucket
# 
# Multi-purpose S3 bucket with:
# - Versioning, encryption (KMS or S3)
# - Lifecycle rules (tiering, expiration)
# - Replication (cross-region DR)
# - Access logging
# - Event notifications (Lambda, SQS, SNS)
# - Object Lock (compliance/governance)
#
# Use cases: Data lake, backups, artifacts, logs, media storage
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
    key = "05-workloads/<TENANT>-<NAME>-bucket/terraform.tfstate"
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
  
  bucket_name = "${local.tenant}-${local.name}-${local.env}-${data.aws_caller_identity.current.account_id}"

  # Versioning
  versioning_enabled = true

  # Encryption
  encryption_type = "SSE-S3" # SSE-S3, SSE-KMS, or KMS ARN
  kms_key_arn     = null     # Set if using SSE-KMS

  # Public access (always blocked by default)
  block_public_access = true

  # Access logging
  enable_logging     = true
  logging_bucket     = null # Set to existing logging bucket, or creates one
  logging_prefix     = "s3-access-logs/${local.bucket_name}/"

  # Lifecycle rules
  lifecycle_rules = {
    transition-to-ia = {
      enabled = true
      filter = {
        prefix = ""
      }
      transitions = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]
      expiration_days = 365
      noncurrent_version_expiration_days = 90
    }
  }

  # Cross-region replication
  enable_replication   = false
  replication_region   = "us-west-2"
  replication_bucket   = null # Will create if null

  # Event notifications
  lambda_notifications = {
    # "object-created" = {
    #   lambda_arn = "arn:aws:lambda:..."
    #   events     = ["s3:ObjectCreated:*"]
    #   prefix     = "uploads/"
    #   suffix     = ".jpg"
    # }
  }

  sqs_notifications = {
    # "new-files" = {
    #   queue_arn = "arn:aws:sqs:..."
    #   events    = ["s3:ObjectCreated:*"]
    # }
  }

  # Object Lock (for compliance - cannot be disabled once enabled)
  object_lock_enabled = false
  object_lock_mode    = "GOVERNANCE" # GOVERNANCE or COMPLIANCE
  object_lock_days    = 30

  # CORS (for web access)
  cors_enabled = false
  cors_rules = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET", "HEAD"]
      allowed_origins = ["*"]
      max_age_seconds = 3600
    }
  ]

  # Intelligent tiering
  intelligent_tiering_enabled = false
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

provider "aws" {
  alias  = "replication"
  region = local.replication_region
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# S3 Bucket
################################################################################

resource "aws_s3_bucket" "main" {
  bucket = local.bucket_name

  dynamic "object_lock_configuration" {
    for_each = local.object_lock_enabled ? [1] : []
    content {
      object_lock_enabled = "Enabled"
    }
  }

  tags = { Name = local.bucket_name }
}

################################################################################
# Versioning
################################################################################

resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id

  versioning_configuration {
    status = local.versioning_enabled ? "Enabled" : "Suspended"
  }
}

################################################################################
# Encryption
################################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.encryption_type == "SSE-S3" ? "AES256" : "aws:kms"
      kms_master_key_id = local.encryption_type != "SSE-S3" ? (local.kms_key_arn != null ? local.kms_key_arn : null) : null
    }
    bucket_key_enabled = local.encryption_type != "SSE-S3"
  }
}

################################################################################
# Public Access Block
################################################################################

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = local.block_public_access
  block_public_policy     = local.block_public_access
  ignore_public_acls      = local.block_public_access
  restrict_public_buckets = local.block_public_access
}

################################################################################
# Access Logging
################################################################################

resource "aws_s3_bucket" "logs" {
  count  = local.enable_logging && local.logging_bucket == null ? 1 : 0
  bucket = "${local.bucket_name}-logs"

  tags = { Name = "${local.bucket_name}-logs" }
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = local.enable_logging && local.logging_bucket == null ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = local.enable_logging && local.logging_bucket == null ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = local.enable_logging && local.logging_bucket == null ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = local.enable_logging && local.logging_bucket == null ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_logging" "main" {
  count  = local.enable_logging ? 1 : 0
  bucket = aws_s3_bucket.main.id

  target_bucket = local.logging_bucket != null ? local.logging_bucket : aws_s3_bucket.logs[0].id
  target_prefix = local.logging_prefix
}

################################################################################
# Lifecycle Rules
################################################################################

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  count  = length(local.lifecycle_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.main.id

  dynamic "rule" {
    for_each = local.lifecycle_rules
    content {
      id     = rule.key
      status = rule.value.enabled ? "Enabled" : "Disabled"

      filter {
        prefix = lookup(rule.value.filter, "prefix", "")
      }

      dynamic "transition" {
        for_each = lookup(rule.value, "transitions", [])
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = lookup(rule.value, "expiration_days", null) != null ? [1] : []
        content {
          days = rule.value.expiration_days
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = lookup(rule.value, "noncurrent_version_expiration_days", null) != null ? [1] : []
        content {
          noncurrent_days = rule.value.noncurrent_version_expiration_days
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.main]
}

################################################################################
# Intelligent Tiering
################################################################################

resource "aws_s3_bucket_intelligent_tiering_configuration" "main" {
  count  = local.intelligent_tiering_enabled ? 1 : 0
  bucket = aws_s3_bucket.main.id
  name   = "EntireBucket"

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}

################################################################################
# CORS
################################################################################

resource "aws_s3_bucket_cors_configuration" "main" {
  count  = local.cors_enabled ? 1 : 0
  bucket = aws_s3_bucket.main.id

  dynamic "cors_rule" {
    for_each = local.cors_rules
    content {
      allowed_headers = cors_rule.value.allowed_headers
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      max_age_seconds = cors_rule.value.max_age_seconds
    }
  }
}

################################################################################
# Object Lock
################################################################################

resource "aws_s3_bucket_object_lock_configuration" "main" {
  count  = local.object_lock_enabled ? 1 : 0
  bucket = aws_s3_bucket.main.id

  rule {
    default_retention {
      mode = local.object_lock_mode
      days = local.object_lock_days
    }
  }
}

################################################################################
# Event Notifications
################################################################################

resource "aws_s3_bucket_notification" "main" {
  count  = length(local.lambda_notifications) > 0 || length(local.sqs_notifications) > 0 ? 1 : 0
  bucket = aws_s3_bucket.main.id

  dynamic "lambda_function" {
    for_each = local.lambda_notifications
    content {
      lambda_function_arn = lambda_function.value.lambda_arn
      events              = lambda_function.value.events
      filter_prefix       = lookup(lambda_function.value, "prefix", null)
      filter_suffix       = lookup(lambda_function.value, "suffix", null)
    }
  }

  dynamic "queue" {
    for_each = local.sqs_notifications
    content {
      queue_arn     = queue.value.queue_arn
      events        = queue.value.events
      filter_prefix = lookup(queue.value, "prefix", null)
      filter_suffix = lookup(queue.value, "suffix", null)
    }
  }
}

################################################################################
# Replication
################################################################################

resource "aws_s3_bucket" "replica" {
  count    = local.enable_replication && local.replication_bucket == null ? 1 : 0
  provider = aws.replication
  bucket   = "${local.bucket_name}-replica"

  tags = { Name = "${local.bucket_name}-replica" }
}

resource "aws_s3_bucket_versioning" "replica" {
  count    = local.enable_replication && local.replication_bucket == null ? 1 : 0
  provider = aws.replication
  bucket   = aws_s3_bucket.replica[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication" {
  count = local.enable_replication ? 1 : 0
  name  = "${local.bucket_name}-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "s3.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "replication" {
  count = local.enable_replication ? 1 : 0
  name  = "replication"
  role  = aws_iam_role.replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = "${aws_s3_bucket.main.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = "${local.replication_bucket != null ? local.replication_bucket : aws_s3_bucket.replica[0].arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "main" {
  count  = local.enable_replication ? 1 : 0
  bucket = aws_s3_bucket.main.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = local.replication_bucket != null ? local.replication_bucket : aws_s3_bucket.replica[0].arn
      storage_class = "STANDARD"
    }
  }

  depends_on = [aws_s3_bucket_versioning.main]
}

################################################################################
# Outputs
################################################################################

output "bucket_name" {
  value = aws_s3_bucket.main.id
}

output "bucket_arn" {
  value = aws_s3_bucket.main.arn
}

output "bucket_domain_name" {
  value = aws_s3_bucket.main.bucket_regional_domain_name
}

output "replica_bucket" {
  value = local.enable_replication && local.replication_bucket == null ? aws_s3_bucket.replica[0].id : local.replication_bucket
}

output "logging_bucket" {
  value = local.enable_logging && local.logging_bucket == null ? aws_s3_bucket.logs[0].id : local.logging_bucket
}
