################################################################################
# CloudTrail Module
#
# Audit logging for AWS API activity:
# - Management events (console, CLI, SDK)
# - Data events (S3, Lambda, DynamoDB)
# - Insights events (anomaly detection)
# - Multi-region trail
# - KMS encryption
# - CloudWatch Logs integration
# - S3 bucket with lifecycle
#
# Usage:
#   module "cloudtrail" {
#     source = "../modules/cloudtrail"
#     name   = "org-trail"
#     
#     enable_data_events = true
#     data_event_buckets = ["my-bucket"]
#   }
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type        = string
  description = "Trail name"
}

variable "s3_bucket_name" {
  type        = string
  default     = ""
  description = "S3 bucket for logs (created if empty)"
}

variable "is_multi_region" {
  type        = bool
  default     = true
  description = "Enable multi-region trail"
}

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = "Organization-wide trail (requires org management account)"
}

variable "enable_log_file_validation" {
  type        = bool
  default     = true
  description = "Enable log file integrity validation"
}

variable "include_global_service_events" {
  type        = bool
  default     = true
  description = "Include global service events (IAM, STS, CloudFront)"
}

variable "enable_cloudwatch_logs" {
  type        = bool
  default     = true
  description = "Send logs to CloudWatch Logs"
}

variable "cloudwatch_log_retention_days" {
  type        = number
  default     = 90
  description = "CloudWatch log retention in days"
}

variable "enable_insights" {
  type        = bool
  default     = false
  description = "Enable CloudTrail Insights (additional cost)"
}

variable "insight_selectors" {
  type        = list(string)
  default     = ["ApiCallRateInsight", "ApiErrorRateInsight"]
  description = "Insight types to enable"
}

variable "enable_data_events" {
  type        = bool
  default     = false
  description = "Enable data events logging"
}

variable "data_event_s3_buckets" {
  type        = list(string)
  default     = []
  description = "S3 bucket ARNs for data events (empty = all buckets)"
}

variable "data_event_lambda_functions" {
  type        = list(string)
  default     = []
  description = "Lambda function ARNs for data events (empty = all functions)"
}

variable "data_event_dynamodb_tables" {
  type        = list(string)
  default     = []
  description = "DynamoDB table ARNs for data events"
}

variable "kms_key_arn" {
  type        = string
  default     = ""
  description = "KMS key ARN for encryption (created if empty)"
}

variable "s3_log_retention_days" {
  type        = number
  default     = 365
  description = "S3 log retention in days"
}

variable "s3_transition_to_glacier_days" {
  type        = number
  default     = 90
  description = "Days before transitioning logs to Glacier"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "${var.name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  create_bucket = var.s3_bucket_name == ""
  create_kms    = var.kms_key_arn == ""
}

################################################################################
# KMS Key
################################################################################

resource "aws_kms_key" "cloudtrail" {
  count = local.create_kms ? 1 : 0

  description             = "CloudTrail encryption key for ${var.name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.name}"
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },
      {
        Sid    = "Allow log decryption"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = "${var.name}-cloudtrail" })
}

resource "aws_kms_alias" "cloudtrail" {
  count         = local.create_kms ? 1 : 0
  name          = "alias/${var.name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail[0].key_id
}

locals {
  kms_key_arn = local.create_kms ? aws_kms_key.cloudtrail[0].arn : var.kms_key_arn
}

################################################################################
# S3 Bucket
################################################################################

resource "aws_s3_bucket" "cloudtrail" {
  count  = local.create_bucket ? 1 : 0
  bucket = local.bucket_name

  tags = merge(var.tags, { Name = local.bucket_name })
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "archive-and-expire"
    status = "Enabled"

    transition {
      days          = var.s3_transition_to_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.s3_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = local.create_bucket ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.name}"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.name}"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail[0].arn,
          "${aws_s3_bucket.cloudtrail[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

################################################################################
# CloudWatch Logs
################################################################################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudwatch_logs ? 1 : 0
  name              = "/aws/cloudtrail/${var.name}"
  retention_in_days = var.cloudwatch_log_retention_days

  tags = merge(var.tags, { Name = var.name })
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "${var.name}-cloudtrail-cloudwatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name}-cloudtrail-cloudwatch" })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "cloudwatch-logs"
  role  = aws_iam_role.cloudtrail_cloudwatch[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
    }]
  })
}

################################################################################
# CloudTrail
################################################################################

resource "aws_cloudtrail" "main" {
  name                          = var.name
  s3_bucket_name                = local.create_bucket ? aws_s3_bucket.cloudtrail[0].id : var.s3_bucket_name
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region
  is_organization_trail         = var.is_organization_trail
  enable_log_file_validation    = var.enable_log_file_validation
  kms_key_id                    = local.kms_key_arn

  cloud_watch_logs_group_arn = var.enable_cloudwatch_logs ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
  cloud_watch_logs_role_arn  = var.enable_cloudwatch_logs ? aws_iam_role.cloudtrail_cloudwatch[0].arn : null

  # Insights
  dynamic "insight_selector" {
    for_each = var.enable_insights ? var.insight_selectors : []
    content {
      insight_type = insight_selector.value
    }
  }

  # Data events
  dynamic "event_selector" {
    for_each = var.enable_data_events ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = true

      # S3 data events
      dynamic "data_resource" {
        for_each = length(var.data_event_s3_buckets) > 0 ? [1] : (var.enable_data_events ? [1] : [])
        content {
          type   = "AWS::S3::Object"
          values = length(var.data_event_s3_buckets) > 0 ? var.data_event_s3_buckets : ["arn:aws:s3"]
        }
      }

      # Lambda data events
      dynamic "data_resource" {
        for_each = length(var.data_event_lambda_functions) > 0 ? [1] : []
        content {
          type   = "AWS::Lambda::Function"
          values = var.data_event_lambda_functions
        }
      }

      # DynamoDB data events
      dynamic "data_resource" {
        for_each = length(var.data_event_dynamodb_tables) > 0 ? [1] : []
        content {
          type   = "AWS::DynamoDB::Table"
          values = var.data_event_dynamodb_tables
        }
      }
    }
  }

  tags = merge(var.tags, { Name = var.name })

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
  ]
}

################################################################################
# Outputs
################################################################################

output "trail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "CloudTrail ARN"
}

output "trail_name" {
  value       = aws_cloudtrail.main.name
  description = "CloudTrail name"
}

output "s3_bucket" {
  value       = local.create_bucket ? aws_s3_bucket.cloudtrail[0].id : var.s3_bucket_name
  description = "S3 bucket for CloudTrail logs"
}

output "kms_key_arn" {
  value       = local.kms_key_arn
  description = "KMS key ARN for encryption"
}

output "cloudwatch_log_group" {
  value       = var.enable_cloudwatch_logs ? aws_cloudwatch_log_group.cloudtrail[0].name : null
  description = "CloudWatch Logs group"
}

output "home_region" {
  value       = aws_cloudtrail.main.home_region
  description = "Trail home region"
}
