################################################################################
# Workload: DynamoDB Table
# 
# Deploys a NoSQL database table:
# - On-demand or provisioned capacity
# - Encryption at rest with KMS
# - Point-in-time recovery
# - TTL support
# - Global Secondary Indexes
# - Streams for event-driven patterns
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<table-name>/
#   Update locals and variables
#   terraform init -backend-config=../../00-bootstrap/backend.hcl
#   terraform apply
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
    key = "05-workloads/<TENANT>-<NAME>-table/terraform.tfstate"
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
  
  table_name = "${local.tenant}-${local.name}-${local.env}"

  # Capacity mode: "PAY_PER_REQUEST" (on-demand) or "PROVISIONED"
  billing_mode = "PAY_PER_REQUEST"

  # Provisioned capacity (only used if billing_mode = "PROVISIONED")
  read_capacity  = 5
  write_capacity = 5

  # Auto-scaling for provisioned mode
  enable_autoscaling     = local.billing_mode == "PROVISIONED"
  autoscaling_min_read   = 5
  autoscaling_max_read   = 100
  autoscaling_min_write  = 5
  autoscaling_max_write  = 100
  autoscaling_target_utilization = 70

  # Primary key
  hash_key       = "pk"      # Partition key
  hash_key_type  = "S"       # S = String, N = Number, B = Binary
  range_key      = "sk"      # Sort key (optional, set to null to disable)
  range_key_type = "S"

  # TTL (set to null to disable)
  ttl_attribute = "ttl"

  # Streams (set to null to disable)
  # Options: KEYS_ONLY, NEW_IMAGE, OLD_IMAGE, NEW_AND_OLD_IMAGES
  stream_view_type = null

  # Point-in-time recovery
  point_in_time_recovery = true

  # Global Secondary Indexes (GSI)
  global_secondary_indexes = [
    # {
    #   name            = "gsi1"
    #   hash_key        = "gsi1pk"
    #   range_key       = "gsi1sk"
    #   projection_type = "ALL"  # ALL, KEYS_ONLY, or INCLUDE
    #   non_key_attributes = []  # Only for INCLUDE
    # }
  ]

  # Local Secondary Indexes (LSI) - must be defined at table creation
  local_secondary_indexes = [
    # {
    #   name            = "lsi1"
    #   range_key       = "lsi1sk"
    #   projection_type = "ALL"
    #   non_key_attributes = []
    # }
  ]

  # Table class: STANDARD or STANDARD_INFREQUENT_ACCESS
  table_class = "STANDARD"
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
# KMS Key
################################################################################

resource "aws_kms_key" "table" {
  description             = "KMS key for ${local.table_name} DynamoDB encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${local.table_name}-dynamodb" }
}

resource "aws_kms_alias" "table" {
  name          = "alias/${local.table_name}-dynamodb"
  target_key_id = aws_kms_key.table.key_id
}

################################################################################
# DynamoDB Table
################################################################################

resource "aws_dynamodb_table" "main" {
  name         = local.table_name
  billing_mode = local.billing_mode
  table_class  = local.table_class

  # Capacity (only for PROVISIONED)
  read_capacity  = local.billing_mode == "PROVISIONED" ? local.read_capacity : null
  write_capacity = local.billing_mode == "PROVISIONED" ? local.write_capacity : null

  # Primary key
  hash_key  = local.hash_key
  range_key = local.range_key

  # Key schema
  attribute {
    name = local.hash_key
    type = local.hash_key_type
  }

  dynamic "attribute" {
    for_each = local.range_key != null ? [1] : []
    content {
      name = local.range_key
      type = local.range_key_type
    }
  }

  # GSI attributes
  dynamic "attribute" {
    for_each = local.global_secondary_indexes
    content {
      name = attribute.value.hash_key
      type = "S"
    }
  }

  dynamic "attribute" {
    for_each = [for gsi in local.global_secondary_indexes : gsi if gsi.range_key != null]
    content {
      name = attribute.value.range_key
      type = "S"
    }
  }

  # LSI attributes
  dynamic "attribute" {
    for_each = local.local_secondary_indexes
    content {
      name = attribute.value.range_key
      type = "S"
    }
  }

  # Global Secondary Indexes
  dynamic "global_secondary_index" {
    for_each = local.global_secondary_indexes
    content {
      name            = global_secondary_index.value.name
      hash_key        = global_secondary_index.value.hash_key
      range_key       = lookup(global_secondary_index.value, "range_key", null)
      projection_type = global_secondary_index.value.projection_type
      non_key_attributes = global_secondary_index.value.projection_type == "INCLUDE" ? global_secondary_index.value.non_key_attributes : null

      # Capacity for provisioned mode
      read_capacity  = local.billing_mode == "PROVISIONED" ? local.read_capacity : null
      write_capacity = local.billing_mode == "PROVISIONED" ? local.write_capacity : null
    }
  }

  # Local Secondary Indexes
  dynamic "local_secondary_index" {
    for_each = local.local_secondary_indexes
    content {
      name            = local_secondary_index.value.name
      range_key       = local_secondary_index.value.range_key
      projection_type = local_secondary_index.value.projection_type
      non_key_attributes = local_secondary_index.value.projection_type == "INCLUDE" ? local_secondary_index.value.non_key_attributes : null
    }
  }

  # TTL
  dynamic "ttl" {
    for_each = local.ttl_attribute != null ? [1] : []
    content {
      attribute_name = local.ttl_attribute
      enabled        = true
    }
  }

  # Streams
  stream_enabled   = local.stream_view_type != null
  stream_view_type = local.stream_view_type

  # Encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.table.arn
  }

  # Point-in-time recovery
  point_in_time_recovery {
    enabled = local.point_in_time_recovery
  }

  # Deletion protection for prod
  deletion_protection_enabled = local.env == "prod"

  tags = { 
    Name   = local.table_name
    Backup = "true"
  }

  lifecycle {
    prevent_destroy = false # Set to true for production
  }
}

################################################################################
# Auto Scaling (Provisioned Mode Only)
################################################################################

resource "aws_appautoscaling_target" "read" {
  count              = local.enable_autoscaling ? 1 : 0
  max_capacity       = local.autoscaling_max_read
  min_capacity       = local.autoscaling_min_read
  resource_id        = "table/${aws_dynamodb_table.main.name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "read" {
  count              = local.enable_autoscaling ? 1 : 0
  name               = "${local.table_name}-read-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.read[0].resource_id
  scalable_dimension = aws_appautoscaling_target.read[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.read[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value = local.autoscaling_target_utilization
  }
}

resource "aws_appautoscaling_target" "write" {
  count              = local.enable_autoscaling ? 1 : 0
  max_capacity       = local.autoscaling_max_write
  min_capacity       = local.autoscaling_min_write
  resource_id        = "table/${aws_dynamodb_table.main.name}"
  scalable_dimension = "dynamodb:table:WriteCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "write" {
  count              = local.enable_autoscaling ? 1 : 0
  name               = "${local.table_name}-write-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.write[0].resource_id
  scalable_dimension = aws_appautoscaling_target.write[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.write[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBWriteCapacityUtilization"
    }
    target_value = local.autoscaling_target_utilization
  }
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "throttled_requests" {
  alarm_name          = "${local.table_name}-throttled-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "DynamoDB throttled requests detected"

  dimensions = {
    TableName = aws_dynamodb_table.main.name
  }

  tags = { Name = "${local.table_name}-throttled" }
}

resource "aws_cloudwatch_metric_alarm" "system_errors" {
  alarm_name          = "${local.table_name}-system-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "DynamoDB system errors detected"

  dimensions = {
    TableName = aws_dynamodb_table.main.name
  }

  tags = { Name = "${local.table_name}-errors" }
}

################################################################################
# IAM Policy Document (for application access)
################################################################################

data "aws_iam_policy_document" "table_access" {
  statement {
    sid    = "AllowTableOperations"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:DeleteItem",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
      "dynamodb:DescribeTable",
    ]

    resources = [
      aws_dynamodb_table.main.arn,
      "${aws_dynamodb_table.main.arn}/index/*",
    ]
  }

  statement {
    sid    = "AllowKMSDecrypt"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]

    resources = [aws_kms_key.table.arn]
  }
}

################################################################################
# Outputs
################################################################################

output "table_name" {
  value = aws_dynamodb_table.main.name
}

output "table_arn" {
  value = aws_dynamodb_table.main.arn
}

output "table_id" {
  value = aws_dynamodb_table.main.id
}

output "stream_arn" {
  value = aws_dynamodb_table.main.stream_arn
}

output "kms_key_arn" {
  value = aws_kms_key.table.arn
}

output "access_policy_json" {
  value       = data.aws_iam_policy_document.table_access.json
  description = "IAM policy document for application access to this table"
}
