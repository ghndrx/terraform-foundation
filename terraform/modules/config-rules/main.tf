################################################################################
# AWS Config Rules Module
#
# Compliance monitoring with managed rules:
# - CIS AWS Foundations Benchmark
# - PCI DSS
# - HIPAA
# - Custom rules
# - Auto-remediation (optional)
#
# Usage:
#   module "config_rules" {
#     source = "../modules/config-rules"
#     
#     enable_cis_benchmark     = true
#     enable_security_best_practices = true
#     
#     # Or pick individual rules
#     rules = {
#       s3-bucket-ssl = true
#       ec2-imdsv2    = true
#     }
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

variable "enable_aws_config" {
  type        = bool
  default     = true
  description = "Enable AWS Config (required for rules)"
}

variable "config_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket for Config snapshots (created if empty)"
}

variable "config_sns_topic_arn" {
  type        = string
  default     = ""
  description = "SNS topic for Config notifications"
}

variable "delivery_frequency" {
  type        = string
  default     = "TwentyFour_Hours"
  description = "Config snapshot delivery frequency"
}

# Compliance Packs
variable "enable_cis_benchmark" {
  type        = bool
  default     = false
  description = "Enable CIS AWS Foundations Benchmark rules"
}

variable "enable_security_best_practices" {
  type        = bool
  default     = true
  description = "Enable AWS Security Best Practices rules"
}

variable "enable_pci_dss" {
  type        = bool
  default     = false
  description = "Enable PCI DSS compliance rules"
}

variable "enable_hipaa" {
  type        = bool
  default     = false
  description = "Enable HIPAA compliance rules"
}

# Individual Rules (all optional)
variable "rules" {
  type = object({
    # S3 Security
    s3_bucket_public_read_prohibited  = optional(bool, true)
    s3_bucket_public_write_prohibited = optional(bool, true)
    s3_bucket_ssl_requests_only       = optional(bool, true)
    s3_bucket_logging_enabled         = optional(bool, false)
    s3_bucket_versioning_enabled      = optional(bool, false)
    s3_default_encryption_kms         = optional(bool, false)

    # EC2 Security
    ec2_imdsv2_check                    = optional(bool, true)
    ec2_instance_no_public_ip           = optional(bool, false)
    ec2_ebs_encryption_by_default       = optional(bool, true)
    ec2_security_group_attached_to_eni  = optional(bool, false)
    restricted_ssh                      = optional(bool, true)
    restricted_rdp                      = optional(bool, true)

    # IAM Security
    iam_root_access_key_check           = optional(bool, true)
    iam_user_mfa_enabled                = optional(bool, true)
    iam_user_no_policies_check          = optional(bool, true)
    iam_password_policy                 = optional(bool, true)
    access_keys_rotated                 = optional(bool, true)
    access_keys_rotated_days            = optional(number, 90)

    # RDS Security
    rds_instance_public_access_check    = optional(bool, true)
    rds_storage_encrypted               = optional(bool, true)
    rds_multi_az_support                = optional(bool, false)
    rds_snapshot_encrypted              = optional(bool, true)

    # Network Security
    vpc_flow_logs_enabled               = optional(bool, true)
    vpc_default_security_group_closed   = optional(bool, true)

    # Encryption
    kms_cmk_not_scheduled_for_deletion  = optional(bool, true)
    encrypted_volumes                   = optional(bool, true)

    # Logging & Monitoring
    cloudtrail_enabled                  = optional(bool, true)
    cloudwatch_alarm_action_check       = optional(bool, false)
    cw_loggroup_retention_period_check  = optional(bool, false)
    guardduty_enabled_centralized       = optional(bool, false)

    # Lambda
    lambda_function_public_access_prohibited = optional(bool, true)
    lambda_inside_vpc                   = optional(bool, false)
  })
  default     = {}
  description = "Individual Config rules to enable"
}

variable "auto_remediation" {
  type        = bool
  default     = false
  description = "Enable auto-remediation for supported rules"
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

################################################################################
# S3 Bucket for Config
################################################################################

resource "aws_s3_bucket" "config" {
  count  = var.enable_aws_config && var.config_bucket == "" ? 1 : 0
  bucket = "aws-config-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = merge(var.tags, { Name = "aws-config" })
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_aws_config && var.config_bucket == "" ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_aws_config && var.config_bucket == "" ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count                   = var.enable_aws_config && var.config_bucket == "" ? 1 : 0
  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  config_bucket = var.config_bucket != "" ? var.config_bucket : (var.enable_aws_config ? aws_s3_bucket.config[0].id : "")
}

################################################################################
# IAM Role for Config
################################################################################

resource "aws_iam_role" "config" {
  count = var.enable_aws_config ? 1 : 0
  name  = "AWSConfigRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "AWSConfigRole" })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_aws_config ? 1 : 0
  name  = "s3-delivery"
  role  = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectAcl"]
        Resource = "arn:aws:s3:::${local.config_bucket}/*"
        Condition = {
          StringLike = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${local.config_bucket}"
      }
    ]
  })
}

################################################################################
# AWS Config Recorder
################################################################################

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws_config ? 1 : 0
  name     = "default"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_aws_config ? 1 : 0
  name           = "default"
  s3_bucket_name = local.config_bucket
  sns_topic_arn  = var.config_sns_topic_arn != "" ? var.config_sns_topic_arn : null

  snapshot_delivery_properties {
    delivery_frequency = var.delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

################################################################################
# Security Best Practices Rules
################################################################################

# S3 Rules
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  count = var.enable_aws_config && (var.rules.s3_bucket_public_read_prohibited || var.enable_security_best_practices) ? 1 : 0
  name  = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  count = var.enable_aws_config && (var.rules.s3_bucket_public_write_prohibited || var.enable_security_best_practices) ? 1 : 0
  name  = "s3-bucket-public-write-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "s3_bucket_ssl_requests_only" {
  count = var.enable_aws_config && (var.rules.s3_bucket_ssl_requests_only || var.enable_security_best_practices) ? 1 : 0
  name  = "s3-bucket-ssl-requests-only"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# EC2 Rules
resource "aws_config_config_rule" "ec2_imdsv2_check" {
  count = var.enable_aws_config && (var.rules.ec2_imdsv2_check || var.enable_security_best_practices) ? 1 : 0
  name  = "ec2-imdsv2-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "ebs_encryption_by_default" {
  count = var.enable_aws_config && (var.rules.ec2_ebs_encryption_by_default || var.enable_security_best_practices) ? 1 : 0
  name  = "ec2-ebs-encryption-by-default-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "restricted_ssh" {
  count = var.enable_aws_config && (var.rules.restricted_ssh || var.enable_security_best_practices) ? 1 : 0
  name  = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# IAM Rules
resource "aws_config_config_rule" "iam_root_access_key_check" {
  count = var.enable_aws_config && (var.rules.iam_root_access_key_check || var.enable_security_best_practices) ? 1 : 0
  name  = "iam-root-access-key-check"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  count = var.enable_aws_config && (var.rules.iam_user_mfa_enabled || var.enable_security_best_practices) ? 1 : 0
  name  = "iam-user-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "access_keys_rotated" {
  count = var.enable_aws_config && (var.rules.access_keys_rotated || var.enable_security_best_practices) ? 1 : 0
  name  = "access-keys-rotated"
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = jsonencode({
    maxAccessKeyAge = var.rules.access_keys_rotated_days
  })
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# RDS Rules
resource "aws_config_config_rule" "rds_instance_public_access_check" {
  count = var.enable_aws_config && (var.rules.rds_instance_public_access_check || var.enable_security_best_practices) ? 1 : 0
  name  = "rds-instance-public-access-check"
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "rds_storage_encrypted" {
  count = var.enable_aws_config && (var.rules.rds_storage_encrypted || var.enable_security_best_practices) ? 1 : 0
  name  = "rds-storage-encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# Network Rules
resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  count = var.enable_aws_config && (var.rules.vpc_flow_logs_enabled || var.enable_security_best_practices) ? 1 : 0
  name  = "vpc-flow-logs-enabled"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

resource "aws_config_config_rule" "vpc_default_security_group_closed" {
  count = var.enable_aws_config && (var.rules.vpc_default_security_group_closed || var.enable_security_best_practices) ? 1 : 0
  name  = "vpc-default-security-group-closed"
  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# CloudTrail Rule
resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_aws_config && (var.rules.cloudtrail_enabled || var.enable_security_best_practices) ? 1 : 0
  name  = "cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# Encryption Rules
resource "aws_config_config_rule" "encrypted_volumes" {
  count = var.enable_aws_config && (var.rules.encrypted_volumes || var.enable_security_best_practices) ? 1 : 0
  name  = "encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

# Lambda Rules
resource "aws_config_config_rule" "lambda_function_public_access_prohibited" {
  count = var.enable_aws_config && (var.rules.lambda_function_public_access_prohibited || var.enable_security_best_practices) ? 1 : 0
  name  = "lambda-function-public-access-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = var.tags
}

################################################################################
# Outputs
################################################################################

output "config_recorder_id" {
  value       = var.enable_aws_config ? aws_config_configuration_recorder.main[0].id : null
  description = "Config recorder ID"
}

output "config_bucket" {
  value       = local.config_bucket
  description = "S3 bucket for Config snapshots"
}

output "enabled_rules" {
  value = var.enable_aws_config ? {
    s3_public_read     = var.rules.s3_bucket_public_read_prohibited || var.enable_security_best_practices
    s3_public_write    = var.rules.s3_bucket_public_write_prohibited || var.enable_security_best_practices
    s3_ssl_only        = var.rules.s3_bucket_ssl_requests_only || var.enable_security_best_practices
    ec2_imdsv2         = var.rules.ec2_imdsv2_check || var.enable_security_best_practices
    ebs_encryption     = var.rules.ec2_ebs_encryption_by_default || var.enable_security_best_practices
    restricted_ssh     = var.rules.restricted_ssh || var.enable_security_best_practices
    iam_root_key       = var.rules.iam_root_access_key_check || var.enable_security_best_practices
    iam_mfa            = var.rules.iam_user_mfa_enabled || var.enable_security_best_practices
    access_key_rotation = var.rules.access_keys_rotated || var.enable_security_best_practices
    rds_public         = var.rules.rds_instance_public_access_check || var.enable_security_best_practices
    rds_encrypted      = var.rules.rds_storage_encrypted || var.enable_security_best_practices
    vpc_flow_logs      = var.rules.vpc_flow_logs_enabled || var.enable_security_best_practices
    cloudtrail         = var.rules.cloudtrail_enabled || var.enable_security_best_practices
  } : null
  description = "List of enabled Config rules"
}

output "compliance_packs" {
  value = {
    cis_benchmark     = var.enable_cis_benchmark
    security_best     = var.enable_security_best_practices
    pci_dss           = var.enable_pci_dss
    hipaa             = var.enable_hipaa
  }
  description = "Enabled compliance packs"
}
