################################################################################
# Workload: WAFv2 Web ACL
# 
# Deploys a WAFv2 Web ACL with:
# - AWS Managed Rules (Core, Known Bad Inputs, SQL injection, etc.)
# - Optional Bot Control and IP Reputation
# - Custom rate limiting rules
# - Geo-blocking capabilities
# - IP allowlist/denylist support
# - CloudWatch metrics and optional logging
# - Association with ALB, API Gateway, CloudFront, or App Runner
#
# Usage:
#   Copy this folder to 05-workloads/<tenant>-<name>-waf/
#   Update locals
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
    key = "05-workloads/<TENANT>-<NAME>-waf/terraform.tfstate"
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
  
  waf_name = "${local.tenant}-${local.name}-${local.env}"

  # Scope: REGIONAL (ALB, API Gateway, App Runner) or CLOUDFRONT
  # Note: CLOUDFRONT scope requires us-east-1 provider
  scope = "REGIONAL"

  # Default action: allow or block unmatched requests
  default_action = "allow"

  # CloudWatch metrics
  cloudwatch_metrics_enabled = true

  # Logging (S3, CloudWatch Logs, or Kinesis Firehose)
  logging_enabled = true
  log_destination = "cloudwatch" # "s3", "cloudwatch", or "firehose"
  log_retention_days = 30

  # Sample requests for rule matches
  sampled_requests_enabled = true

  #############################################################################
  # AWS Managed Rules - Enable/disable as needed
  #############################################################################
  
  managed_rules = {
    # Core rule set - OWASP Top 10 protections
    AWSManagedRulesCommonRuleSet = {
      enabled  = true
      priority = 10
      override_action = "none" # "none" to use rule actions, "count" to count only
      excluded_rules  = []     # e.g., ["SizeRestrictions_BODY"]
    }

    # Known bad inputs (Log4j, etc.)
    AWSManagedRulesKnownBadInputsRuleSet = {
      enabled  = true
      priority = 20
      override_action = "none"
      excluded_rules  = []
    }

    # SQL injection protection
    AWSManagedRulesSQLiRuleSet = {
      enabled  = true
      priority = 30
      override_action = "none"
      excluded_rules  = []
    }

    # Linux OS protection
    AWSManagedRulesLinuxRuleSet = {
      enabled  = false
      priority = 40
      override_action = "none"
      excluded_rules  = []
    }

    # Unix OS protection  
    AWSManagedRulesUnixRuleSet = {
      enabled  = false
      priority = 50
      override_action = "none"
      excluded_rules  = []
    }

    # Windows OS protection
    AWSManagedRulesWindowsRuleSet = {
      enabled  = false
      priority = 60
      override_action = "none"
      excluded_rules  = []
    }

    # PHP application protection
    AWSManagedRulesPHPRuleSet = {
      enabled  = false
      priority = 70
      override_action = "none"
      excluded_rules  = []
    }

    # WordPress protection
    AWSManagedRulesWordPressRuleSet = {
      enabled  = false
      priority = 80
      override_action = "none"
      excluded_rules  = []
    }

    # Amazon IP reputation list
    AWSManagedRulesAmazonIpReputationList = {
      enabled  = true
      priority = 90
      override_action = "none"
      excluded_rules  = []
    }

    # Anonymous IP list (VPNs, proxies, Tor)
    AWSManagedRulesAnonymousIpList = {
      enabled  = false
      priority = 100
      override_action = "none"
      excluded_rules  = []
    }

    # Bot Control (additional costs apply)
    AWSManagedRulesBotControlRuleSet = {
      enabled  = false
      priority = 110
      override_action = "none"
      excluded_rules  = []
    }

    # Account Takeover Prevention (additional costs apply)
    AWSManagedRulesATPRuleSet = {
      enabled  = false
      priority = 120
      override_action = "none"
      excluded_rules  = []
    }
  }

  #############################################################################
  # Custom Rules
  #############################################################################

  # Rate limiting rule (requests per 5-minute window per IP)
  rate_limit_enabled   = true
  rate_limit_threshold = 2000
  rate_limit_priority  = 1

  # Geo-blocking (block requests from specific countries)
  geo_block_enabled   = false
  geo_block_countries = ["RU", "CN", "KP"] # ISO 3166-1 alpha-2 codes
  geo_block_priority  = 2

  # IP allowlist (always allow these IPs, bypasses other rules)
  ip_allowlist_enabled = false
  ip_allowlist         = [] # e.g., ["203.0.113.0/24", "198.51.100.1/32"]
  ip_allowlist_priority = 0

  # IP denylist (always block these IPs)
  ip_denylist_enabled = false
  ip_denylist         = []
  ip_denylist_priority = 3

  #############################################################################
  # Resource Association (optional)
  #############################################################################

  # Associate with existing resources (leave empty to skip)
  # For ALB: ARN of the ALB
  # For API Gateway: ARN of the stage
  # For App Runner: ARN of the service
  # For CloudFront: handled separately (scope must be CLOUDFRONT)
  associate_resource_arns = []
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
# IP Sets (for allowlist/denylist)
################################################################################

resource "aws_wafv2_ip_set" "allowlist" {
  count              = local.ip_allowlist_enabled ? 1 : 0
  name               = "${local.waf_name}-allowlist"
  description        = "IP allowlist for ${local.waf_name}"
  scope              = local.scope
  ip_address_version = "IPV4"
  addresses          = local.ip_allowlist

  tags = { Name = "${local.waf_name}-allowlist" }
}

resource "aws_wafv2_ip_set" "denylist" {
  count              = local.ip_denylist_enabled ? 1 : 0
  name               = "${local.waf_name}-denylist"
  description        = "IP denylist for ${local.waf_name}"
  scope              = local.scope
  ip_address_version = "IPV4"
  addresses          = local.ip_denylist

  tags = { Name = "${local.waf_name}-denylist" }
}

################################################################################
# Web ACL
################################################################################

resource "aws_wafv2_web_acl" "main" {
  name        = local.waf_name
  description = "WAF Web ACL for ${local.tenant} ${local.name}"
  scope       = local.scope

  default_action {
    dynamic "allow" {
      for_each = local.default_action == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = local.default_action == "block" ? [1] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = local.cloudwatch_metrics_enabled
    metric_name                = replace(local.waf_name, "-", "")
    sampled_requests_enabled   = local.sampled_requests_enabled
  }

  #############################################################################
  # IP Allowlist Rule (highest priority - allows bypass)
  #############################################################################
  
  dynamic "rule" {
    for_each = local.ip_allowlist_enabled ? [1] : []
    content {
      name     = "ip-allowlist"
      priority = local.ip_allowlist_priority

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowlist[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = local.cloudwatch_metrics_enabled
        metric_name                = "${replace(local.waf_name, "-", "")}IPAllowlist"
        sampled_requests_enabled   = local.sampled_requests_enabled
      }
    }
  }

  #############################################################################
  # Rate Limiting Rule
  #############################################################################

  dynamic "rule" {
    for_each = local.rate_limit_enabled ? [1] : []
    content {
      name     = "rate-limit"
      priority = local.rate_limit_priority

      action {
        block {}
      }

      statement {
        rate_based_statement {
          limit              = local.rate_limit_threshold
          aggregate_key_type = "IP"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = local.cloudwatch_metrics_enabled
        metric_name                = "${replace(local.waf_name, "-", "")}RateLimit"
        sampled_requests_enabled   = local.sampled_requests_enabled
      }
    }
  }

  #############################################################################
  # Geo-blocking Rule
  #############################################################################

  dynamic "rule" {
    for_each = local.geo_block_enabled ? [1] : []
    content {
      name     = "geo-block"
      priority = local.geo_block_priority

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = local.geo_block_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = local.cloudwatch_metrics_enabled
        metric_name                = "${replace(local.waf_name, "-", "")}GeoBlock"
        sampled_requests_enabled   = local.sampled_requests_enabled
      }
    }
  }

  #############################################################################
  # IP Denylist Rule
  #############################################################################

  dynamic "rule" {
    for_each = local.ip_denylist_enabled ? [1] : []
    content {
      name     = "ip-denylist"
      priority = local.ip_denylist_priority

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.denylist[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = local.cloudwatch_metrics_enabled
        metric_name                = "${replace(local.waf_name, "-", "")}IPDenylist"
        sampled_requests_enabled   = local.sampled_requests_enabled
      }
    }
  }

  #############################################################################
  # AWS Managed Rules
  #############################################################################

  dynamic "rule" {
    for_each = { for k, v in local.managed_rules : k => v if v.enabled }
    content {
      name     = rule.key
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.key
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = rule.value.excluded_rules
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = local.cloudwatch_metrics_enabled
        metric_name                = "${replace(local.waf_name, "-", "")}${rule.key}"
        sampled_requests_enabled   = local.sampled_requests_enabled
      }
    }
  }

  tags = { Name = local.waf_name }
}

################################################################################
# Logging - CloudWatch Logs
################################################################################

resource "aws_cloudwatch_log_group" "waf" {
  count             = local.logging_enabled && local.log_destination == "cloudwatch" ? 1 : 0
  name              = "aws-waf-logs-${local.waf_name}"
  retention_in_days = local.log_retention_days

  tags = { Name = "aws-waf-logs-${local.waf_name}" }
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudwatch" {
  count                   = local.logging_enabled && local.log_destination == "cloudwatch" ? 1 : 0
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]
  resource_arn            = aws_wafv2_web_acl.main.arn

  # Optional: filter logs (e.g., only blocked requests)
  # logging_filter {
  #   default_behavior = "DROP"
  #   filter {
  #     behavior    = "KEEP"
  #     requirement = "MEETS_ANY"
  #     condition {
  #       action_condition {
  #         action = "BLOCK"
  #       }
  #     }
  #   }
  # }
}

################################################################################
# Logging - S3 (alternative)
################################################################################

resource "aws_s3_bucket" "waf_logs" {
  count  = local.logging_enabled && local.log_destination == "s3" ? 1 : 0
  bucket = "aws-waf-logs-${data.aws_caller_identity.current.account_id}-${local.waf_name}"

  tags = { Name = "aws-waf-logs-${local.waf_name}" }
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  count  = local.logging_enabled && local.log_destination == "s3" ? 1 : 0
  bucket = aws_s3_bucket.waf_logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = local.log_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  count  = local.logging_enabled && local.log_destination == "s3" ? 1 : 0
  bucket = aws_s3_bucket.waf_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  count                   = local.logging_enabled && local.log_destination == "s3" ? 1 : 0
  bucket                  = aws_s3_bucket.waf_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_wafv2_web_acl_logging_configuration" "s3" {
  count                   = local.logging_enabled && local.log_destination == "s3" ? 1 : 0
  log_destination_configs = [aws_s3_bucket.waf_logs[0].arn]
  resource_arn            = aws_wafv2_web_acl.main.arn
}

################################################################################
# Resource Association
################################################################################

resource "aws_wafv2_web_acl_association" "main" {
  for_each     = toset(local.associate_resource_arns)
  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

################################################################################
# Outputs
################################################################################

output "web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "web_acl_arn" {
  description = "ARN of the WAF Web ACL (use this for resource associations)"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_name" {
  description = "Name of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.name
}

output "web_acl_capacity" {
  description = "WCU capacity used by this Web ACL"
  value       = aws_wafv2_web_acl.main.capacity
}

output "ip_allowlist_arn" {
  description = "ARN of the IP allowlist set (if enabled)"
  value       = local.ip_allowlist_enabled ? aws_wafv2_ip_set.allowlist[0].arn : null
}

output "ip_denylist_arn" {
  description = "ARN of the IP denylist set (if enabled)"
  value       = local.ip_denylist_enabled ? aws_wafv2_ip_set.denylist[0].arn : null
}

output "log_group_name" {
  description = "CloudWatch Log Group name (if CloudWatch logging enabled)"
  value       = local.logging_enabled && local.log_destination == "cloudwatch" ? aws_cloudwatch_log_group.waf[0].name : null
}

output "log_bucket_name" {
  description = "S3 bucket name (if S3 logging enabled)"
  value       = local.logging_enabled && local.log_destination == "s3" ? aws_s3_bucket.waf_logs[0].id : null
}
