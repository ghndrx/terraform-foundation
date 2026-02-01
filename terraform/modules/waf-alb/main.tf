################################################################################
# WAF Module for ALB Protection
#
# Provides Web Application Firewall protection:
# - AWS Managed Rules (OWASP, Known Bad Inputs, etc.)
# - Rate limiting
# - Geo-blocking (optional)
# - IP allowlist/blocklist
# - Logging to S3/CloudWatch
#
# Attach to ALB: set waf_web_acl_arn in your workload
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
  description = "Name for the WAF Web ACL"
}

variable "description" {
  type    = string
  default = "WAF Web ACL for ALB protection"
}

# Rate limiting
variable "rate_limit" {
  type        = number
  default     = 2000
  description = "Requests per 5-minute period per IP"
}

variable "rate_limit_action" {
  type    = string
  default = "block"
  validation {
    condition     = contains(["block", "count"], var.rate_limit_action)
    error_message = "Must be 'block' or 'count'"
  }
}

# Geo restrictions
variable "blocked_countries" {
  type        = list(string)
  default     = []
  description = "ISO 3166-1 alpha-2 country codes to block"
}

variable "allowed_countries" {
  type        = list(string)
  default     = []
  description = "If set, ONLY these countries are allowed (overrides blocked)"
}

# IP lists
variable "ip_allowlist" {
  type        = list(string)
  default     = []
  description = "CIDR blocks to always allow"
}

variable "ip_blocklist" {
  type        = list(string)
  default     = []
  description = "CIDR blocks to always block"
}

# Managed rule settings
variable "enable_aws_managed_rules" {
  type    = bool
  default = true
}

variable "enable_known_bad_inputs" {
  type    = bool
  default = true
}

variable "enable_sql_injection" {
  type    = bool
  default = true
}

variable "enable_linux_protection" {
  type    = bool
  default = true
}

variable "enable_php_protection" {
  type    = bool
  default = false
}

variable "enable_wordpress_protection" {
  type    = bool
  default = false
}

variable "enable_bot_control" {
  type        = bool
  default     = false
  description = "Bot Control (additional cost ~$10/mo + $1/million requests)"
}

# Logging
variable "enable_logging" {
  type    = bool
  default = true
}

variable "log_destination_arn" {
  type        = string
  default     = ""
  description = "S3 bucket ARN, CloudWatch Log Group ARN, or Kinesis Firehose ARN"
}

variable "tags" {
  type    = map(string)
  default = {}
}

################################################################################
# IP Sets
################################################################################

resource "aws_wafv2_ip_set" "allowlist" {
  count              = length(var.ip_allowlist) > 0 ? 1 : 0
  name               = "${var.name}-allowlist"
  description        = "Allowed IP addresses"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.ip_allowlist

  tags = merge(var.tags, { Name = "${var.name}-allowlist" })
}

resource "aws_wafv2_ip_set" "blocklist" {
  count              = length(var.ip_blocklist) > 0 ? 1 : 0
  name               = "${var.name}-blocklist"
  description        = "Blocked IP addresses"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.ip_blocklist

  tags = merge(var.tags, { Name = "${var.name}-blocklist" })
}

################################################################################
# Web ACL
################################################################################

resource "aws_wafv2_web_acl" "main" {
  name        = var.name
  description = var.description
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: IP Allowlist (highest priority - allow first)
  dynamic "rule" {
    for_each = length(var.ip_allowlist) > 0 ? [1] : []
    content {
      name     = "AllowlistedIPs"
      priority = 0

      override_action {
        none {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowlist[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-allowlist"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 2: IP Blocklist
  dynamic "rule" {
    for_each = length(var.ip_blocklist) > 0 ? [1] : []
    content {
      name     = "BlocklistedIPs"
      priority = 1

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocklist[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-blocklist"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 3: Geo blocking
  dynamic "rule" {
    for_each = length(var.blocked_countries) > 0 ? [1] : []
    content {
      name     = "GeoBlock"
      priority = 2

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-geoblock"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 4: Geo allow (only specific countries)
  dynamic "rule" {
    for_each = length(var.allowed_countries) > 0 ? [1] : []
    content {
      name     = "GeoAllow"
      priority = 3

      action {
        block {}
      }

      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = var.allowed_countries
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-geoallow"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 5: Rate limiting
  rule {
    name     = "RateLimit"
    priority = 10

    action {
      dynamic "block" {
        for_each = var.rate_limit_action == "block" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rate_limit_action == "count" ? [1] : []
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-ratelimit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: AWS Managed Rules - Common Rule Set
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules ? [1] : []
    content {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 20

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"

          # Exclude rules that may cause false positives
          rule_action_override {
            name = "SizeRestrictions_BODY"
            action_to_use {
              count {}
            }
          }

          rule_action_override {
            name = "GenericRFI_BODY"
            action_to_use {
              count {}
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-common"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 7: Known Bad Inputs
  dynamic "rule" {
    for_each = var.enable_known_bad_inputs ? [1] : []
    content {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 21

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesKnownBadInputsRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-badinputs"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 8: SQL Injection
  dynamic "rule" {
    for_each = var.enable_sql_injection ? [1] : []
    content {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 22

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesSQLiRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-sqli"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 9: Linux Protection
  dynamic "rule" {
    for_each = var.enable_linux_protection ? [1] : []
    content {
      name     = "AWSManagedRulesLinuxRuleSet"
      priority = 23

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesLinuxRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-linux"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 10: PHP Protection
  dynamic "rule" {
    for_each = var.enable_php_protection ? [1] : []
    content {
      name     = "AWSManagedRulesPHPRuleSet"
      priority = 24

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesPHPRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-php"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 11: WordPress Protection
  dynamic "rule" {
    for_each = var.enable_wordpress_protection ? [1] : []
    content {
      name     = "AWSManagedRulesWordPressRuleSet"
      priority = 25

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesWordPressRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-wordpress"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 12: Bot Control (costs extra)
  dynamic "rule" {
    for_each = var.enable_bot_control ? [1] : []
    content {
      name     = "AWSManagedRulesBotControlRuleSet"
      priority = 30

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesBotControlRuleSet"
          vendor_name = "AWS"

          managed_rule_group_configs {
            aws_managed_rules_bot_control_rule_set {
              inspection_level = "COMMON"
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-botcontrol"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, { Name = var.name })
}

################################################################################
# Logging
################################################################################

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = var.enable_logging && var.log_destination_arn != "" ? 1 : 0
  log_destination_configs = [var.log_destination_arn]
  resource_arn            = aws_wafv2_web_acl.main.arn

  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }

      condition {
        action_condition {
          action = "COUNT"
        }
      }
    }
  }
}

################################################################################
# Outputs
################################################################################

output "web_acl_arn" {
  value       = aws_wafv2_web_acl.main.arn
  description = "ARN of the WAF Web ACL - use this with ALB"
}

output "web_acl_id" {
  value = aws_wafv2_web_acl.main.id
}

output "web_acl_capacity" {
  value       = aws_wafv2_web_acl.main.capacity
  description = "WCU capacity used (max 1500 for regional)"
}
