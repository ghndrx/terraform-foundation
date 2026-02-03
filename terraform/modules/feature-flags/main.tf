################################################################################
# Feature Flags Module
#
# Centralized feature toggles for organization-wide security controls.
# Define once, propagate everywhere. All features are OPT-IN by default.
#
# Usage:
#   module "feature_flags" {
#     source = "../modules/feature-flags"
#     
#     security = {
#       guardduty_enabled    = true
#       securityhub_enabled  = true
#       config_enabled       = true
#       cloudtrail_enabled   = true
#     }
#     
#     compliance = {
#       cis_benchmark_enabled = true
#       pci_dss_enabled       = false
#       hipaa_enabled         = false
#     }
#   }
#
# Then reference in other modules:
#   enable_guardduty = module.feature_flags.security.guardduty_enabled
#
################################################################################

terraform {
  required_version = ">= 1.5.0"
}

################################################################################
# Security Feature Flags
################################################################################

variable "security" {
  type = object({
    # Threat Detection
    guardduty_enabled              = optional(bool, false)
    guardduty_s3_protection        = optional(bool, true)
    guardduty_eks_protection       = optional(bool, true)
    guardduty_malware_protection   = optional(bool, true)
    guardduty_rds_protection       = optional(bool, false)
    guardduty_lambda_protection    = optional(bool, false)
    guardduty_runtime_monitoring   = optional(bool, false)

    # Security Posture
    securityhub_enabled            = optional(bool, false)
    securityhub_auto_enable        = optional(bool, true)

    # Configuration Compliance
    config_enabled                 = optional(bool, false)
    config_all_resources           = optional(bool, true)
    config_include_global          = optional(bool, true)

    # Audit Logging
    cloudtrail_enabled             = optional(bool, false)
    cloudtrail_multi_region        = optional(bool, true)
    cloudtrail_log_validation      = optional(bool, true)
    cloudtrail_insights            = optional(bool, false)
    cloudtrail_data_events         = optional(bool, false)

    # Identity
    access_analyzer_enabled        = optional(bool, false)
    access_analyzer_type           = optional(string, "ACCOUNT")
    macie_enabled                  = optional(bool, false)
    inspector_enabled              = optional(bool, false)

    # Network Security
    vpc_flow_logs_enabled          = optional(bool, false)
    network_firewall_enabled       = optional(bool, false)

    # Data Protection
    ebs_encryption_default         = optional(bool, true)
    s3_block_public_access         = optional(bool, true)
    rds_encryption_default         = optional(bool, true)
  })
  default     = {}
  description = "Security service feature flags"
}

################################################################################
# Compliance Feature Flags
################################################################################

variable "compliance" {
  type = object({
    # Standards
    cis_benchmark_enabled          = optional(bool, false)
    cis_benchmark_version          = optional(string, "1.4.0")
    aws_foundational_enabled       = optional(bool, true)
    pci_dss_enabled                = optional(bool, false)
    hipaa_enabled                  = optional(bool, false)
    nist_800_53_enabled            = optional(bool, false)
    soc2_enabled                   = optional(bool, false)

    # Config Rules
    config_rules_enabled           = optional(bool, false)
    config_auto_remediation        = optional(bool, false)

    # Custom Rules
    custom_config_rules            = optional(list(string), [])
  })
  default     = {}
  description = "Compliance framework feature flags"
}

################################################################################
# IAM Feature Flags
################################################################################

variable "iam" {
  type = object({
    # Password Policy
    password_policy_enabled        = optional(bool, true)
    password_minimum_length        = optional(number, 14)
    password_require_symbols       = optional(bool, true)
    password_require_numbers       = optional(bool, true)
    password_require_uppercase     = optional(bool, true)
    password_require_lowercase     = optional(bool, true)
    password_max_age_days          = optional(number, 90)
    password_reuse_prevention      = optional(number, 24)
    password_hard_expiry           = optional(bool, false)

    # MFA
    mfa_enforcement_enabled        = optional(bool, false)
    mfa_hardware_required          = optional(bool, false)
    mfa_grace_period_days          = optional(number, 0)

    # Roles
    create_admin_role              = optional(bool, true)
    create_developer_role          = optional(bool, true)
    create_readonly_role           = optional(bool, true)
    create_permissions_boundary    = optional(bool, true)

    # Service Control
    require_imdsv2                 = optional(bool, true)
  })
  default     = {}
  description = "IAM feature flags"
}

################################################################################
# Alerting Feature Flags
################################################################################

variable "alerting" {
  type = object({
    # Event Sources
    guardduty_alerts_enabled       = optional(bool, true)
    securityhub_alerts_enabled     = optional(bool, true)
    config_alerts_enabled          = optional(bool, true)
    health_alerts_enabled          = optional(bool, true)
    cloudtrail_alerts_enabled      = optional(bool, false)

    # Severity Routing
    critical_to_pagerduty          = optional(bool, false)
    high_to_slack                  = optional(bool, true)
    medium_to_email                = optional(bool, true)
    low_to_cloudwatch              = optional(bool, true)

    # Thresholds
    guardduty_min_severity         = optional(number, 4.0)
    securityhub_min_severity       = optional(number, 70)
  })
  default     = {}
  description = "Alerting feature flags"
}

################################################################################
# Cost Management Feature Flags
################################################################################

variable "cost" {
  type = object({
    # Budgets
    budgets_enabled                = optional(bool, true)
    budget_forecasted_alerts       = optional(bool, true)
    budget_default_limit           = optional(number, 1000)
    budget_alert_thresholds        = optional(list(number), [50, 80, 100])

    # Cost Allocation
    cost_allocation_tags_enabled   = optional(bool, true)
    cost_explorer_enabled          = optional(bool, true)
  })
  default     = {}
  description = "Cost management feature flags"
}

################################################################################
# Networking Feature Flags
################################################################################

variable "networking" {
  type = object({
    # VPC
    create_vpc                     = optional(bool, true)
    vpc_endpoints_enabled          = optional(bool, true)
    nat_gateway_enabled            = optional(bool, true)
    nat_gateway_ha                 = optional(bool, false)

    # DNS
    route53_enabled                = optional(bool, false)
    private_dns_enabled            = optional(bool, true)

    # Transit
    transit_gateway_enabled        = optional(bool, false)
    ram_sharing_enabled            = optional(bool, false)
  })
  default     = {}
  description = "Networking feature flags"
}

################################################################################
# Backup Feature Flags
################################################################################

variable "backup" {
  type = object({
    # AWS Backup
    backup_enabled                 = optional(bool, false)
    backup_vault_encryption        = optional(bool, true)
    backup_cross_region            = optional(bool, false)
    backup_cross_account           = optional(bool, false)

    # Default Schedules
    daily_backup_enabled           = optional(bool, true)
    weekly_backup_enabled          = optional(bool, true)
    monthly_backup_enabled         = optional(bool, false)

    # Retention
    daily_retention_days           = optional(number, 7)
    weekly_retention_days          = optional(number, 30)
    monthly_retention_days         = optional(number, 365)
  })
  default     = {}
  description = "Backup feature flags"
}

################################################################################
# Environment Presets
################################################################################

variable "environment_preset" {
  type        = string
  default     = "custom"
  description = "Environment preset (production, staging, development, custom)"

  validation {
    condition     = contains(["production", "staging", "development", "custom"], var.environment_preset)
    error_message = "Must be production, staging, development, or custom"
  }
}

locals {
  # Production preset - maximum security
  production_overrides = {
    security = {
      guardduty_enabled           = true
      securityhub_enabled         = true
      config_enabled              = true
      cloudtrail_enabled          = true
      access_analyzer_enabled     = true
      ebs_encryption_default      = true
      s3_block_public_access      = true
    }
    compliance = {
      cis_benchmark_enabled       = true
      aws_foundational_enabled    = true
      config_rules_enabled        = true
    }
    iam = {
      password_policy_enabled     = true
      mfa_enforcement_enabled     = true
      create_permissions_boundary = true
    }
    alerting = {
      guardduty_alerts_enabled    = true
      securityhub_alerts_enabled  = true
      health_alerts_enabled       = true
    }
  }

  # Staging preset - security with cost awareness
  staging_overrides = {
    security = {
      guardduty_enabled           = true
      securityhub_enabled         = true
      config_enabled              = true
      cloudtrail_enabled          = true
      access_analyzer_enabled     = false
      ebs_encryption_default      = true
      s3_block_public_access      = true
    }
    compliance = {
      cis_benchmark_enabled       = false
      aws_foundational_enabled    = true
      config_rules_enabled        = true
    }
    iam = {
      password_policy_enabled     = true
      mfa_enforcement_enabled     = false
      create_permissions_boundary = true
    }
    alerting = {
      guardduty_alerts_enabled    = true
      securityhub_alerts_enabled  = false
      health_alerts_enabled       = true
    }
  }

  # Development preset - minimal security, maximum flexibility
  development_overrides = {
    security = {
      guardduty_enabled           = false
      securityhub_enabled         = false
      config_enabled              = false
      cloudtrail_enabled          = false
      access_analyzer_enabled     = false
      ebs_encryption_default      = true
      s3_block_public_access      = false
    }
    compliance = {
      cis_benchmark_enabled       = false
      aws_foundational_enabled    = false
      config_rules_enabled        = false
    }
    iam = {
      password_policy_enabled     = true
      mfa_enforcement_enabled     = false
      create_permissions_boundary = false
    }
    alerting = {
      guardduty_alerts_enabled    = false
      securityhub_alerts_enabled  = false
      health_alerts_enabled       = true
    }
  }

  # Select preset or use custom
  preset_map = {
    production  = local.production_overrides
    staging     = local.staging_overrides
    development = local.development_overrides
    custom      = {}
  }

  selected_preset = local.preset_map[var.environment_preset]
}

################################################################################
# Merged Outputs
#
# Merge user input with preset defaults. User input always wins.
################################################################################

output "security" {
  value = merge(
    var.security,
    try(local.selected_preset.security, {})
  )
  description = "Merged security feature flags"
}

output "compliance" {
  value = merge(
    var.compliance,
    try(local.selected_preset.compliance, {})
  )
  description = "Merged compliance feature flags"
}

output "iam" {
  value = merge(
    var.iam,
    try(local.selected_preset.iam, {})
  )
  description = "Merged IAM feature flags"
}

output "alerting" {
  value = merge(
    var.alerting,
    try(local.selected_preset.alerting, {})
  )
  description = "Merged alerting feature flags"
}

output "cost" {
  value = var.cost
  description = "Cost management feature flags"
}

output "networking" {
  value = var.networking
  description = "Networking feature flags"
}

output "backup" {
  value = var.backup
  description = "Backup feature flags"
}

output "environment_preset" {
  value       = var.environment_preset
  description = "Active environment preset"
}

# Convenience outputs for common checks
output "is_production" {
  value       = var.environment_preset == "production"
  description = "True if production preset is active"
}

output "encryption_required" {
  value       = var.security.ebs_encryption_default && var.security.s3_block_public_access
  description = "True if encryption defaults are enabled"
}

output "compliance_strict" {
  value       = var.compliance.cis_benchmark_enabled || var.compliance.pci_dss_enabled || var.compliance.hipaa_enabled
  description = "True if any strict compliance standard is enabled"
}
