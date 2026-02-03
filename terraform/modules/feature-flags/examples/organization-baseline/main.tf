################################################################################
# Example: Organization Baseline with Feature Flags
#
# Demonstrates wiring feature flags into security and compliance modules.
# Copy and adapt for your organization's needs.
################################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

################################################################################
# Feature Flags - Single Source of Truth
################################################################################

module "feature_flags" {
  source = "../../"

  # Use production preset with customizations
  environment_preset = "production"

  # Override: Also enable PCI compliance
  compliance = {
    pci_dss_enabled = true
  }

  # Override: Configure alerting thresholds
  alerting = {
    guardduty_min_severity  = 7.0  # Only alert on HIGH+ findings
    critical_to_pagerduty   = true # Page for critical issues
  }
}

################################################################################
# Security Baseline - Consumes Feature Flags
################################################################################

resource "aws_s3_bucket" "config" {
  bucket_prefix = "org-config-"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

module "security_baseline" {
  source = "../../../security-baseline"

  name = "org-security"

  # Wire feature flags
  enable_guardduty       = module.feature_flags.security.guardduty_enabled
  enable_securityhub     = module.feature_flags.security.securityhub_enabled
  enable_config          = module.feature_flags.security.config_enabled
  enable_access_analyzer = module.feature_flags.security.access_analyzer_enabled

  config_bucket_name = aws_s3_bucket.config.id

  # Security Hub standards based on compliance flags
  securityhub_standards = concat(
    module.feature_flags.compliance.aws_foundational_enabled ? ["aws-foundational-security-best-practices/v/1.0.0"] : [],
    module.feature_flags.compliance.cis_benchmark_enabled ? ["cis-aws-foundations-benchmark/v/1.4.0"] : [],
    module.feature_flags.compliance.pci_dss_enabled ? ["pci-dss/v/3.2.1"] : []
  )

  tags = {
    Environment = module.feature_flags.environment_preset
    ManagedBy   = "terraform"
  }
}

################################################################################
# Alerting - Consumes Feature Flags
################################################################################

module "alerting" {
  source = "../../../alerting"

  name = "org-alerts"

  email_endpoints = ["security@example.com"]

  # Wire feature flags
  enable_guardduty_events   = module.feature_flags.alerting.guardduty_alerts_enabled
  enable_securityhub_events = module.feature_flags.alerting.securityhub_alerts_enabled
  enable_aws_health_events  = module.feature_flags.alerting.health_alerts_enabled

  tags = {
    Environment = module.feature_flags.environment_preset
  }
}

################################################################################
# IAM Account Settings - Consumes Feature Flags
################################################################################

module "iam_settings" {
  source = "../../../iam-account-settings"

  account_alias = "my-org-prod"

  enable_password_policy = module.feature_flags.iam.password_policy_enabled
  enforce_mfa            = module.feature_flags.iam.mfa_enforcement_enabled

  password_policy = {
    minimum_length                 = module.feature_flags.iam.password_minimum_length
    require_symbols                = module.feature_flags.iam.password_require_symbols
    require_numbers                = module.feature_flags.iam.password_require_numbers
    require_uppercase_characters   = module.feature_flags.iam.password_require_uppercase
    require_lowercase_characters   = module.feature_flags.iam.password_require_lowercase
    max_password_age               = module.feature_flags.iam.password_max_age_days
    password_reuse_prevention      = module.feature_flags.iam.password_reuse_prevention
  }

  tags = {
    Environment = module.feature_flags.environment_preset
  }
}

################################################################################
# CloudTrail - Consumes Feature Flags
################################################################################

module "cloudtrail" {
  source = "../../../cloudtrail"
  count  = module.feature_flags.security.cloudtrail_enabled ? 1 : 0

  name            = "org-trail"
  is_multi_region = module.feature_flags.security.cloudtrail_multi_region

  enable_log_file_validation = module.feature_flags.security.cloudtrail_log_validation
  enable_insights            = module.feature_flags.security.cloudtrail_insights
  enable_data_events         = module.feature_flags.security.cloudtrail_data_events

  tags = {
    Environment = module.feature_flags.environment_preset
  }
}

################################################################################
# Outputs
################################################################################

output "feature_flags" {
  value = {
    preset              = module.feature_flags.environment_preset
    is_production       = module.feature_flags.is_production
    encryption_required = module.feature_flags.encryption_required
    compliance_strict   = module.feature_flags.compliance_strict
  }
  description = "Active feature flags summary"
}

output "enabled_services" {
  value = module.security_baseline.enabled_services
}
