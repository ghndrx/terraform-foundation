################################################################################
# Account Baseline - Input Variables
################################################################################

variable "name" {
  type        = string
  description = "Name prefix for resources"
}

# EBS Encryption
variable "enable_ebs_encryption" {
  type        = bool
  default     = true
  description = "Enable EBS encryption by default"
}

variable "ebs_kms_key_arn" {
  type        = string
  default     = null
  description = "KMS key ARN for EBS encryption (null = AWS managed)"
}

# S3 Public Access
variable "enable_s3_block_public" {
  type        = bool
  default     = true
  description = "Block public access to S3 at account level"
}

# Password Policy
variable "enable_password_policy" {
  type        = bool
  default     = true
  description = "Configure IAM password policy"
}

variable "password_policy" {
  type = object({
    minimum_length          = optional(number, 14)
    require_lowercase       = optional(bool, true)
    require_uppercase       = optional(bool, true)
    require_numbers         = optional(bool, true)
    require_symbols         = optional(bool, true)
    allow_users_to_change   = optional(bool, true)
    max_age_days            = optional(number, 90)
    reuse_prevention_count  = optional(number, 24)
    hard_expiry             = optional(bool, false)
  })
  default     = {}
  description = "IAM password policy settings"
}

# Access Analyzer
variable "enable_access_analyzer" {
  type        = bool
  default     = true
  description = "Enable IAM Access Analyzer"
}

variable "access_analyzer_type" {
  type        = string
  default     = "ACCOUNT"
  description = "Access Analyzer type (ACCOUNT or ORGANIZATION)"
}

# Security Hub
variable "enable_securityhub" {
  type        = bool
  default     = false
  description = "Enable Security Hub (set false if using delegated admin)"
}

variable "securityhub_enable_default_standards" {
  type        = bool
  default     = false
  description = "Enable default Security Hub standards"
}

variable "securityhub_auto_enable_controls" {
  type        = bool
  default     = true
  description = "Auto-enable new controls"
}

variable "securityhub_standards" {
  type        = list(string)
  default     = []
  description = "Security Hub standard ARNs to enable"
}

# GuardDuty
variable "enable_guardduty" {
  type        = bool
  default     = false
  description = "Enable GuardDuty (set false if using delegated admin)"
}

variable "guardduty_finding_frequency" {
  type        = string
  default     = "FIFTEEN_MINUTES"
  description = "GuardDuty finding publishing frequency"
}

variable "guardduty_kubernetes_audit" {
  type        = bool
  default     = true
  description = "Enable GuardDuty Kubernetes audit logs"
}

variable "guardduty_malware_protection" {
  type        = bool
  default     = true
  description = "Enable GuardDuty malware protection"
}

# AWS Config
variable "enable_config" {
  type        = bool
  default     = false
  description = "Enable AWS Config (set false if using org aggregator)"
}

variable "config_s3_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket for Config recordings"
}

variable "config_s3_prefix" {
  type        = string
  default     = "config"
  description = "S3 key prefix for Config recordings"
}

variable "config_sns_topic_arn" {
  type        = string
  default     = null
  description = "SNS topic for Config notifications"
}

variable "config_snapshot_frequency" {
  type        = string
  default     = "TwentyFour_Hours"
  description = "Config snapshot delivery frequency"
}

variable "config_include_global_resources" {
  type        = bool
  default     = true
  description = "Include global resources in Config"
}

# IAM Roles
variable "create_admin_role" {
  type        = bool
  default     = false
  description = "Create admin IAM role"
}

variable "create_readonly_role" {
  type        = bool
  default     = false
  description = "Create readonly IAM role"
}

variable "iam_role_path" {
  type        = string
  default     = "/"
  description = "IAM role path"
}

variable "trusted_admin_principals" {
  type        = list(string)
  default     = []
  description = "ARNs allowed to assume admin role"
}

variable "trusted_readonly_principals" {
  type        = list(string)
  default     = []
  description = "ARNs allowed to assume readonly role"
}

variable "require_mfa" {
  type        = bool
  default     = true
  description = "Require MFA for admin role assumption"
}

variable "admin_session_duration" {
  type        = number
  default     = 3600
  description = "Admin role session duration in seconds"
}

variable "readonly_session_duration" {
  type        = number
  default     = 3600
  description = "Readonly role session duration in seconds"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to resources"
}
