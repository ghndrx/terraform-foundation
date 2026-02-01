################################################################################
# SCPs - Input Variables
################################################################################

variable "name_prefix" {
  type        = string
  default     = "scp"
  description = "Prefix for SCP names"
}

variable "enable_deny_leave_org" {
  type        = bool
  default     = true
  description = "Prevent accounts from leaving organization"
}

variable "enable_require_imdsv2" {
  type        = bool
  default     = true
  description = "Require IMDSv2 for EC2 instances"
}

variable "enable_deny_root_actions" {
  type        = bool
  default     = true
  description = "Deny most actions by root user"
}

variable "allowed_regions" {
  type        = list(string)
  default     = []
  description = "Allowed regions (empty = all regions allowed)"
}

variable "protect_security_services" {
  type        = bool
  default     = true
  description = "Prevent disabling GuardDuty, Security Hub, Config, Access Analyzer"
}

variable "protect_cloudtrail" {
  type        = bool
  default     = true
  description = "Prevent CloudTrail modification"
}

variable "require_s3_encryption" {
  type        = bool
  default     = true
  description = "Require S3 bucket encryption"
}

variable "require_ebs_encryption" {
  type        = bool
  default     = true
  description = "Require EBS volume encryption"
}

variable "target_ous" {
  type        = list(string)
  default     = []
  description = "OU IDs to attach SCPs to"
}

variable "target_accounts" {
  type        = list(string)
  default     = []
  description = "Account IDs to attach SCPs to"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to SCP resources"
}
