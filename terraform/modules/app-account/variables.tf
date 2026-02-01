################################################################################
# App Account - Input Variables
################################################################################

# Account Identity
variable "account_name" {
  type        = string
  description = "Name for the new account"
}

variable "account_email" {
  type        = string
  default     = ""
  description = "Root email for the account (auto-generated if empty)"
}

variable "email_prefix" {
  type        = string
  default     = "aws"
  description = "Email prefix for auto-generated email"
}

variable "email_domain" {
  type        = string
  default     = "example.com"
  description = "Email domain for auto-generated email"
}

# Organization Placement
variable "organizational_unit" {
  type        = string
  default     = "Workloads"
  description = "OU name (for tagging)"
}

variable "organizational_unit_id" {
  type        = string
  description = "OU ID to place the account in"
}

# Account Metadata
variable "environment" {
  type        = string
  description = "Environment type (dev, staging, prod)"

  validation {
    condition     = contains(["dev", "staging", "prod", "sandbox"], var.environment)
    error_message = "Must be dev, staging, prod, or sandbox"
  }
}

variable "cost_center" {
  type        = string
  default     = ""
  description = "Cost center for billing"
}

variable "owner" {
  type        = string
  description = "Team/person responsible for this account"
}

variable "owner_email" {
  type        = string
  default     = ""
  description = "Owner email for notifications"
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Primary region for the account"
}

# IAM Configuration
variable "admin_role_name" {
  type        = string
  default     = "OrganizationAccountAccessRole"
  description = "Name of admin role created in new account"
}

variable "iam_user_access_to_billing" {
  type        = bool
  default     = false
  description = "Allow IAM users to access billing"
}

variable "create_cross_account_roles" {
  type        = bool
  default     = true
  description = "Create cross-account IAM roles"
}

variable "admin_trusted_principals" {
  type        = list(string)
  default     = []
  description = "ARNs allowed to assume admin role"
}

variable "readonly_trusted_principals" {
  type        = list(string)
  default     = []
  description = "ARNs allowed to assume readonly role"
}

# Baseline Configuration
variable "apply_baseline" {
  type        = bool
  default     = true
  description = "Apply account baseline configuration"
}

# Budget
variable "budget_limit" {
  type        = number
  default     = 100
  description = "Monthly budget limit in USD (0 = no budget)"
}

# Safety
variable "close_on_deletion" {
  type        = bool
  default     = false
  description = "Close account when Terraform resource is deleted"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags"
}
