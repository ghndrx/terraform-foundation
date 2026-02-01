variable "tenant" {
  description = "Tenant identifier (lowercase, no spaces)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.tenant))
    error_message = "Tenant must be lowercase alphanumeric with hyphens only."
  }
}

variable "email_domain" {
  description = "Domain for AWS account emails"
  type        = string
}

variable "email_prefix" {
  description = "Email prefix before + sign"
  type        = string
  default     = "aws"
}

variable "production_ou_id" {
  description = "ID of the Production OU"
  type        = string
}

variable "nonproduction_ou_id" {
  description = "ID of the Non-Production OU"
  type        = string
}

variable "environments" {
  description = "Environments to create for each app"
  type        = list(string)
  default     = ["prod", "staging", "dev"]
}

variable "apps" {
  description = "Map of applications for this tenant"
  type = map(object({
    monthly_budget = number
    owner_email    = string
  }))
}

variable "monthly_budget" {
  description = "Total monthly budget for tenant"
  type        = number
  default     = 1000
}

variable "alert_emails" {
  description = "Emails to receive budget alerts"
  type        = list(string)
}

variable "permission_set_admin_arn" {
  description = "ARN of the TenantAdmin permission set"
  type        = string
}

variable "permission_set_developer_arn" {
  description = "ARN of the TenantDeveloper permission set"
  type        = string
}

variable "permission_set_readonly_arn" {
  description = "ARN of the TenantReadOnly permission set"
  type        = string
}
