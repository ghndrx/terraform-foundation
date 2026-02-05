################################################################################
# Variables
################################################################################

variable "name_prefix" {
  type        = string
  description = "Prefix for resource names (e.g., 'prod', 'dev', 'finops')"
}

variable "alert_emails" {
  type        = list(string)
  description = "Email addresses for SNS notifications"
  default     = []
}

variable "direct_email_subscribers" {
  type        = list(string)
  description = "Email addresses for direct Cost Explorer alerts (bypasses SNS)"
  default     = []
}

variable "monitor_type" {
  type        = string
  description = "Type of anomaly monitor: DIMENSIONAL or CUSTOM"
  default     = "DIMENSIONAL"

  validation {
    condition     = contains(["DIMENSIONAL", "CUSTOM"], var.monitor_type)
    error_message = "monitor_type must be DIMENSIONAL or CUSTOM."
  }
}

variable "monitor_dimension" {
  type        = string
  description = "Dimension for DIMENSIONAL monitors: SERVICE or LINKED_ACCOUNT"
  default     = "SERVICE"

  validation {
    condition     = contains(["SERVICE", "LINKED_ACCOUNT"], var.monitor_dimension)
    error_message = "monitor_dimension must be SERVICE or LINKED_ACCOUNT."
  }
}

variable "cost_category_name" {
  type        = string
  description = "Cost Category name for CUSTOM monitors"
  default     = null
}

variable "cost_category_values" {
  type        = list(string)
  description = "Cost Category values to filter for CUSTOM monitors"
  default     = []
}

variable "alert_frequency" {
  type        = string
  description = "Frequency of anomaly alerts: DAILY or IMMEDIATE"
  default     = "DAILY"

  validation {
    condition     = contains(["DAILY", "IMMEDIATE", "WEEKLY"], var.alert_frequency)
    error_message = "alert_frequency must be DAILY, IMMEDIATE, or WEEKLY."
  }
}

variable "threshold_percentage" {
  type        = number
  description = "Anomaly impact percentage threshold (e.g., 10 = 10%)"
  default     = 10

  validation {
    condition     = var.threshold_percentage > 0 && var.threshold_percentage <= 100
    error_message = "threshold_percentage must be between 1 and 100."
  }
}

variable "threshold_absolute" {
  type        = number
  description = "Anomaly impact absolute threshold in USD"
  default     = 100

  validation {
    condition     = var.threshold_absolute > 0
    error_message = "threshold_absolute must be greater than 0."
  }
}

variable "service_monitors" {
  type = map(object({
    threshold_percentage = number
    threshold_absolute   = number
  }))
  description = "Optional service-specific monitors with custom thresholds"
  default     = {}

  # Example:
  # service_monitors = {
  #   ec2 = { threshold_percentage = 15, threshold_absolute = 200 }
  #   rds = { threshold_percentage = 20, threshold_absolute = 100 }
  # }
}

variable "kms_key_id" {
  type        = string
  description = "KMS key ID/ARN for SNS topic encryption (optional)"
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to all resources"
  default     = {}
}
