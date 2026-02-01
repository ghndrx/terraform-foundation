################################################################################
# Tenant Budget - Input Variables
################################################################################

variable "name" {
  type        = string
  description = "Tenant/budget name"
}

variable "budget_limit" {
  type        = number
  description = "Monthly budget limit in USD"
}

variable "alert_thresholds" {
  type        = list(number)
  default     = [50, 80, 100]
  description = "Percentage thresholds for actual spend alerts"
}

variable "enable_forecasted_alerts" {
  type        = bool
  default     = true
  description = "Enable forecasted spend alerts"
}

variable "forecasted_thresholds" {
  type        = list(number)
  default     = [100]
  description = "Percentage thresholds for forecasted spend alerts"
}

variable "notification_emails" {
  type        = list(string)
  default     = []
  description = "Email addresses for budget alerts"
}

variable "create_sns_topic" {
  type        = bool
  default     = true
  description = "Create SNS topic for alerts"
}

variable "sns_topic_arn" {
  type        = string
  default     = null
  description = "Existing SNS topic ARN (if not creating)"
}

variable "cost_filter_tags" {
  type        = map(string)
  default     = {}
  description = "Cost allocation tags to filter by"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to resources"
}
