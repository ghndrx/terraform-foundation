################################################################################
# Tenant Baseline - Input Variables
################################################################################

# Core tenant info
variable "tenant_name" {
  type        = string
  description = "Tenant name (human readable)"
}

variable "tenant_id" {
  type        = string
  description = "Short tenant ID for resource naming"
}

variable "environment" {
  type        = string
  description = "Environment (dev, staging, prod)"
}

variable "cost_center" {
  type        = string
  description = "Cost center for billing"
}

variable "owner_email" {
  type        = string
  description = "Tenant owner email for notifications"
}

# IAM Configuration
variable "create_permissions_boundary" {
  type        = bool
  default     = true
  description = "Create permissions boundary"
}

variable "create_admin_role" {
  type        = bool
  default     = true
  description = "Create tenant admin role"
}

variable "create_developer_role" {
  type        = bool
  default     = true
  description = "Create tenant developer role"
}

variable "create_readonly_role" {
  type        = bool
  default     = true
  description = "Create tenant readonly role"
}

variable "trusted_principals" {
  type        = list(string)
  default     = []
  description = "ARNs allowed to assume tenant roles"
}

variable "allowed_services" {
  type        = list(string)
  default     = ["ec2", "s3", "lambda", "dynamodb", "rds", "ecs", "ecr"]
  description = "AWS services the tenant can use"
}

variable "require_mfa" {
  type        = bool
  default     = true
  description = "Require MFA for admin role"
}

# Budget Configuration
variable "budget_limit" {
  type        = number
  default     = 100
  description = "Monthly budget limit in USD"
}

variable "budget_alert_thresholds" {
  type        = list(number)
  default     = [50, 80, 100]
  description = "Budget alert thresholds"
}

variable "enable_forecasted_alerts" {
  type        = bool
  default     = true
  description = "Enable forecasted spend alerts"
}

variable "budget_notification_emails" {
  type        = list(string)
  default     = []
  description = "Email addresses for budget alerts"
}

# VPC Configuration
variable "create_vpc" {
  type        = bool
  default     = false
  description = "Create dedicated tenant VPC"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "VPC CIDR block"
}

variable "vpc_azs" {
  type        = list(string)
  default     = []
  description = "Availability zones"
}

variable "vpc_public_subnets" {
  type        = list(string)
  default     = []
  description = "Public subnet CIDRs"
}

variable "vpc_private_subnets" {
  type        = list(string)
  default     = []
  description = "Private subnet CIDRs"
}

variable "vpc_enable_nat" {
  type        = bool
  default     = true
  description = "Enable NAT for VPC"
}

variable "vpc_nat_mode" {
  type        = string
  default     = "instance"
  description = "NAT mode: gateway or instance"
}

variable "transit_gateway_id" {
  type        = string
  default     = ""
  description = "Transit Gateway ID for attachment"
}

variable "enable_flow_logs" {
  type        = bool
  default     = true
  description = "Enable VPC flow logs"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags"
}
