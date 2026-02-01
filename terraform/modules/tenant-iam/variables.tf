################################################################################
# Tenant IAM - Input Variables
################################################################################

variable "tenant_name" {
  type        = string
  description = "Tenant name (human readable)"
}

variable "tenant_id" {
  type        = string
  description = "Short tenant ID for resource naming"
}

variable "create_permissions_boundary" {
  type        = bool
  default     = true
  description = "Create permissions boundary policy"
}

variable "permissions_boundary_arn" {
  type        = string
  default     = null
  description = "Existing permissions boundary ARN (if not creating)"
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
  default     = ["ec2", "s3", "lambda", "dynamodb", "rds", "ecs", "ecr", "logs", "cloudwatch", "events", "sqs", "sns"]
  description = "AWS services the tenant can use"
}

variable "resource_prefix" {
  type        = string
  default     = ""
  description = "Resource naming prefix (defaults to tenant_id-)"
}

variable "iam_path" {
  type        = string
  default     = "/tenants/"
  description = "IAM path for roles and policies"
}

variable "require_mfa" {
  type        = bool
  default     = true
  description = "Require MFA for admin role"
}

variable "admin_session_duration" {
  type        = number
  default     = 3600
  description = "Admin role session duration in seconds"
}

variable "developer_session_duration" {
  type        = number
  default     = 14400
  description = "Developer role session duration in seconds"
}

variable "readonly_session_duration" {
  type        = number
  default     = 14400
  description = "Readonly role session duration in seconds"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to resources"
}
