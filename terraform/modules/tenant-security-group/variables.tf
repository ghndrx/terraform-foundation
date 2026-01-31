variable "tenant" {
  description = "Tenant identifier"
  type        = string
}

variable "environment" {
  description = "Environment (prod, staging, dev)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for the security groups"
  type        = string
}

variable "create_web_sg" {
  description = "Create web tier security group"
  type        = bool
  default     = true
}

variable "create_app_sg" {
  description = "Create app tier security group"
  type        = bool
  default     = true
}

variable "create_db_sg" {
  description = "Create database tier security group"
  type        = bool
  default     = true
}

variable "app_port" {
  description = "Application port"
  type        = number
  default     = 8080
}

variable "db_port" {
  description = "Database port"
  type        = number
  default     = 5432
}
