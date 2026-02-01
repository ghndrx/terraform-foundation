################################################################################
# Security Groups - Input Variables
################################################################################

variable "vpc_id" {
  type        = string
  description = "VPC ID to create security groups in"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for security group names"
}

variable "create_web_tier" {
  type        = bool
  default     = false
  description = "Create web tier security group"
}

variable "create_app_tier" {
  type        = bool
  default     = false
  description = "Create application tier security group"
}

variable "create_db_tier" {
  type        = bool
  default     = false
  description = "Create database tier security group"
}

variable "create_bastion" {
  type        = bool
  default     = false
  description = "Create bastion host security group"
}

variable "create_endpoints" {
  type        = bool
  default     = false
  description = "Create VPC endpoints security group"
}

variable "create_eks" {
  type        = bool
  default     = false
  description = "Create EKS cluster and node security groups"
}

variable "web_ingress_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR for web tier ingress (use ALB SG for production)"
}

variable "app_port" {
  type        = number
  default     = 8080
  description = "Application port for app tier"
}

variable "db_port" {
  type        = number
  default     = 5432
  description = "Database port (5432=PostgreSQL, 3306=MySQL)"
}

variable "allowed_ssh_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDRs allowed SSH access to bastion"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to security groups"
}
