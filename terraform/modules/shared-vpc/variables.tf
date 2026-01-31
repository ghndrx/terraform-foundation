variable "vpc_cidr" {
  description = "CIDR block for the shared VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "tenant_subnet_cidr" {
  description = "CIDR block for tenant-specific subnets (if enabled)"
  type        = string
  default     = "10.1.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet internet access"
  type        = bool
  default     = true
}

variable "tenants" {
  description = "List of tenant names (for per-tenant subnets)"
  type        = list(string)
  default     = []
}

variable "create_tenant_subnets" {
  description = "Create separate subnets per tenant (stricter isolation)"
  type        = bool
  default     = false
}

variable "workloads_ou_arn" {
  description = "ARN of the Workloads OU to share subnets with"
  type        = string
}
