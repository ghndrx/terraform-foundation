################################################################################
# Tenant VPC - Input Variables
################################################################################

variable "tenant_name" {
  type        = string
  description = "Tenant name (used for resource naming)"
}

variable "cidr" {
  type        = string
  description = "VPC CIDR block"
}

variable "azs" {
  type        = list(string)
  default     = []
  description = "Availability zones (auto-detected if empty)"
}

variable "az_count" {
  type        = number
  default     = 2
  description = "Number of AZs if not specifying azs"
}

variable "public_subnets" {
  type        = list(string)
  default     = []
  description = "Public subnet CIDRs"
}

variable "private_subnets" {
  type        = list(string)
  description = "Private subnet CIDRs"
}

variable "enable_nat" {
  type        = bool
  default     = true
  description = "Enable NAT for private subnets"
}

variable "nat_mode" {
  type        = string
  default     = "instance"
  description = "NAT mode: gateway or instance"

  validation {
    condition     = contains(["gateway", "instance"], var.nat_mode)
    error_message = "Must be gateway or instance"
  }
}

variable "nat_instance_type" {
  type        = string
  default     = "t4g.nano"
  description = "NAT instance type (if using instance mode)"
}

variable "transit_gateway_id" {
  type        = string
  default     = ""
  description = "Transit Gateway ID for attachment"
}

variable "enable_flow_logs" {
  type        = bool
  default     = true
  description = "Enable VPC Flow Logs"
}

variable "flow_log_retention_days" {
  type        = number
  default     = 30
  description = "Flow log retention in days"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to resources"
}
