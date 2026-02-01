################################################################################
# RAM Share - Input Variables
################################################################################

variable "name" {
  type        = string
  description = "Name of the resource share"
}

variable "resource_arns" {
  type        = list(string)
  description = "List of resource ARNs to share"
}

variable "share_with_organization" {
  type        = bool
  default     = false
  description = "Share with entire organization"
}

variable "principal_ous" {
  type        = list(string)
  default     = []
  description = "OU ARNs to share with"
}

variable "principal_accounts" {
  type        = list(string)
  default     = []
  description = "Account IDs to share with"
}

variable "allow_external_principals" {
  type        = bool
  default     = false
  description = "Allow sharing with external accounts"
}

variable "permission_arns" {
  type        = list(string)
  default     = null
  description = "Custom RAM permission ARNs"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to resources"
}
