################################################################################
# Identity Center - Input Variables
################################################################################

variable "create_default_permission_sets" {
  type        = bool
  default     = true
  description = "Create default permission sets (Admin, PowerUser, ReadOnly, Billing)"
}

variable "permission_sets" {
  type = map(object({
    description      = string
    session_duration = optional(string, "PT4H")
    managed_policies = optional(list(string), [])
    inline_policy    = optional(string, "")
  }))
  default     = {}
  description = "Custom permission sets to create"
}

variable "account_assignments" {
  type = list(object({
    group_name     = string
    permission_set = string
    account_id     = string
  }))
  default     = []
  description = "Group to account/permission assignments"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to resources"
}
