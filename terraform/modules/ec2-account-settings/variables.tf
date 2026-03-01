################################################################################
# EC2 Account Settings - Variables
################################################################################

#------------------------------------------------------------------------------
# Serial Console
#------------------------------------------------------------------------------

variable "manage_serial_console" {
  description = "Whether to manage EC2 serial console access setting"
  type        = bool
  default     = true
}

variable "serial_console_enabled" {
  description = "Enable EC2 serial console access. Disable for security hardening."
  type        = bool
  default     = false
}

#------------------------------------------------------------------------------
# Instance Metadata Service (IMDS) Defaults
#------------------------------------------------------------------------------

variable "manage_imds_defaults" {
  description = "Whether to manage IMDS default settings for new instances"
  type        = bool
  default     = true
}

variable "imds_http_tokens" {
  description = "IMDS token requirement: 'optional' (v1+v2) or 'required' (v2 only)"
  type        = string
  default     = "required"

  validation {
    condition     = contains(["optional", "required"], var.imds_http_tokens)
    error_message = "Must be 'optional' or 'required'."
  }
}

variable "imds_http_endpoint" {
  description = "IMDS endpoint state: 'enabled' or 'disabled'"
  type        = string
  default     = "enabled"

  validation {
    condition     = contains(["enabled", "disabled"], var.imds_http_endpoint)
    error_message = "Must be 'enabled' or 'disabled'."
  }
}

variable "imds_hop_limit" {
  description = "HTTP PUT response hop limit for IMDS tokens (1-64). Use 1 for instance-only access, 2+ for containers."
  type        = number
  default     = 2

  validation {
    condition     = var.imds_hop_limit >= 1 && var.imds_hop_limit <= 64
    error_message = "Must be between 1 and 64."
  }
}

variable "imds_instance_metadata_tags" {
  description = "Allow instance tags in metadata: 'enabled' or 'disabled'"
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["enabled", "disabled"], var.imds_instance_metadata_tags)
    error_message = "Must be 'enabled' or 'disabled'."
  }
}

#------------------------------------------------------------------------------
# EBS Snapshot Public Access
#------------------------------------------------------------------------------

variable "manage_snapshot_public_access" {
  description = "Whether to manage EBS snapshot public access setting"
  type        = bool
  default     = true
}

variable "snapshot_block_public_access_state" {
  description = "EBS snapshot public access: 'block-all-sharing', 'block-new-sharing', or 'unblocked'"
  type        = string
  default     = "block-all-sharing"

  validation {
    condition     = contains(["block-all-sharing", "block-new-sharing", "unblocked"], var.snapshot_block_public_access_state)
    error_message = "Must be 'block-all-sharing', 'block-new-sharing', or 'unblocked'."
  }
}

#------------------------------------------------------------------------------
# AMI Public Access
#------------------------------------------------------------------------------

variable "manage_ami_public_access" {
  description = "Whether to manage AMI public access setting"
  type        = bool
  default     = true
}

variable "ami_block_public_access_state" {
  description = "AMI public access: 'block-new-sharing' or 'unblocked'"
  type        = string
  default     = "block-new-sharing"

  validation {
    condition     = contains(["block-new-sharing", "unblocked"], var.ami_block_public_access_state)
    error_message = "Must be 'block-new-sharing' or 'unblocked'."
  }
}
