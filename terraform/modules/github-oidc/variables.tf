################################################################################
# GitHub OIDC Module - Variables
# With AWS/Terraform/Security Best Practices Validation
################################################################################

variable "create_provider" {
  type        = bool
  default     = true
  description = "Create the OIDC provider. Set false if already exists in account."
}

variable "provider_arn" {
  type        = string
  default     = ""
  description = "Existing OIDC provider ARN (required if create_provider = false)"

  validation {
    condition     = var.provider_arn == "" || can(regex("^arn:aws:iam::[0-9]{12}:oidc-provider/", var.provider_arn))
    error_message = "Provider ARN must be a valid IAM OIDC provider ARN."
  }
}

variable "github_org" {
  type        = string
  default     = ""
  description = "GitHub organization. If set, prepended to repos that don't include org."

  validation {
    condition     = var.github_org == "" || can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]*$", var.github_org))
    error_message = "GitHub org must be alphanumeric with hyphens (no leading hyphen)."
  }
}

variable "name_prefix" {
  type        = string
  default     = "github"
  description = "Prefix for IAM role names"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-_]*$", var.name_prefix))
    error_message = "Name prefix must start with letter, contain only alphanumeric, hyphens, underscores."
  }
}

variable "path" {
  type        = string
  default     = "/github-actions/"
  description = "IAM path for roles (enables easier permission boundaries)"

  validation {
    condition     = can(regex("^/[a-zA-Z0-9/_-]*/$", var.path))
    error_message = "IAM path must start and end with /, contain only alphanumeric, /, -, _."
  }
}

variable "permissions_boundary" {
  type        = string
  default     = null
  description = "ARN of permissions boundary to attach to roles (RECOMMENDED for defense-in-depth)"

  validation {
    condition     = var.permissions_boundary == null || can(regex("^arn:aws:iam::[0-9]{12}:policy/", var.permissions_boundary))
    error_message = "Permissions boundary must be a valid IAM policy ARN."
  }
}

variable "require_permissions_boundary" {
  type        = bool
  default     = false
  description = "Require a permissions boundary to be set (security guardrail)"
}

variable "max_session_hours_limit" {
  type        = number
  default     = 4
  description = "Maximum allowed session duration in hours (caps role max_session_hours)"

  validation {
    condition     = var.max_session_hours_limit >= 1 && var.max_session_hours_limit <= 12
    error_message = "Max session hours must be between 1 and 12."
  }
}

variable "deny_wildcard_repos" {
  type        = bool
  default     = true
  description = "Deny roles that allow all repos (*). Set false only if using workflow_ref restriction."
}

variable "roles" {
  type = map(object({
    # Repository configuration
    repos        = list(string)                    # GitHub repos (owner/repo or just repo if github_org set)
    branches     = optional(list(string), [])      # Branch restrictions (empty = all branches)
    tags         = optional(list(string), [])      # Tag restrictions (e.g., ["v*", "release-*"])
    environments = optional(list(string), [])      # GitHub environment restrictions

    # Event type restrictions
    pull_request = optional(bool, false)           # Allow from pull_request events
    workflow_ref = optional(string, "")            # Restrict to specific reusable workflow

    # IAM configuration
    policy_arns       = optional(list(string), []) # Managed policy ARNs to attach
    inline_policy     = optional(string, "")       # Inline policy JSON
    policy_statements = optional(list(object({     # Policy statements to generate
      sid       = optional(string, "")
      effect    = optional(string, "Allow")
      actions   = list(string)
      resources = list(string)
      conditions = optional(list(object({
        test     = string
        variable = string
        values   = list(string)
      })), [])
    })), [])

    # Session configuration
    max_session_hours = optional(number, 1)        # Maximum session duration (1-12)

    # Extra trust conditions
    extra_conditions = optional(map(map(list(string))), {}) # Additional assume role conditions
  }))
  default     = {}
  description = "Map of role configurations for GitHub Actions"

  validation {
    condition = alltrue([
      for k, v in var.roles : length(v.repos) > 0
    ])
    error_message = "Each role must specify at least one repository."
  }

  validation {
    condition = alltrue([
      for k, v in var.roles : v.max_session_hours >= 1 && v.max_session_hours <= 12
    ])
    error_message = "Role max_session_hours must be between 1 and 12."
  }

  validation {
    condition = alltrue([
      for k, v in var.roles : alltrue([
        for repo in v.repos : can(regex("^[a-zA-Z0-9][a-zA-Z0-9-_.]*/[a-zA-Z0-9][a-zA-Z0-9-_.]*$|^[a-zA-Z0-9][a-zA-Z0-9-_.]*$|^\\*$", repo))
      ])
    ])
    error_message = "Repository names must be valid GitHub repo format (owner/repo or repo)."
  }
}

# Pre-built role templates
variable "terraform_deploy_role" {
  type = object({
    enabled           = optional(bool, false)
    repos             = optional(list(string), [])
    branches          = optional(list(string), ["main"])
    environments      = optional(list(string), [])
    state_bucket      = optional(string, "")
    state_bucket_key_prefix = optional(string, "*")  # Limit to specific paths
    dynamodb_table    = optional(string, "")
    allowed_services  = optional(list(string), [])   # Limit to specific AWS services
    denied_actions    = optional(list(string), [     # Explicit denies for safety
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:DeleteAccountPasswordPolicy",
      "organizations:*",
      "account:*"
    ])
  })
  default     = {}
  description = "Pre-configured role for Terraform deployments"
}

variable "ecr_push_role" {
  type = object({
    enabled       = optional(bool, false)
    repos         = optional(list(string), [])
    branches      = optional(list(string), ["main"])
    ecr_repos     = optional(list(string), [])     # Specific ECR repos (no default wildcard)
    allow_create  = optional(bool, false)
    allow_delete  = optional(bool, false)          # Explicit opt-in for delete
  })
  default     = {}
  description = "Pre-configured role for ECR push operations"

  validation {
    condition     = !try(var.ecr_push_role.enabled, false) || length(try(var.ecr_push_role.ecr_repos, [])) > 0
    error_message = "ECR push role requires explicit ecr_repos list (no wildcards for security)."
  }
}

variable "s3_deploy_role" {
  type = object({
    enabled          = optional(bool, false)
    repos            = optional(list(string), [])
    branches         = optional(list(string), ["main"])
    bucket_arns      = optional(list(string), [])
    allowed_prefixes = optional(list(string), ["*"])  # Limit to specific paths
    cloudfront_arns  = optional(list(string), [])
  })
  default     = {}
  description = "Pre-configured role for S3 static site deployments"

  validation {
    condition     = !try(var.s3_deploy_role.enabled, false) || length(try(var.s3_deploy_role.bucket_arns, [])) > 0
    error_message = "S3 deploy role requires explicit bucket_arns list."
  }
}

variable "lambda_deploy_role" {
  type = object({
    enabled         = optional(bool, false)
    repos           = optional(list(string), [])
    branches        = optional(list(string), ["main"])
    function_arns   = optional(list(string), [])
    allow_create    = optional(bool, false)
    allow_logs      = optional(bool, true)         # Allow CloudWatch Logs access
  })
  default     = {}
  description = "Pre-configured role for Lambda deployments"

  validation {
    condition     = !try(var.lambda_deploy_role.enabled, false) || length(try(var.lambda_deploy_role.function_arns, [])) > 0
    error_message = "Lambda deploy role requires explicit function_arns list."
  }
}

variable "enable_cloudtrail_logging" {
  type        = bool
  default     = true
  description = "Create CloudWatch metric alarms for OIDC role assumptions"
}

variable "alarm_sns_topic_arn" {
  type        = string
  default     = ""
  description = "SNS topic ARN for security alarms"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags to apply to all resources"

  validation {
    condition     = !contains(keys(var.tags), "Name")
    error_message = "Name tag is auto-generated, do not specify in tags variable."
  }
}
