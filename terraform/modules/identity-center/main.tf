################################################################################
# Identity Center Module
#
# Configures AWS IAM Identity Center (formerly AWS SSO):
# - Permission sets with managed and inline policies
# - Account assignments for groups
# - Default permission sets (Admin, PowerUser, ReadOnly, Billing)
################################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_ssoadmin_instances" "this" {}

locals {
  instance_arn      = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]

  # Default permission sets
  default_permission_sets = var.create_default_permission_sets ? {
    AdministratorAccess = {
      description       = "Full administrator access"
      session_duration  = "PT4H"
      managed_policies  = ["arn:aws:iam::aws:policy/AdministratorAccess"]
      inline_policy     = ""
    }
    PowerUserAccess = {
      description       = "Power user access (no IAM)"
      session_duration  = "PT4H"
      managed_policies  = ["arn:aws:iam::aws:policy/PowerUserAccess"]
      inline_policy     = ""
    }
    ReadOnlyAccess = {
      description       = "Read-only access"
      session_duration  = "PT8H"
      managed_policies  = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      inline_policy     = ""
    }
    Billing = {
      description       = "Billing access"
      session_duration  = "PT4H"
      managed_policies  = ["arn:aws:iam::aws:policy/job-function/Billing"]
      inline_policy     = ""
    }
    ViewOnlyAccess = {
      description       = "View-only access (no data access)"
      session_duration  = "PT8H"
      managed_policies  = ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]
      inline_policy     = ""
    }
  } : {}

  # Merge default and custom permission sets
  all_permission_sets = merge(local.default_permission_sets, var.permission_sets)
}

################################################################################
# Permission Sets
################################################################################

resource "aws_ssoadmin_permission_set" "this" {
  for_each = local.all_permission_sets

  instance_arn     = local.instance_arn
  name             = each.key
  description      = each.value.description
  session_duration = each.value.session_duration

  tags = merge(var.tags, {
    Name = each.key
  })
}

# Attach managed policies
resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each = {
    for pair in flatten([
      for ps_name, ps in local.all_permission_sets : [
        for policy in ps.managed_policies : {
          key         = "${ps_name}-${replace(policy, "/.*//", "")}"
          ps_name     = ps_name
          policy_arn  = policy
        }
      ]
    ]) : pair.key => pair
  }

  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.ps_name].arn
  managed_policy_arn = each.value.policy_arn
}

# Attach inline policies
resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each = {
    for name, ps in local.all_permission_sets : name => ps
    if ps.inline_policy != ""
  }

  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = each.value.inline_policy
}

################################################################################
# Account Assignments
################################################################################

# Look up groups from Identity Store
data "aws_identitystore_group" "this" {
  for_each = toset([for a in var.account_assignments : a.group_name])

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.value
    }
  }
}

# Create account assignments
resource "aws_ssoadmin_account_assignment" "this" {
  for_each = {
    for a in var.account_assignments :
    "${a.group_name}-${a.permission_set}-${a.account_id}" => a
  }

  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn

  principal_id   = data.aws_identitystore_group.this[each.value.group_name].group_id
  principal_type = "GROUP"

  target_id   = each.value.account_id
  target_type = "AWS_ACCOUNT"
}
