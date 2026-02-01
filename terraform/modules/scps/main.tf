################################################################################
# Service Control Policies Module
#
# Implements AWS Organizations SCPs for security guardrails:
# - Deny leaving organization
# - Require IMDSv2
# - Deny root user actions
# - Region restrictions
# - Protect security services
# - Protect CloudTrail
# - Require encryption
#
# References:
# - AWS SRA: https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture
# - CIS Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services
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

locals {
  # Build list of SCPs to create based on enabled flags
  scps = merge(
    var.enable_deny_leave_org ? {
      deny_leave_org = {
        name        = "${var.name_prefix}-deny-leave-org"
        description = "Prevent accounts from leaving the organization"
        policy      = data.aws_iam_policy_document.deny_leave_org.json
      }
    } : {},
    var.enable_require_imdsv2 ? {
      require_imdsv2 = {
        name        = "${var.name_prefix}-require-imdsv2"
        description = "Require IMDSv2 for EC2 instances"
        policy      = data.aws_iam_policy_document.require_imdsv2.json
      }
    } : {},
    var.enable_deny_root_actions ? {
      deny_root = {
        name        = "${var.name_prefix}-deny-root-actions"
        description = "Deny most actions by root user"
        policy      = data.aws_iam_policy_document.deny_root.json
      }
    } : {},
    length(var.allowed_regions) > 0 ? {
      region_restriction = {
        name        = "${var.name_prefix}-region-restriction"
        description = "Restrict operations to allowed regions"
        policy      = data.aws_iam_policy_document.region_restriction.json
      }
    } : {},
    var.protect_security_services ? {
      protect_security = {
        name        = "${var.name_prefix}-protect-security-services"
        description = "Prevent disabling security services"
        policy      = data.aws_iam_policy_document.protect_security.json
      }
    } : {},
    var.protect_cloudtrail ? {
      protect_cloudtrail = {
        name        = "${var.name_prefix}-protect-cloudtrail"
        description = "Prevent CloudTrail modification"
        policy      = data.aws_iam_policy_document.protect_cloudtrail.json
      }
    } : {},
    var.require_s3_encryption ? {
      require_s3_encryption = {
        name        = "${var.name_prefix}-require-s3-encryption"
        description = "Require S3 bucket encryption"
        policy      = data.aws_iam_policy_document.require_s3_encryption.json
      }
    } : {},
    var.require_ebs_encryption ? {
      require_ebs_encryption = {
        name        = "${var.name_prefix}-require-ebs-encryption"
        description = "Require EBS volume encryption"
        policy      = data.aws_iam_policy_document.require_ebs_encryption.json
      }
    } : {},
  )

  # Global services that shouldn't be region-restricted
  global_services = [
    "iam",
    "organizations",
    "sts",
    "support",
    "budgets",
    "cloudfront",
    "route53",
    "waf",
    "waf-regional",
    "health",
    "trustedadvisor",
  ]
}

################################################################################
# Policy Documents
################################################################################

data "aws_iam_policy_document" "deny_leave_org" {
  statement {
    sid       = "DenyLeaveOrganization"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "require_imdsv2" {
  statement {
    sid    = "RequireIMDSv2"
    effect = "Deny"
    actions = [
      "ec2:RunInstances"
    ]
    resources = ["arn:aws:ec2:*:*:instance/*"]

    condition {
      test     = "StringNotEquals"
      variable = "ec2:MetadataHttpTokens"
      values   = ["required"]
    }
  }

  statement {
    sid    = "DenyIMDSv1Modification"
    effect = "Deny"
    actions = [
      "ec2:ModifyInstanceMetadataOptions"
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "ec2:MetadataHttpTokens"
      values   = ["required"]
    }
  }
}

data "aws_iam_policy_document" "deny_root" {
  statement {
    sid    = "DenyRootActions"
    effect = "Deny"
    not_actions = [
      # Allow essential root-only actions
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:ListVirtualMFADevices",
      "sts:GetSessionToken",
      "support:*",
    ]
    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:root"]
    }
  }
}

data "aws_iam_policy_document" "region_restriction" {
  statement {
    sid    = "DenyNonAllowedRegions"
    effect = "Deny"
    not_actions = [
      # Global services - always allow
      "iam:*",
      "organizations:*",
      "sts:*",
      "support:*",
      "budgets:*",
      "cloudfront:*",
      "route53:*",
      "route53domains:*",
      "waf:*",
      "wafv2:*",
      "waf-regional:*",
      "health:*",
      "trustedadvisor:*",
      "globalaccelerator:*",
      "shield:*",
      "chime:*",
      "aws-portal:*",
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }
}

data "aws_iam_policy_document" "protect_security" {
  statement {
    sid    = "ProtectGuardDuty"
    effect = "Deny"
    actions = [
      "guardduty:DeleteDetector",
      "guardduty:DeleteMembers",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ProtectSecurityHub"
    effect = "Deny"
    actions = [
      "securityhub:DisableSecurityHub",
      "securityhub:DeleteMembers",
      "securityhub:DisassociateFromMasterAccount",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ProtectConfig"
    effect = "Deny"
    actions = [
      "config:DeleteConfigRule",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:StopConfigurationRecorder",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ProtectAccessAnalyzer"
    effect = "Deny"
    actions = [
      "access-analyzer:DeleteAnalyzer",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "protect_cloudtrail" {
  statement {
    sid    = "ProtectCloudTrail"
    effect = "Deny"
    actions = [
      "cloudtrail:DeleteTrail",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
    ]
    resources = ["*"]

    # Allow org management account to manage org trail
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalOrgMasterAccountId"
      values   = ["${data.aws_caller_identity.current.account_id}"]
    }
  }
}

data "aws_iam_policy_document" "require_s3_encryption" {
  statement {
    sid    = "DenyUnencryptedS3PutObject"
    effect = "Deny"
    actions = [
      "s3:PutObject"
    ]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  statement {
    sid    = "DenyWrongEncryptionType"
    effect = "Deny"
    actions = [
      "s3:PutObject"
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256", "aws:kms"]
    }
  }
}

data "aws_iam_policy_document" "require_ebs_encryption" {
  statement {
    sid    = "DenyUnencryptedVolume"
    effect = "Deny"
    actions = [
      "ec2:CreateVolume"
    ]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyUnencryptedSnapshot"
    effect = "Deny"
    actions = [
      "ec2:RunInstances"
    ]
    resources = ["arn:aws:ec2:*::snapshot/*"]

    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"
      values   = ["false"]
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_organizations_organization" "current" {}

################################################################################
# SCP Resources
################################################################################

resource "aws_organizations_policy" "this" {
  for_each = local.scps

  name        = each.value.name
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.policy

  tags = merge(var.tags, {
    Name = each.value.name
  })
}

# Attach SCPs to specified OUs
resource "aws_organizations_policy_attachment" "ou" {
  for_each = {
    for pair in setproduct(keys(local.scps), var.target_ous) : "${pair[0]}-${pair[1]}" => {
      policy_key = pair[0]
      target_id  = pair[1]
    }
  }

  policy_id = aws_organizations_policy.this[each.value.policy_key].id
  target_id = each.value.target_id
}

# Attach SCPs to specified accounts
resource "aws_organizations_policy_attachment" "account" {
  for_each = {
    for pair in setproduct(keys(local.scps), var.target_accounts) : "${pair[0]}-${pair[1]}" => {
      policy_key = pair[0]
      target_id  = pair[1]
    }
  }

  policy_id = aws_organizations_policy.this[each.value.policy_key].id
  target_id = each.value.target_id
}
