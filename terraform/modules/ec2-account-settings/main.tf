################################################################################
# EC2 Account Settings Module
#
# Applies account-level EC2 security hardening:
# - Disable EC2 Serial Console access (attack surface reduction)
# - Enforce IMDSv2 by default (SSRF protection)
# - Block public EBS snapshots (data exfiltration prevention)
# - Block public AMI sharing (intellectual property protection)
#
# Deploy per-region for regional settings (IMDS, snapshots, AMIs)
################################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0" # IMDSv2 defaults added in 5.31
    }
  }
}

data "aws_region" "current" {}

################################################################################
# EC2 Serial Console Access
#
# Disables serial console access by default. Serial console can be used
# for instance recovery but also presents an attack vector if compromised
# credentials are obtained. Enable only when needed for troubleshooting.
#
# Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html
################################################################################

resource "aws_ec2_serial_console_access" "this" {
  count = var.manage_serial_console ? 1 : 0

  enabled = var.serial_console_enabled
}

################################################################################
# Instance Metadata Service (IMDS) Defaults
#
# Enforces IMDSv2 for all new EC2 instances. IMDSv2 requires session tokens
# which mitigates SSRF attacks that could exfiltrate instance credentials.
#
# Settings:
# - http_tokens = "required"    : Requires IMDSv2 session tokens
# - http_endpoint = "enabled"   : IMDS accessible (but secured with v2)
# - http_put_response_hop_limit : Limits token request scope (1 = instance only)
# - instance_metadata_tags      : Control tag access via IMDS
#
# Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html
################################################################################

resource "aws_ec2_instance_metadata_defaults" "this" {
  count = var.manage_imds_defaults ? 1 : 0

  http_tokens                 = var.imds_http_tokens
  http_endpoint               = var.imds_http_endpoint
  http_put_response_hop_limit = var.imds_hop_limit
  instance_metadata_tags      = var.imds_instance_metadata_tags
}

################################################################################
# EBS Snapshot Block Public Access
#
# Prevents EBS snapshots from being shared publicly. Public snapshots
# can expose sensitive data and are a common source of data breaches.
#
# States:
# - "block-all-sharing"           : Block all public sharing
# - "block-new-sharing"           : Block new shares, keep existing
# - "unblocked"                   : Allow public sharing (not recommended)
#
# Reference: https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html
################################################################################

resource "aws_ebs_snapshot_block_public_access" "this" {
  count = var.manage_snapshot_public_access ? 1 : 0

  state = var.snapshot_block_public_access_state
}

################################################################################
# EC2 AMI Block Public Access
#
# Prevents AMIs from being shared publicly. Public AMIs can expose
# proprietary software, configurations, or embedded credentials.
#
# Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-to-amis.html
################################################################################

resource "aws_ec2_image_block_public_access" "this" {
  count = var.manage_ami_public_access ? 1 : 0

  state = var.ami_block_public_access_state
}

################################################################################
# Outputs
################################################################################

output "serial_console_enabled" {
  description = "Whether EC2 serial console access is enabled"
  value       = var.manage_serial_console ? var.serial_console_enabled : null
}

output "imds_settings" {
  description = "Instance metadata service default settings"
  value = var.manage_imds_defaults ? {
    http_tokens    = var.imds_http_tokens
    http_endpoint  = var.imds_http_endpoint
    hop_limit      = var.imds_hop_limit
    metadata_tags  = var.imds_instance_metadata_tags
  } : null
}

output "snapshot_block_public_access" {
  description = "EBS snapshot block public access state"
  value       = var.manage_snapshot_public_access ? var.snapshot_block_public_access_state : null
}

output "ami_block_public_access" {
  description = "AMI block public access state"
  value       = var.manage_ami_public_access ? var.ami_block_public_access_state : null
}

output "region" {
  description = "AWS region where settings are applied"
  value       = data.aws_region.current.id
}

output "hardening_summary" {
  description = "Summary of enabled security hardening features"
  value = {
    serial_console_disabled       = var.manage_serial_console && !var.serial_console_enabled
    imdsv2_enforced               = var.manage_imds_defaults && var.imds_http_tokens == "required"
    snapshot_public_blocked       = var.manage_snapshot_public_access && var.snapshot_block_public_access_state == "block-all-sharing"
    ami_public_blocked            = var.manage_ami_public_access && var.ami_block_public_access_state == "block-new-sharing"
  }
}
