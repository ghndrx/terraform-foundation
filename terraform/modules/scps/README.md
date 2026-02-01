# scps

AWS Organizations Service Control Policies for security guardrails.

## Features

- **Deny leaving organization** - Prevent accounts from leaving
- **Require IMDSv2** - Block EC2 instances without IMDSv2
- **Deny root actions** - Block most root user operations
- **Region restrictions** - Limit operations to allowed regions
- **Protect security services** - Prevent disabling GuardDuty, Security Hub, Config
- **Protect CloudTrail** - Prevent trail modification
- **Require S3 encryption** - Block unencrypted S3 objects
- **Require EBS encryption** - Block unencrypted volumes

## Usage

```hcl
module "scps" {
  source = "../modules/scps"
  
  name_prefix = "org"
  
  # Enable all security guardrails
  enable_deny_leave_org     = true
  enable_require_imdsv2     = true
  enable_deny_root_actions  = true
  protect_security_services = true
  protect_cloudtrail        = true
  require_s3_encryption     = true
  require_ebs_encryption    = true
  
  # Optional: Region restriction
  allowed_regions = ["us-east-1", "us-west-2", "eu-west-1"]
  
  # Attach to OUs
  target_ous = [
    "ou-xxxx-workloads",
    "ou-xxxx-sandbox"
  ]
  
  tags = {
    Environment = "org"
    ManagedBy   = "terraform"
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |

## Providers

Must be run from the **AWS Organizations management account**.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| name_prefix | Prefix for SCP names | `string` | `"scp"` | no |
| enable_deny_leave_org | Prevent accounts from leaving | `bool` | `true` | no |
| enable_require_imdsv2 | Require IMDSv2 for EC2 | `bool` | `true` | no |
| enable_deny_root_actions | Deny root user actions | `bool` | `true` | no |
| allowed_regions | Allowed AWS regions | `list(string)` | `[]` | no |
| protect_security_services | Protect security services | `bool` | `true` | no |
| protect_cloudtrail | Protect CloudTrail | `bool` | `true` | no |
| require_s3_encryption | Require S3 encryption | `bool` | `true` | no |
| require_ebs_encryption | Require EBS encryption | `bool` | `true` | no |
| target_ous | OU IDs to attach SCPs | `list(string)` | `[]` | no |
| target_accounts | Account IDs to attach SCPs | `list(string)` | `[]` | no |
| tags | Resource tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| policy_ids | Map of SCP names to policy IDs |
| policy_arns | Map of SCP names to policy ARNs |
| enabled_policies | List of enabled SCP names |
| attachment_count | Count of attachments |

## Security Best Practices

These SCPs implement:
- CIS AWS Foundations Benchmark
- AWS Security Reference Architecture
- Well-Architected Framework Security Pillar

## Notes

- SCPs only affect member accounts, not the management account
- Test SCPs in sandbox OU before applying to production
- Global services (IAM, Route53, etc.) are exempt from region restrictions
