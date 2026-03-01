# EC2 Account Settings Module

Account-level EC2 security hardening for AWS. This module configures security defaults that apply to all EC2 resources in the account/region.

## Security Controls

| Control | Default | Security Benefit |
|---------|---------|-----------------|
| **Serial Console** | Disabled | Reduces attack surface; prevents console access with compromised credentials |
| **IMDSv2 Enforcement** | Required | Mitigates SSRF attacks that could exfiltrate instance role credentials |
| **EBS Snapshot Public Block** | Block All | Prevents accidental data exposure via public snapshots |
| **AMI Public Block** | Block New | Prevents accidental exposure of proprietary AMIs |

## Usage

### Full Security Hardening (Recommended)

```hcl
module "ec2_account_settings" {
  source = "../../modules/ec2-account-settings"

  # All security controls enabled with secure defaults
}
```

### With Container Support (EKS/ECS)

```hcl
module "ec2_account_settings" {
  source = "../../modules/ec2-account-settings"

  # Increase hop limit for container workloads accessing IMDS
  imds_hop_limit = 2
}
```

### Selective Controls

```hcl
module "ec2_account_settings" {
  source = "../../modules/ec2-account-settings"

  # Only manage specific settings
  manage_serial_console         = true
  manage_imds_defaults          = true
  manage_snapshot_public_access = false  # Managed elsewhere
  manage_ami_public_access      = false  # Managed elsewhere
}
```

### Allow Serial Console (Troubleshooting)

```hcl
module "ec2_account_settings" {
  source = "../../modules/ec2-account-settings"

  # Temporarily enable for troubleshooting
  serial_console_enabled = true
}
```

## Multi-Region Deployment

These settings are regional. Use a `for_each` with provider aliases:

```hcl
locals {
  regions = ["us-east-1", "us-west-2", "eu-west-1"]
}

provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu-west-1"
  region = "eu-west-1"
}

module "ec2_settings_us_east_1" {
  source = "../../modules/ec2-account-settings"
  providers = { aws = aws.us-east-1 }
}

module "ec2_settings_us_west_2" {
  source = "../../modules/ec2-account-settings"
  providers = { aws = aws.us-west-2 }
}

module "ec2_settings_eu_west_1" {
  source = "../../modules/ec2-account-settings"
  providers = { aws = aws.eu-west-1 }
}
```

## IMDSv2 Details

Instance Metadata Service v2 (IMDSv2) requires session tokens for metadata requests, protecting against:

- **SSRF attacks**: Attackers can't exfiltrate credentials via simple HTTP GET requests
- **WAF bypasses**: Token requirement adds defense-in-depth
- **Misconfigured proxies**: Hop limit restricts token scope

### Hop Limit Guidelines

| Value | Use Case |
|-------|----------|
| 1 | Bare EC2 instances (most secure) |
| 2 | Docker containers, ECS, EKS (recommended for containers) |
| 3+ | Nested virtualization (rare) |

## Compliance Mapping

| Framework | Control |
|-----------|---------|
| CIS AWS Benchmark | 5.6 - Ensure IMDSv2 is required |
| AWS Well-Architected | SEC05-BP02 - Control traffic at all layers |
| SOC 2 | CC6.1 - Logical and physical access controls |
| PCI DSS | 2.2 - Develop configuration standards |

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.31.0 |

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| manage_serial_console | Manage EC2 serial console setting | `bool` | `true` |
| serial_console_enabled | Enable serial console access | `bool` | `false` |
| manage_imds_defaults | Manage IMDS defaults | `bool` | `true` |
| imds_http_tokens | Token requirement: optional/required | `string` | `"required"` |
| imds_http_endpoint | IMDS endpoint: enabled/disabled | `string` | `"enabled"` |
| imds_hop_limit | HTTP hop limit (1-64) | `number` | `2` |
| imds_instance_metadata_tags | Allow tags in IMDS | `string` | `"disabled"` |
| manage_snapshot_public_access | Manage snapshot public access | `bool` | `true` |
| snapshot_block_public_access_state | Snapshot sharing: block-all-sharing/block-new-sharing/unblocked | `string` | `"block-all-sharing"` |
| manage_ami_public_access | Manage AMI public access | `bool` | `true` |
| ami_block_public_access_state | AMI sharing: block-new-sharing/unblocked | `string` | `"block-new-sharing"` |

## Outputs

| Name | Description |
|------|-------------|
| serial_console_enabled | Serial console access state |
| imds_settings | IMDS configuration object |
| snapshot_block_public_access | Snapshot public access state |
| ami_block_public_access | AMI public access state |
| region | Region where settings applied |
| hardening_summary | Boolean summary of security controls |

## Related Modules

- [account-baseline](../account-baseline) - EBS encryption, S3 public block, password policy
- [security-baseline](../security-baseline) - GuardDuty, Security Hub, Config
- [iam-account-settings](../iam-account-settings) - IAM hardening
