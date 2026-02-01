# security-baseline

Security Baseline Module

## Usage

```hcl
module "security_baseline" {
  source = "../modules/security-baseline"
  
  # Required variables
  name = ""
  config_bucket_name = ""

  # Optional: see variables.tf for all options
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |

## Inputs

| Name | Description | Type | Required |
|------|-------------|------|----------|
| name | Name prefix for resources | `string` | yes |
| enable_guardduty |  | `bool` | no |
| enable_securityhub |  | `bool` | no |
| enable_config |  | `bool` | no |
| enable_access_analyzer |  | `bool` | no |
| enable_macie | Macie for S3 data classification (additional cost) | `bool` | no |
| config_bucket_name | S3 bucket for AWS Config recordings | `string` | yes |
| guardduty_finding_publishing_frequency |  | `string` | no |
| securityhub_standards | Security Hub standards to enable | `list(string)` | no |
| config_rules | Additional AWS Config managed rule identifiers to enable | `list(string)` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| guardduty_detector_id |  |
| securityhub_account_id |  |
| config_recorder_id |  |
| access_analyzer_arn |  |
| enabled_services |  |

## License

Apache 2.0 - See LICENSE for details.
