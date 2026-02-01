# config-rules

AWS Config Rules Module

## Usage

```hcl
module "config_rules" {
  source = "../modules/config-rules"
  
  # Required variables

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
| enable_aws_config | Enable AWS Config (required for rules) | `bool` | no |
| config_bucket | S3 bucket for Config snapshots (created if empty) | `string` | no |
| config_sns_topic_arn | SNS topic for Config notifications | `string` | no |
| delivery_frequency | Config snapshot delivery frequency | `string` | no |
| enable_cis_benchmark | Enable CIS AWS Foundations Benchmark rules | `bool` | no |
| enable_security_best_practices | Enable AWS Security Best Practices rules | `bool` | no |
| enable_pci_dss | Enable PCI DSS compliance rules | `bool` | no |
| enable_hipaa | Enable HIPAA compliance rules | `bool` | no |
| rules |  | `object({` | no |
| auto_remediation | Enable auto-remediation for supported rules | `bool` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| config_recorder_id | Config recorder ID |
| config_bucket | S3 bucket for Config snapshots |
| enabled_rules |  |
| compliance_packs |  |

## License

Apache 2.0 - See LICENSE for details.
