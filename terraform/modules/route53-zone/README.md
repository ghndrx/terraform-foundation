# route53-zone

Route53 Zone Module

## Usage

```hcl
module "route53_zone" {
  source = "../modules/route53-zone"
  
  # Required variables
  domain_name = ""
  records = ""
  alias_records = ""
  mx_records = ""

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
| domain_name | Domain name for the hosted zone | `string` | yes |
| comment | Comment for the hosted zone | `string` | no |
| private_zone | Create a private hosted zone | `bool` | no |
| vpc_ids | VPC IDs to associate with private zone | `list(string)` | no |
| enable_dnssec | Enable DNSSEC signing | `bool` | no |
| enable_query_logging | Enable query logging to CloudWatch | `bool` | no |
| query_log_retention_days | Query log retention in days | `number` | no |
| records |  | `map(object({` | yes |
| alias_records |  | `map(object({` | yes |
| mx_records |  | `list(object({` | yes |
| txt_records |  | `map(string)` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| zone_id | Hosted zone ID |
| zone_arn | Hosted zone ARN |
| name_servers | Name servers for the zone (update at registrar) |
| domain_name | Domain name |
| dnssec_ds_record | DS record for DNSSEC (add to parent zone/registrar) |

## License

Apache 2.0 - See LICENSE for details.
