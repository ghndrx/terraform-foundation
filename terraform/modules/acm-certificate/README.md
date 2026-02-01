# acm-certificate

ACM Certificate Module

## Usage

```hcl
module "acm_certificate" {
  source = "../modules/acm-certificate"
  
  # Required variables
  domain_name = ""

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
| domain_name | Primary domain name for the certificate | `string` | yes |
| subject_alternative_names | Additional domain names (SANs) for the certificate | `list(string)` | no |
| zone_id | Route53 zone ID for DNS validation (null for email validatio... | `string` | no |
| validation_method | Validation method: DNS or EMAIL | `string` | no |
| wait_for_validation | Wait for certificate validation to complete | `bool` | no |
| validation_timeout | Timeout for certificate validation | `string` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| certificate_arn | ARN of the certificate |
| certificate_domain_name | Primary domain name |
| certificate_status | Certificate status |
| validation_records |  |
| validated_certificate_arn | ARN of the validated certificate |

## License

Apache 2.0 - See LICENSE for details.
