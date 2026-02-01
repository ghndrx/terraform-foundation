# alb

Application Load Balancer Module

## Usage

```hcl
module "alb" {
  source = "../modules/alb"
  
  # Required variables
  name = ""
  vpc_id = ""
  subnet_ids = ""
  access_logs = ""
  target_groups = ""
  listener_rules = ""

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
| name | ALB name | `string` | yes |
| vpc_id | VPC ID | `string` | yes |
| subnet_ids | Subnet IDs (public for internet-facing, private for internal... | `list(string)` | yes |
| internal | Internal ALB (no public IP) | `bool` | no |
| certificate_arn | ACM certificate ARN for HTTPS | `string` | no |
| additional_certificates | Additional certificate ARNs for SNI | `list(string)` | no |
| ssl_policy | SSL policy for HTTPS listeners | `string` | no |
| enable_deletion_protection | Prevent accidental deletion | `bool` | no |
| enable_http2 | Enable HTTP/2 | `bool` | no |
| idle_timeout | Idle timeout in seconds | `number` | no |
| drop_invalid_header_fields | Drop requests with invalid headers | `bool` | no |
| access_logs |  | `object({` | yes |
| target_groups |  | `map(object({` | yes |
| listener_rules |  | `map(object({` | yes |
| waf_arn | WAF Web ACL ARN to associate | `string` | no |

*...and 3 more variables. See `variables.tf` for complete list.*

## Outputs

| Name | Description |
|------|-------------|
| arn | ALB ARN |
| arn_suffix | ALB ARN suffix (for CloudWatch metrics) |
| dns_name | ALB DNS name |
| zone_id | ALB hosted zone ID |
| security_group_id | ALB security group ID |
| target_group_arns |  |
| target_group_arn_suffixes |  |
| https_listener_arn | HTTPS listener ARN |
| http_listener_arn | HTTP listener ARN |

## License

Apache 2.0 - See LICENSE for details.
