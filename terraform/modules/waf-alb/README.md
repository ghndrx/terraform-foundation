# waf-alb

WAF Module for ALB Protection

## Usage

```hcl
module "waf_alb" {
  source = "../modules/waf-alb"
  
  # Required variables
  name = ""

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
| name | Name for the WAF Web ACL | `string` | yes |
| description |  | `string` | no |
| rate_limit | Requests per 5-minute period per IP | `number` | no |
| rate_limit_action |  | `string` | no |
| blocked_countries | ISO 3166-1 alpha-2 country codes to block | `list(string)` | no |
| allowed_countries | If set, ONLY these countries are allowed (overrides blocked) | `list(string)` | no |
| ip_allowlist | CIDR blocks to always allow | `list(string)` | no |
| ip_blocklist | CIDR blocks to always block | `list(string)` | no |
| enable_aws_managed_rules |  | `bool` | no |
| enable_known_bad_inputs |  | `bool` | no |
| enable_sql_injection |  | `bool` | no |
| enable_linux_protection |  | `bool` | no |
| enable_php_protection |  | `bool` | no |
| enable_wordpress_protection |  | `bool` | no |
| enable_bot_control | Bot Control (additional cost ~$10/mo + $1/million requests) | `bool` | no |

*...and 3 more variables. See `variables.tf` for complete list.*

## Outputs

| Name | Description |
|------|-------------|
| web_acl_arn | ARN of the WAF Web ACL - use this with ALB |
| web_acl_id |  |
| web_acl_capacity | WCU capacity used (max 1500 for regional) |

## License

Apache 2.0 - See LICENSE for details.
