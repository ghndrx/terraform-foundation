# vpc-lite

VPC Lite Module

## Usage

```hcl
module "vpc_lite" {
  source = "../modules/vpc-lite"
  
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
| name | VPC name prefix | `string` | yes |
| cidr | VPC CIDR block | `string` | no |
| azs | Availability zones (auto-detected if empty) | `list(string)` | no |
| az_count | Number of AZs to use (if azs not specified) | `number` | no |
| nat_mode | NAT mode: none, instance, or gateway | `string` | no |
| create_private_subnets | Create private subnets (set false for public-only) | `bool` | no |
| enable_vpc_endpoints | Create VPC endpoints for AWS services (recommended when nat_... | `bool` | no |
| vpc_endpoint_services | Gateway endpoints to create (s3, dynamodb) | `list(string)` | no |
| vpc_endpoint_interfaces | Interface endpoints to create (ecr.api, ecr.dkr, logs, ssm, ... | `list(string)` | no |
| enable_flow_logs | Enable VPC Flow Logs | `bool` | no |
| flow_log_retention_days | Flow log retention (shorter = cheaper) | `number` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id |  |
| vpc_cidr |  |
| public_subnet_ids |  |
| private_subnet_ids |  |
| nat_mode | NAT mode used |
| nat_ip | NAT public IP (if applicable) |
| cost_estimate | Estimated monthly cost for NAT |
| internet_access |  |
| vpc_endpoints |  |

## License

Apache 2.0 - See LICENSE for details.
