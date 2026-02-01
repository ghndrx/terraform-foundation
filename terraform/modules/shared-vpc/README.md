# shared-vpc

Shared VPC Module Single VPC shared across all tenants via AWS RAM Isolation via: Security Groups, ABAC (tags), optional subnet segmentation

## Usage

```hcl
module "shared_vpc" {
  source = "../modules/shared-vpc"
  
  # Required variables
  workloads_ou_arn = ""

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
| vpc_cidr | CIDR block for the shared VPC | `string` | no |
| tenant_subnet_cidr | CIDR block for tenant-specific subnets (if enabled) | `string` | no |
| availability_zones | List of availability zones | `list(string)` | no |
| enable_nat_gateway | Enable NAT Gateway for private subnet internet access | `bool` | no |
| tenants | List of tenant names (for per-tenant subnets) | `list(string)` | no |
| create_tenant_subnets | Create separate subnets per tenant (stricter isolation) | `bool` | no |
| workloads_ou_arn | ARN of the Workloads OU to share subnets with | `string` | yes |

## Outputs

| Name | Description |
|------|-------------|
| vpc_id |  |
| vpc_cidr |  |
| public_subnet_ids |  |
| private_shared_subnet_ids |  |
| private_tenant_subnet_ids |  |
| nat_gateway_ip |  |
| ram_share_arn |  |

## License

Apache 2.0 - See LICENSE for details.
