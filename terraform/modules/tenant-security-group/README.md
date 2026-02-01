# tenant-security-group

Tenant Security Group Module Creates isolated security groups for tenant workloads in shared VPC }

## Usage

```hcl
module "tenant_security_group" {
  source = "../modules/tenant-security-group"
  
  # Required variables
  tenant = ""
  environment = ""
  vpc_id = ""

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
| tenant | Tenant identifier | `string` | yes |
| environment | Environment (prod, staging, dev) | `string` | yes |
| vpc_id | VPC ID for the security groups | `string` | yes |
| create_web_sg | Create web tier security group | `bool` | no |
| create_app_sg | Create app tier security group | `bool` | no |
| create_db_sg | Create database tier security group | `bool` | no |
| app_port | Application port | `number` | no |
| db_port | Database port | `number` | no |

## Outputs

| Name | Description |
|------|-------------|
| base_sg_id |  |
| web_sg_id |  |
| app_sg_id |  |
| db_sg_id |  |

## License

Apache 2.0 - See LICENSE for details.
