# tenant-baseline

Terraform module for AWS landing zone pattern.

Apply tenant-specific baseline for multi-tenant architectures.

## Planned Features

- [ ] Tenant-specific IAM roles with boundaries
- [ ] Tenant budget alerts
- [ ] Tenant tagging enforcement
- [ ] Dedicated or shared VPC networking
- [ ] Cost allocation tag setup

## Planned Usage

```hcl
module "tenant" {
  source = "../modules/tenant-baseline"
  
  tenant_name  = "acme-corp"
  tenant_id    = "acme"
  environment  = "prod"
  cost_center  = "CC-12345"
  owner_email  = "admin@acme.com"
  budget_limit = 500
  
  # Dedicated VPC (optional)
  vpc_config = {
    cidr            = "10.100.0.0/16"
    azs             = ["us-east-1a", "us-east-1b"]
    private_subnets = ["10.100.1.0/24", "10.100.2.0/24"]
    public_subnets  = ["10.100.101.0/24", "10.100.102.0/24"]
  }
  
  tags = local.tags
}
```
