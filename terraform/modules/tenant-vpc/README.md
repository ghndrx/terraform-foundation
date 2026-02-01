# tenant-vpc

Terraform module for AWS landing zone pattern.

Create tenant-isolated VPC with standard networking.

## Planned Features

- [ ] Dedicated CIDR block
- [ ] Public/private subnets across AZs
- [ ] NAT Gateway or cost-optimized NAT Instance
- [ ] VPC Flow Logs to CloudWatch
- [ ] Transit Gateway attachment
- [ ] Routes to shared services VPC

## Planned Usage

```hcl
module "tenant_vpc" {
  source = "../modules/tenant-vpc"
  
  tenant_name = "acme-corp"
  cidr        = "10.100.0.0/16"
  azs         = ["us-east-1a", "us-east-1b"]
  
  private_subnets = ["10.100.1.0/24", "10.100.2.0/24"]
  public_subnets  = ["10.100.101.0/24", "10.100.102.0/24"]
  
  enable_nat = true
  nat_mode   = "instance"  # Cost-optimized
  
  transit_gateway_id = data.aws_ec2_transit_gateway.main.id
  
  tags = local.tags
}
```
