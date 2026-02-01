# security-groups

Terraform module for AWS landing zone pattern.

Create common security group patterns for multi-tier architectures.

## Planned Features

- [ ] Web tier (HTTP/HTTPS from ALB)
- [ ] App tier (from web tier only)
- [ ] Database tier (from app tier only)
- [ ] Bastion host (SSH from allowed CIDRs)
- [ ] VPC endpoints (HTTPS from VPC)
- [ ] EKS patterns (cluster, nodes, pods)

## Planned Usage

```hcl
module "security_groups" {
  source = "../modules/security-groups"
  
  vpc_id      = module.vpc.vpc_id
  name_prefix = "myapp"
  
  create_web_tier = true
  create_app_tier = true
  create_db_tier  = true
  create_bastion  = true
  
  allowed_ssh_cidrs = ["10.0.0.0/8"]
  
  tags = local.tags
}
```
