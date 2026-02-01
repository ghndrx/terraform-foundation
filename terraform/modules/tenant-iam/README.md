# tenant-iam

Terraform module for AWS landing zone pattern.

Create tenant-specific IAM roles with proper isolation.

## Planned Features

- [ ] Tenant admin role (full tenant access)
- [ ] Tenant developer role (limited write)
- [ ] Tenant readonly role (view only)
- [ ] Permissions boundary enforcement
- [ ] Resource-based isolation (tenant prefix)
- [ ] Cross-account trust configuration

## Planned Usage

```hcl
module "tenant_iam" {
  source = "../modules/tenant-iam"
  
  tenant_name = "acme-corp"
  tenant_id   = "acme"
  
  create_admin_role     = true
  create_developer_role = true
  create_readonly_role  = true
  
  trusted_principals = [
    "arn:aws:iam::111111111111:root"  # Identity account
  ]
  
  allowed_services = ["ec2", "s3", "lambda", "rds"]
  resource_prefix  = "acme-"
  
  permissions_boundary = aws_iam_policy.tenant_boundary.arn
}
```

## Security

All tenant roles are created with permissions boundaries to prevent:
- Creating IAM users/roles without boundaries
- Accessing other tenants' resources
- Modifying security services
