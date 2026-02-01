# identity-center

Terraform module for AWS landing zone pattern.

Configure AWS IAM Identity Center (formerly AWS SSO).

## Planned Features

- [ ] Default permission sets (Admin, PowerUser, ReadOnly, Billing)
- [ ] Custom permission sets with managed + inline policies
- [ ] Group-to-account assignments
- [ ] SCIM provisioning setup
- [ ] MFA enforcement
- [ ] Session duration policies

## Planned Usage

```hcl
module "identity_center" {
  source = "../modules/identity-center"
  
  default_permission_sets = true
  
  permission_sets = {
    DatabaseAdmin = {
      description      = "Database administration access"
      session_duration = "PT8H"
      managed_policies = ["arn:aws:iam::aws:policy/AmazonRDSFullAccess"]
    }
  }
  
  group_assignments = {
    admins_prod = {
      group_name     = "AWS-Admins"
      permission_set = "AdministratorAccess"
      account_ids    = ["111111111111", "222222222222"]
    }
  }
}
```
