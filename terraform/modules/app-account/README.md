# app-account

Terraform module for AWS landing zone pattern.

Provision new application/workload AWS accounts with account vending pattern.

## Planned Features

- [ ] Create account via AWS Organizations
- [ ] Place in appropriate OU
- [ ] Apply account baseline module
- [ ] Configure VPC (shared or dedicated)
- [ ] Create cross-account IAM roles
- [ ] Set up budget alerts
- [ ] Apply standard tags

## Planned Usage

```hcl
module "app_account" {
  source = "../modules/app-account"
  
  account_name  = "myapp-prod"
  account_email = "aws+myapp-prod@company.com"
  environment   = "prod"
  owner         = "platform-team"
  
  vpc_config = {
    mode = "shared"  # Use shared VPC from network account
  }
  
  budget_limit = 500
  
  tags = local.tags
}
```
