# tenant-onboard

Tenant Onboarding Module Creates: Tenant OUs, App Accounts, IAM Groups, Budgets }

## Usage

```hcl
module "tenant_onboard" {
  source = "../modules/tenant-onboard"
  
  # Required variables
  tenant = ""
  email_domain = ""
  production_ou_id = ""
  nonproduction_ou_id = ""
  apps = ""
  alert_emails = ""
  permission_set_admin_arn = ""
  permission_set_developer_arn = ""
  permission_set_readonly_arn = ""

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
| tenant | Tenant identifier (lowercase, no spaces) | `string` | yes |
| email_domain | Domain for AWS account emails | `string` | yes |
| email_prefix | Email prefix before + sign | `string` | no |
| production_ou_id | ID of the Production OU | `string` | yes |
| nonproduction_ou_id | ID of the Non-Production OU | `string` | yes |
| environments | Environments to create for each app | `list(string)` | no |
| apps | Map of applications for this tenant | `map(object({` | yes |
| monthly_budget | Total monthly budget for tenant | `number` | no |
| alert_emails | Emails to receive budget alerts | `list(string)` | yes |
| permission_set_admin_arn | ARN of the TenantAdmin permission set | `string` | yes |
| permission_set_developer_arn | ARN of the TenantDeveloper permission set | `string` | yes |
| permission_set_readonly_arn | ARN of the TenantReadOnly permission set | `string` | yes |

## Outputs

| Name | Description |
|------|-------------|
| tenant_ou_ids |  |
| account_ids |  |
| group_ids |  |

## License

Apache 2.0 - See LICENSE for details.
