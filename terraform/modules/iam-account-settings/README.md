# iam-account-settings

IAM Account Settings Module

## Usage

```hcl
module "iam_account_settings" {
  source = "../modules/iam-account-settings"
  
  # Required variables
  password_policy = ""

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
| account_alias | AWS account alias (appears in sign-in URL) | `string` | no |
| password_policy |  | `object({` | yes |
| enable_password_policy | Enable custom password policy | `bool` | no |
| enforce_mfa | Create IAM policy to enforce MFA for all actions | `bool` | no |
| mfa_grace_period_days | Days new users have before MFA is required (0 = immediate) | `number` | no |
| mfa_exempt_roles | Role names exempt from MFA requirement | `list(string)` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| account_alias | AWS account alias |
| signin_url |  |
| password_policy |  |
| mfa_enforcement_policy_arn | MFA enforcement policy ARN |
| mfa_required_group | Group name for users requiring MFA |
| mfa_scp_template_policy | Template policy for MFA SCP (copy to Organizations) |

## License

Apache 2.0 - See LICENSE for details.
