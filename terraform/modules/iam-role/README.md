# iam-role

IAM Role Module

## Usage

```hcl
module "iam_role" {
  source = "../modules/iam-role"
  
  # Required variables
  name = ""

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
| name | Role name | `string` | yes |
| role_type | Type: service, cross-account, oidc | `string` | no |
| description | Role description | `string` | no |
| path | IAM path | `string` | no |
| max_session_duration | Maximum session duration in seconds (1-12 hours) | `number` | no |
| service | AWS service principal (e.g., lambda.amazonaws.com) | `string` | no |
| services | Multiple service principals | `list(string)` | no |
| trusted_account_ids | Account IDs that can assume this role | `list(string)` | no |
| trusted_role_arns | Specific role ARNs that can assume this role | `list(string)` | no |
| require_mfa | Require MFA for cross-account assumption | `bool` | no |
| require_external_id | External ID required for assumption | `string` | no |
| oidc_provider_arn | OIDC provider ARN | `string` | no |
| oidc_subjects | Allowed OIDC subjects (e.g., repo:org/repo:*) | `list(string)` | no |
| oidc_audiences | OIDC audiences | `list(string)` | no |
| managed_policies | List of managed policy ARNs to attach | `list(string)` | no |

*...and 4 more variables. See `variables.tf` for complete list.*

## Outputs

| Name | Description |
|------|-------------|
| role_arn | Role ARN |
| role_name | Role name |
| role_id | Role unique ID |
| instance_profile_arn | Instance profile ARN |
| instance_profile_name | Instance profile name |
| assume_role_command |  |

## License

Apache 2.0 - See LICENSE for details.
