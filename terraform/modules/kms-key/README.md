# kms-key

KMS Key Module

## Usage

```hcl
module "kms_key" {
  source = "../modules/kms-key"
  
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
| name | Key name (used for alias) | `string` | yes |
| description | Key description | `string` | no |
| deletion_window_in_days | Waiting period before key deletion (7-30 days) | `number` | no |
| enable_key_rotation | Enable automatic key rotation (annual) | `bool` | no |
| multi_region | Create a multi-region key | `bool` | no |
| key_usage | Key usage: ENCRYPT_DECRYPT or SIGN_VERIFY | `string` | no |
| key_spec | Key spec (SYMMETRIC_DEFAULT, RSA_2048, ECC_NIST_P256, etc.) | `string` | no |
| admin_principals | IAM ARNs with full admin access to the key | `list(string)` | no |
| user_principals | IAM ARNs with encrypt/decrypt access | `list(string)` | no |
| service_principals | AWS service principals that can use the key (e.g., logs.amaz... | `list(string)` | no |
| grant_accounts | Account IDs with cross-account access | `list(string)` | no |
| tags |  | `map(string)` | no |

## Outputs

| Name | Description |
|------|-------------|
| key_id | KMS key ID |
| key_arn | KMS key ARN |
| alias_arn | KMS alias ARN |
| alias_name | KMS alias name |
| key_policy | Key policy document |

## License

Apache 2.0 - See LICENSE for details.
