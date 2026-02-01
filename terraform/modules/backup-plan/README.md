# backup-plan

AWS Backup Module

## Usage

```hcl
module "backup_plan" {
  source = "../modules/backup-plan"
  
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
| name | Backup plan name | `string` | yes |
| tenant | Tenant name for resource selection | `string` | no |
| backup_tag_key | Tag key to select resources for backup | `string` | no |
| backup_tag_value | Tag value to select resources for backup | `string` | no |
| daily_retention_days |  | `number` | no |
| weekly_retention_days |  | `number` | no |
| monthly_retention_days |  | `number` | no |
| enable_continuous_backup | Enable continuous backup for point-in-time recovery (RDS, S3... | `bool` | no |
| enable_cross_region_copy |  | `bool` | no |
| dr_region | DR region for cross-region backup copy | `string` | no |
| dr_retention_days |  | `number` | no |
| kms_key_arn | KMS key ARN for backup encryption (uses AWS managed key if n... | `string` | no |

## Outputs

| Name | Description |
|------|-------------|
| vault_arn |  |
| vault_name |  |
| plan_id |  |
| plan_arn |  |
| role_arn |  |

## License

Apache 2.0 - See LICENSE for details.
