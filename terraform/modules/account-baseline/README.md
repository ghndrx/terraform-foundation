# account-baseline

Terraform module for AWS landing zone pattern.

Apply baseline security configuration to AWS accounts in a landing zone.

## Planned Features

- [ ] CloudTrail configuration (or org trail delegation)
- [ ] AWS Config (or org aggregator delegation)  
- [ ] GuardDuty member enrollment
- [ ] Security Hub member enrollment
- [ ] IAM password policy
- [ ] Standard IAM roles (admin, readonly, billing)
- [ ] EBS default encryption
- [ ] S3 public access block

## Planned Usage

```hcl
module "baseline" {
  source = "../modules/account-baseline"
  
  account_name = "workload-prod"
  
  # Delegate to org-level services
  enable_cloudtrail = false
  enable_config     = false
  
  # Enroll in delegated admin services
  enable_guardduty   = true
  enable_securityhub = true
  
  tags = local.tags
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |
