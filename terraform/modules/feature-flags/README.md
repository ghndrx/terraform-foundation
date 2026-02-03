# Feature Flags Module

Centralized feature toggles for organization-wide security, compliance, and operational controls. Define once, propagate everywhere.

## Philosophy

- **Everything OPT-IN**: All features default to `false` or minimal settings
- **Environment Presets**: Quick setup via `production`, `staging`, or `development` presets
- **User Override Wins**: Explicit settings always override preset defaults
- **Single Source of Truth**: Define features once, reference everywhere

## Usage

### Basic - Custom Settings

```hcl
module "feature_flags" {
  source = "../modules/feature-flags"
  
  security = {
    guardduty_enabled    = true
    securityhub_enabled  = true
    config_enabled       = true
    cloudtrail_enabled   = true
  }
  
  compliance = {
    cis_benchmark_enabled = true
  }
  
  iam = {
    mfa_enforcement_enabled = true
  }
}
```

### Quick Start - Environment Presets

```hcl
# Production: Maximum security (all security services enabled)
module "feature_flags" {
  source             = "../modules/feature-flags"
  environment_preset = "production"
}

# Staging: Security with cost awareness
module "feature_flags" {
  source             = "../modules/feature-flags"
  environment_preset = "staging"
}

# Development: Minimal security, maximum flexibility
module "feature_flags" {
  source             = "../modules/feature-flags"
  environment_preset = "development"
}
```

### Preset with Overrides

```hcl
module "feature_flags" {
  source             = "../modules/feature-flags"
  environment_preset = "production"
  
  # Override: Disable Macie even in production
  security = {
    macie_enabled = false
  }
  
  # Override: Enable PCI compliance
  compliance = {
    pci_dss_enabled = true
  }
}
```

### Consuming in Other Modules

```hcl
module "security_baseline" {
  source = "../modules/security-baseline"
  
  name = "org-security"
  
  # Reference feature flags
  enable_guardduty       = module.feature_flags.security.guardduty_enabled
  enable_securityhub     = module.feature_flags.security.securityhub_enabled
  enable_config          = module.feature_flags.security.config_enabled
  enable_access_analyzer = module.feature_flags.security.access_analyzer_enabled
  
  config_bucket_name = module.s3_bucket.id
}

module "alerting" {
  source = "../modules/alerting"
  
  name = "org-alerts"
  
  enable_guardduty_events   = module.feature_flags.alerting.guardduty_alerts_enabled
  enable_securityhub_events = module.feature_flags.alerting.securityhub_alerts_enabled
  enable_aws_health_events  = module.feature_flags.alerting.health_alerts_enabled
}
```

## Environment Presets Comparison

| Feature | Production | Staging | Development |
|---------|------------|---------|-------------|
| GuardDuty | ✅ | ✅ | ❌ |
| Security Hub | ✅ | ✅ | ❌ |
| AWS Config | ✅ | ✅ | ❌ |
| CloudTrail | ✅ | ✅ | ❌ |
| Access Analyzer | ✅ | ❌ | ❌ |
| CIS Benchmark | ✅ | ❌ | ❌ |
| MFA Enforcement | ✅ | ❌ | ❌ |
| Permissions Boundary | ✅ | ✅ | ❌ |
| EBS Encryption | ✅ | ✅ | ✅ |
| S3 Block Public | ✅ | ✅ | ❌ |

## Feature Categories

### Security (`var.security`)

Threat detection and data protection services.

| Flag | Default | Description |
|------|---------|-------------|
| `guardduty_enabled` | `false` | Enable GuardDuty threat detection |
| `guardduty_s3_protection` | `true` | GuardDuty S3 data source |
| `guardduty_eks_protection` | `true` | GuardDuty EKS audit logs |
| `guardduty_malware_protection` | `true` | GuardDuty malware scanning |
| `securityhub_enabled` | `false` | Enable Security Hub |
| `config_enabled` | `false` | Enable AWS Config |
| `cloudtrail_enabled` | `false` | Enable CloudTrail |
| `access_analyzer_enabled` | `false` | Enable IAM Access Analyzer |
| `ebs_encryption_default` | `true` | Default EBS encryption |
| `s3_block_public_access` | `true` | Account-level S3 public block |

### Compliance (`var.compliance`)

Compliance frameworks and Config rules.

| Flag | Default | Description |
|------|---------|-------------|
| `cis_benchmark_enabled` | `false` | CIS AWS Foundations Benchmark |
| `aws_foundational_enabled` | `true` | AWS Foundational Security Best Practices |
| `pci_dss_enabled` | `false` | PCI DSS compliance rules |
| `hipaa_enabled` | `false` | HIPAA compliance rules |
| `config_rules_enabled` | `false` | Enable managed Config rules |
| `config_auto_remediation` | `false` | Auto-remediate Config findings |

### IAM (`var.iam`)

Identity and access management policies.

| Flag | Default | Description |
|------|---------|-------------|
| `password_policy_enabled` | `true` | Enable account password policy |
| `password_minimum_length` | `14` | Minimum password length |
| `password_max_age_days` | `90` | Password rotation period |
| `mfa_enforcement_enabled` | `false` | Require MFA for all actions |
| `mfa_grace_period_days` | `0` | Grace period for new users |
| `require_imdsv2` | `true` | Require EC2 IMDSv2 |

### Alerting (`var.alerting`)

Security event notifications.

| Flag | Default | Description |
|------|---------|-------------|
| `guardduty_alerts_enabled` | `true` | Alert on GuardDuty findings |
| `securityhub_alerts_enabled` | `true` | Alert on Security Hub findings |
| `health_alerts_enabled` | `true` | Alert on AWS Health events |
| `guardduty_min_severity` | `4.0` | Minimum GuardDuty severity (0-10) |
| `securityhub_min_severity` | `70` | Minimum Security Hub severity (0-100) |

### Cost (`var.cost`)

Budget and cost management.

| Flag | Default | Description |
|------|---------|-------------|
| `budgets_enabled` | `true` | Enable AWS Budgets |
| `budget_default_limit` | `1000` | Default monthly budget |
| `budget_alert_thresholds` | `[50,80,100]` | Alert threshold percentages |
| `cost_allocation_tags_enabled` | `true` | Enable cost allocation tags |

### Networking (`var.networking`)

VPC and network configuration.

| Flag | Default | Description |
|------|---------|-------------|
| `create_vpc` | `true` | Create tenant VPC |
| `vpc_endpoints_enabled` | `true` | Create VPC endpoints |
| `nat_gateway_enabled` | `true` | Create NAT Gateway |
| `nat_gateway_ha` | `false` | Multi-AZ NAT Gateways |

### Backup (`var.backup`)

AWS Backup configuration.

| Flag | Default | Description |
|------|---------|-------------|
| `backup_enabled` | `false` | Enable AWS Backup |
| `daily_backup_enabled` | `true` | Daily backup schedule |
| `daily_retention_days` | `7` | Daily backup retention |

## Outputs

| Output | Description |
|--------|-------------|
| `security` | Merged security feature flags |
| `compliance` | Merged compliance feature flags |
| `iam` | Merged IAM feature flags |
| `alerting` | Merged alerting feature flags |
| `cost` | Cost management feature flags |
| `networking` | Networking feature flags |
| `backup` | Backup feature flags |
| `environment_preset` | Active preset name |
| `is_production` | Boolean: true if production preset |
| `encryption_required` | Boolean: true if encryption defaults enabled |
| `compliance_strict` | Boolean: true if strict compliance enabled |

## Best Practices

1. **Define Once**: Create feature flags in your root/organization module
2. **Reference Everywhere**: Pass flags to child modules via outputs
3. **Use Presets**: Start with a preset, override as needed
4. **Document Deviations**: Comment why you override preset defaults
5. **Review Regularly**: Periodically review which features are enabled
