# GuardDuty Module

AWS GuardDuty threat detection with alerting, S3 export, and threat intelligence integration.

## Features

- **All Protection Types**: S3, Kubernetes, malware, RDS, Lambda, runtime monitoring
- **SNS Alerts**: EventBridge-based alerts with severity filtering
- **S3 Export**: Archive findings with lifecycle policies
- **Threat Intelligence**: Custom IP sets and threat intel feeds
- **Organization Support**: Delegated admin configuration

## Usage

### Basic

```hcl
module "guardduty" {
  source = "../modules/guardduty"
  name   = "main"
}
```

### With Email Alerts

```hcl
module "guardduty" {
  source = "../modules/guardduty"
  name   = "main"

  enable_sns_alerts        = true
  alert_email              = "security@example.com"
  alert_severity_threshold = "HIGH"  # Only HIGH and CRITICAL
}
```

### Full Security Stack

```hcl
module "guardduty" {
  source = "../modules/guardduty"
  name   = "security-prod"

  # All protections enabled
  enable_s3_protection       = true
  enable_kubernetes_audit    = true
  enable_malware_protection  = true
  enable_rds_login_events    = true
  enable_lambda_network_logs = true
  enable_runtime_monitoring  = true  # Additional cost

  # Alerting
  enable_sns_alerts        = true
  alert_email              = "security@example.com"
  alert_severity_threshold = "MEDIUM"

  # Export for compliance
  enable_s3_export = true

  # Trusted IPs (won't generate findings)
  ipset_cidrs = [
    "10.0.0.0/8",
    "192.168.1.0/24",
  ]

  tags = {
    Environment = "production"
    Team        = "security"
  }
}
```

### Organization Admin

```hcl
module "guardduty" {
  source = "../modules/guardduty"
  name   = "org-guardduty"

  is_organization_admin            = true
  auto_enable_organization_members = true

  enable_sns_alerts = true
  alert_email       = "soc@example.com"
}
```

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| name | Name prefix for resources | string | - |
| enable | Enable GuardDuty detector | bool | true |
| finding_publishing_frequency | Publishing frequency | string | "FIFTEEN_MINUTES" |
| enable_s3_protection | S3 data events monitoring | bool | true |
| enable_kubernetes_audit | EKS audit logs | bool | true |
| enable_malware_protection | EC2/EBS malware scanning | bool | true |
| enable_rds_login_events | RDS login monitoring | bool | true |
| enable_lambda_network_logs | Lambda network activity | bool | true |
| enable_runtime_monitoring | Runtime monitoring ($$) | bool | false |
| enable_sns_alerts | Enable SNS alerts | bool | false |
| alert_email | Email for alerts | string | "" |
| alert_sns_topic_arn | Existing SNS topic | string | "" |
| alert_severity_threshold | Min severity: LOW/MEDIUM/HIGH/CRITICAL | string | "MEDIUM" |
| enable_s3_export | Export findings to S3 | bool | false |
| export_s3_bucket | S3 bucket for export | string | "" |
| ipset_cidrs | Trusted IP CIDRs | list(string) | [] |
| threat_intel_feed_urls | Threat intel feed URLs | list(string) | [] |
| is_organization_admin | Delegated admin account | bool | false |

## Outputs

| Name | Description |
|------|-------------|
| detector_id | GuardDuty detector ID |
| detector_arn | GuardDuty detector ARN |
| sns_topic_arn | SNS topic for alerts |
| export_bucket | S3 bucket for findings |
| eventbridge_rule_arn | EventBridge rule ARN |
| enabled_features | Map of enabled features |

## Severity Levels

| Level | Numeric Range | Example Finding Types |
|-------|--------------|----------------------|
| LOW | 1.0 - 3.9 | Info gathering, unusual activity |
| MEDIUM | 4.0 - 6.9 | Potentially malicious activity |
| HIGH | 7.0 - 8.9 | Compromised resources, active threats |
| CRITICAL | 9.0+ | Confirmed breaches, exfiltration |

## Cost Considerations

- **Base**: Charged per GB of VPC Flow Logs, DNS logs, CloudTrail events
- **S3 Protection**: Per S3 event analyzed
- **EKS Audit Logs**: Per EKS audit log event
- **Malware Protection**: Per GB scanned
- **Runtime Monitoring**: Per vCPU-hour monitored
- **S3 Export**: Standard S3 storage costs

See [GuardDuty Pricing](https://aws.amazon.com/guardduty/pricing/) for current rates.
