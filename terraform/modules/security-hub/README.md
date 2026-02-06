# Security Hub Module

AWS Security Hub for centralized security posture management with alerting and cross-region aggregation.

## Features

- **Multiple Standards**: AWS Foundational, CIS v1.4/v3.0, PCI DSS, NIST 800-53
- **SNS Alerts**: EventBridge-based alerts with severity filtering
- **Cross-Region Aggregation**: Aggregate findings across regions
- **Custom Actions**: Define remediation workflow triggers
- **Built-in Insights**: Pre-configured finding queries
- **Product Integrations**: Inspector, Macie, Detective

## Usage

### Basic

```hcl
module "security_hub" {
  source = "../modules/security-hub"
  name   = "main"

  enable_aws_foundational = true
}
```

### Compliance-Focused

```hcl
module "security_hub" {
  source = "../modules/security-hub"
  name   = "compliance"

  # Standards
  enable_aws_foundational = true
  enable_cis_benchmark    = true
  enable_pci_dss          = true
  enable_nist_800_53      = true

  # Disable noisy controls
  disabled_controls = [
    "EC2.19",  # Default security group
    "IAM.6",   # MFA hardware
  ]

  # Alerting
  enable_sns_alerts = true
  alert_email       = "security@example.com"
  alert_severity    = ["CRITICAL", "HIGH"]

  tags = {
    Environment = "production"
  }
}
```

### Cross-Region Aggregator

```hcl
# Deploy in your primary region (e.g., us-east-1)
module "security_hub" {
  source = "../modules/security-hub"
  name   = "aggregator"

  enable_finding_aggregator = true
  aggregation_regions       = []  # All regions

  enable_sns_alerts = true
  alert_email       = "soc@example.com"
}
```

### Organization Admin

```hcl
module "security_hub" {
  source = "../modules/security-hub"
  name   = "org-hub"

  is_organization_admin            = true
  auto_enable_organization_members = true

  enable_aws_foundational = true
  enable_cis_benchmark    = true

  enable_sns_alerts = true
  alert_email       = "security@example.com"
}
```

### With Custom Actions

```hcl
module "security_hub" {
  source = "../modules/security-hub"
  name   = "main"

  custom_actions = [
    {
      name        = "NotifySlack"
      identifier  = "NotifySlack"
      description = "Send finding to Slack"
    },
    {
      name        = "CreateJiraTicket"
      identifier  = "CreateJira"
      description = "Create Jira ticket for finding"
    }
  ]
}
```

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| name | Name prefix for resources | string | - |
| enable | Enable Security Hub | bool | true |
| auto_enable_controls | Auto-enable new controls | bool | true |
| control_finding_generator | SECURITY_CONTROL or STANDARD_CONTROL | string | "SECURITY_CONTROL" |
| enable_aws_foundational | AWS Foundational Best Practices | bool | true |
| enable_cis_benchmark | CIS Benchmark v1.4 | bool | false |
| enable_cis_benchmark_v3 | CIS Benchmark v3.0 | bool | false |
| enable_pci_dss | PCI DSS v3.2.1 | bool | false |
| enable_nist_800_53 | NIST 800-53 Rev. 5 | bool | false |
| disabled_controls | Control IDs to disable | list(string) | [] |
| enable_sns_alerts | Enable SNS alerts | bool | false |
| alert_email | Email for alerts | string | "" |
| alert_severity | Severities to alert | list(string) | ["CRITICAL", "HIGH"] |
| enable_finding_aggregator | Cross-region aggregation | bool | false |
| aggregation_regions | Regions to aggregate | list(string) | [] |
| is_organization_admin | Org admin account | bool | false |
| custom_actions | Custom action definitions | list(object) | [] |
| enable_inspector | Inspector integration | bool | false |
| enable_macie | Macie integration | bool | false |

## Outputs

| Name | Description |
|------|-------------|
| hub_arn | Security Hub account ARN |
| sns_topic_arn | SNS topic for alerts |
| enabled_standards | List of enabled standards |
| finding_aggregator_arn | Aggregator ARN |
| custom_action_arns | Map of custom action ARNs |
| insight_arns | Map of insight ARNs |

## Built-in Insights

The module creates these pre-configured insights:

1. **Critical Findings** - All critical findings grouped by resource type
2. **Failed Resources** - Resources with compliance failures
3. **Findings by Account** - Finding counts per AWS account

## Severity Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Requires immediate action |
| HIGH | High-priority security issue |
| MEDIUM | Moderate security concern |
| LOW | Minor security issue |
| INFORMATIONAL | No security impact |

## Custom Actions Workflow

1. Define custom action in Terraform
2. Create EventBridge rule targeting the action
3. Route to Lambda/Step Functions for remediation

```hcl
resource "aws_cloudwatch_event_rule" "custom_action" {
  name = "securityhub-notify-slack"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Custom Action"]
    resources   = [module.security_hub.custom_action_arns["NotifySlack"]]
  })
}
```

## Cost Considerations

- **Base**: Per finding ingested
- **Standards**: No additional cost beyond base
- **Aggregation**: Cross-region data transfer costs

See [Security Hub Pricing](https://aws.amazon.com/security-hub/pricing/) for current rates.
