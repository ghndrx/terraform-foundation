# tenant-budget

Terraform module for AWS landing zone pattern.

Create tenant-specific AWS budget alerts.

## Planned Features

- [ ] Monthly budget with configurable limit
- [ ] Multi-threshold alerts (50%, 80%, 100%, 120%)
- [ ] Cost allocation tag filtering
- [ ] SNS and email notifications
- [ ] Forecasted spend alerts
- [ ] Auto-actions at budget limits (optional)

## Planned Usage

```hcl
module "tenant_budget" {
  source = "../modules/tenant-budget"
  
  tenant_name  = "acme-corp"
  budget_limit = 500
  
  alert_thresholds = [50, 80, 100]
  
  notification_emails = [
    "billing@acme.com",
    "admin@acme.com"
  ]
  
  cost_filter_tags = {
    Tenant = "acme-corp"
  }
  
  enable_forecasted_alerts = true
}
```
