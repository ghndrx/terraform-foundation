# Terraform Foundation

![Terraform](https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=flat&logo=terraform)
![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?style=flat&logo=amazon-aws)
![License](https://img.shields.io/badge/License-MIT-blue)

Enterprise-grade cloud foundation with multi-tenancy, designed to scale from startup to enterprise.

## Features

- 🏢 **Multi-tenancy** - Logical tenant isolation via tags & ABAC
- 💰 **Cost optimized** - Single shared VPC, one NAT Gateway
- 🔒 **Security** - SCPs, tag enforcement, tenant-scoped IAM
- 📊 **Billing** - Per-tenant and per-app budget alerts
- 🎚️ **Flexible** - Single-account or multi-account deployment

## Deployment Modes

| Mode | Accounts | Best For | Cost |
|------|----------|----------|------|
| **single-account** | 1 | Startups, POCs, small teams | $ |
| **multi-account** | 1 per env (prod/staging/dev) | Growing companies, compliance | $$ |

Both modes use the same tenant isolation pattern (tags + ABAC + security groups).

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Shared VPC                                   │
│                                                                      │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│   │  Tenant A   │  │  Tenant B   │  │  Tenant C   │                │
│   │  SG: A-*    │  │  SG: B-*    │  │  SG: C-*    │                │
│   │  Tag: A     │  │  Tag: B     │  │  Tag: C     │                │
│   └─────────────┘  └─────────────┘  └─────────────┘                │
│                                                                      │
│   Isolation: Security Groups + Tags (ABAC) + IAM                    │
│   Cost: Single NAT Gateway (~$32/mo vs $288 for 3 separate VPCs)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Single-Account Mode (Fastest)

```bash
# 1. Bootstrap
cd terraform/00-bootstrap
terraform init
terraform apply -var="project_name=myproject" -var="deployment_mode=single-account"

# 2. Network (skip 01-organization in single-account mode)
cd ../02-network
terraform init -backend-config=../00-bootstrap/backend.hcl
terraform apply -var="state_bucket=myproject-terraform-state"

# 3. Add a tenant
./scripts/new-tenant.sh acme
cd terraform/04-tenants/acme
# Edit main.tf (apps, budgets, emails)
terraform init -backend-config=../../00-bootstrap/backend.hcl
terraform apply -var="state_bucket=myproject-terraform-state"
```

### Multi-Account Mode (Enterprise)

```bash
# 1. Bootstrap
cd terraform/00-bootstrap
terraform init
terraform apply -var="project_name=myorg" -var="deployment_mode=multi-account"

# 2. Organization (creates AWS Org, OUs, core accounts)
cd ../01-organization
terraform init -backend-config=../00-bootstrap/backend.hcl
terraform apply

# 3. Network (VPC in dedicated network account)
cd ../02-network
terraform init -backend-config=../00-bootstrap/backend.hcl
terraform apply -var="state_bucket=myorg-terraform-state" -var="deployment_mode=multi-account"

# 4. Add tenants as above
```

## Layered Structure

Apply in order — each layer depends on the previous:

```
terraform/
├── 00-bootstrap/       # State bucket, locks, KMS (FIRST)
├── 01-organization/    # AWS Org, OUs, SCPs (multi-account only)
├── 02-network/         # Shared VPC, NAT, subnets
├── 03-platform/        # Shared services: CI/CD, ECR (optional)
├── 04-tenants/         # Per-tenant: SGs, IAM, budgets
│   ├── _template/      # Copy for new tenants
│   ├── acme/
│   └── globex/
└── 05-workloads/       # Actual resources: ECS, RDS, Lambda
```

## Tenant Isolation

### Security Groups

Each tenant gets isolated SGs that **only allow intra-tenant traffic**:

```
acme-prod-base-sg     → Self-referencing (acme can talk to acme)
acme-prod-web-sg      → 443/80 from internet
acme-prod-app-sg      → 8080 from acme-base only
acme-prod-db-sg       → 5432 from acme-base only

❌ globex-* cannot reach acme-* (no SG rules allow it)
```

### ABAC (Attribute-Based Access Control)

IAM roles are scoped to tenant by tag:

```hcl
# acme-admin can ONLY touch resources tagged Tenant=acme
Condition = {
  StringEquals = {
    "aws:ResourceTag/Tenant" = "acme"
  }
}

# Must tag new resources correctly
Condition = {
  StringEquals = {
    "aws:RequestTag/Tenant" = "acme"
  }
}
```

### Budgets

- **Tenant budget**: Total spend for all apps
- **App budgets**: Per-app limits
- **Alerts**: 50%, 80%, 100% thresholds → email

## Cost Savings

| Setup | NAT Gateways | Est. Monthly |
|-------|--------------|--------------|
| VPC per tenant (3 tenants, 3 AZ) | 9 | ~$288 |
| **Shared VPC (1 NAT)** | 1 | ~$32 |
| **Savings** | | **~$256/mo** |

## Scripts

```bash
# Create new tenant
./scripts/new-tenant.sh <name>

# Apply all layers in order
./scripts/apply-all.sh plan   # Preview
./scripts/apply-all.sh apply  # Deploy
```

## Requirements

- Terraform >= 1.5
- AWS CLI configured
- Sufficient IAM permissions (Organizations, IAM, EC2, etc.)

## Roadmap

- [ ] Add 03-platform (shared ECR, CI/CD)
- [ ] Add 05-workloads templates (ECS, Lambda, RDS)
- [ ] Terragrunt support
- [ ] GCP/Azure modules (future)

## License

MIT
