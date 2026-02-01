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
- 🚀 **CI/CD Ready** - GitHub Actions workflow included
- 📦 **Workload Templates** - ECS, Lambda, RDS ready to deploy

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
│   └─────────────┘  └─────────────┘  └─────────────┘                │
│                                                                      │
│   Isolation: Security Groups + Tags (ABAC) + IAM                    │
│   Cost: Single NAT Gateway (~$32/mo vs $288 for 3 separate VPCs)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Terraform >= 1.5
- AWS CLI configured with appropriate permissions
- Make (optional, for convenience commands)

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

# 3. Platform (ECR, CI/CD)
cd ../03-platform
terraform init -backend-config=../00-bootstrap/backend.hcl
terraform apply -var="state_bucket=myproject-terraform-state" -var="project_name=myproject"

# 4. Add a tenant
./scripts/new-tenant.sh acme
cd terraform/04-tenants/acme
# Edit main.tf (apps, budgets, emails)
terraform init -backend-config=../../00-bootstrap/backend.hcl
terraform apply -var="state_bucket=myproject-terraform-state"

# 5. Deploy a workload
./scripts/new-workload.sh ecs acme api
cd terraform/05-workloads/acme-api
# Edit main.tf (container image, ports, scaling)
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

# 4. Platform & tenants as above
```

### Using Make

```bash
make help              # Show all commands
make init              # Initialize all layers
make plan              # Plan all layers
make apply             # Apply all layers
make new-tenant NAME=acme
make plan-tenant NAME=acme
```

## Layered Structure

Apply in order — each layer depends on the previous:

```
terraform/
├── 00-bootstrap/       # State bucket, locks, KMS (FIRST)
├── 01-organization/    # AWS Org, OUs, SCPs (multi-account only)
├── 02-network/         # Shared VPC, NAT, subnets
├── 03-platform/        # Shared services: ECR, CodeBuild
├── 04-tenants/         # Per-tenant: SGs, IAM, budgets
│   ├── _template/      # Copy for new tenants
│   ├── acme/
│   └── globex/
├── 05-workloads/       # Actual resources
│   ├── _template/
│   │   ├── ecs-service/
│   │   ├── eks-cluster/
│   │   ├── elasticache-redis/
│   │   ├── lambda-function/
│   │   ├── rds-database/
│   │   ├── sqs-queue/
│   │   └── static-site/
│   ├── acme-api/
│   └── acme-db/
└── modules/            # Reusable modules
    ├── backup-plan/      # AWS Backup automation
    ├── vpc-endpoints/    # PrivateLink endpoints
    └── ...
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

## Workload Templates

### ECS Fargate Service

Full container orchestration with:
- ECS Cluster with Fargate/Fargate Spot
- Application Load Balancer with access logging
- Auto-scaling (CPU/Memory based)
- CloudWatch logging

```bash
./scripts/new-workload.sh ecs <tenant> <app-name>
```

### EKS Kubernetes Cluster

Production-ready Kubernetes with:
- EKS managed node groups (On-Demand & Spot)
- IRSA (IAM Roles for Service Accounts)
- Core addons (VPC CNI, CoreDNS, kube-proxy, EBS CSI)
- IMDSv2 enforced, encrypted EBS volumes
- Cluster Autoscaler & LB Controller ready

```bash
./scripts/new-workload.sh eks <tenant> <cluster-name>
```

### Lambda Function

Serverless functions with:
- API Gateway HTTP API (optional)
- VPC access for database connectivity
- EventBridge scheduled execution
- X-Ray tracing

```bash
./scripts/new-workload.sh lambda <tenant> <function-name>
```

### RDS Database

Managed databases with:
- PostgreSQL, MySQL, or Aurora
- KMS encryption, IAM authentication
- Secrets Manager for credentials
- Enhanced monitoring, Performance Insights

```bash
./scripts/new-workload.sh rds <tenant> <db-name>
```

### ElastiCache Redis

In-memory caching with:
- Redis 7.x replication group
- Encryption at rest and in transit
- Automatic failover (Multi-AZ)
- Auth token in Secrets Manager

```bash
./scripts/new-workload.sh redis <tenant> <cache-name>
```

### SQS Queue

Message queuing with:
- Main queue + dead letter queue
- KMS encryption
- CloudWatch alarms (depth, age, DLQ)
- FIFO support optional

```bash
./scripts/new-workload.sh sqs <tenant> <queue-name>
```

### DynamoDB Table

NoSQL database with:
- On-demand or provisioned capacity
- KMS encryption, point-in-time recovery
- GSI/LSI support, TTL
- Auto-scaling (provisioned mode)

```bash
./scripts/new-workload.sh dynamodb <tenant> <table-name>
```

### EventBridge Event Bus

Event-driven architecture with:
- Custom event bus for tenant isolation
- Event rules with pattern matching
- Dead letter queue, event archiving
- Schema discovery

```bash
./scripts/new-workload.sh eventbus <tenant> <bus-name>
```

### Step Functions Workflow

Serverless orchestration with:
- Standard or Express workflows
- IAM permissions per service
- CloudWatch logging, X-Ray tracing
- API Gateway or EventBridge triggers

```bash
./scripts/new-workload.sh stepfn <tenant> <workflow-name>
```

### Static Site (S3 + CloudFront)

CDN-backed static hosting with:
- S3 bucket (private, OAC access)
- CloudFront with HTTPS
- Security headers (CSP, HSTS, etc.)
- Optional custom domain + ACM

```bash
./scripts/new-workload.sh static <tenant> <site-name>
```

### ECR Repository

Container registry with:
- Lifecycle policies (auto-cleanup old images)
- Cross-account pull/push access
- Multi-region replication
- Image scanning on push

```bash
./scripts/new-workload.sh ecr <tenant> <repo-name>
```

### SNS Topic

Pub/sub messaging with:
- Multiple subscription types (Lambda, SQS, HTTP, Email)
- Message filtering policies
- Dead letter queue for failed deliveries
- FIFO topics for ordered delivery

```bash
./scripts/new-workload.sh sns <tenant> <topic-name>
```

### SSM Parameters

Configuration store with:
- Hierarchical parameter paths
- SecureString for secrets (KMS encrypted)
- Free tier (cheaper than Secrets Manager)
- IAM policies for read/write access

```bash
./scripts/new-workload.sh params <tenant> <config-name>
```

### EventBridge Rules

Event-driven automation with:
- Scheduled rules (cron/rate expressions)
- Event pattern matching (AWS service events)
- Input transformations
- Multiple targets (Lambda, SQS, SNS, Step Functions)

```bash
./scripts/new-workload.sh events <tenant> <rules-name>
```

### Cognito User Pool

Authentication with:
- User signup/signin
- Social identity providers
- MFA (TOTP, SMS)
- Custom UI branding
- App clients for web/mobile

```bash
./scripts/new-workload.sh cognito <tenant> <auth-name>
```

### SES Email

Transactional email with:
- Domain identity verification
- DKIM/SPF/DMARC
- Email templates
- Reputation monitoring
- Bounce/complaint handling

```bash
./scripts/new-workload.sh ses <tenant> <email-name>
```

### API Gateway

REST API with:
- Lambda integration
- Request validation
- Usage plans and API keys
- Custom domain support
- CloudWatch logging

```bash
./scripts/new-workload.sh apigw <tenant> <api-name>
```

## Platform Services (03-platform)

The platform layer provides shared infrastructure:

- **ECR Repositories**: Container registry with lifecycle policies
- **CodeBuild**: Shared build project with VPC access
- **S3 Artifacts**: CI/CD artifact storage with lifecycle rules
- **SSM Parameters**: Centralized configuration store

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

# Create new workload
./scripts/new-workload.sh <ecs|eks|lambda|rds> <tenant> <name>

# Apply all layers in order
./scripts/apply-all.sh plan   # Preview
./scripts/apply-all.sh apply  # Deploy
```

## CI/CD

GitHub Actions workflow included (`.github/workflows/terraform.yml`):

- **On PR**: Format check, validate, security scan, plan (comments on PR)
- **On merge**: Auto-apply (requires `production` environment approval)

Setup:
1. Create an IAM role for GitHub OIDC
2. Add `AWS_ROLE_ARN` to repository secrets
3. Create `production` environment with required reviewers

## Requirements

- Terraform >= 1.5
- AWS CLI configured
- Sufficient IAM permissions (Organizations, IAM, EC2, RDS, etc.)

### Optional Tools

- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanning
- [terraform-docs](https://github.com/terraform-docs/terraform-docs) - Documentation generation
- [infracost](https://www.infracost.io/) - Cost estimation

## Security Controls

Built-in security controls (see [docs/SECURITY.md](docs/SECURITY.md)):

| Control | Implementation |
|---------|----------------|
| **Encryption at rest** | KMS for RDS, EBS, S3, SQS, ElastiCache |
| **Encryption in transit** | TLS enforced on all services |
| **Network isolation** | VPC Flow Logs, private subnets, SG-based tenant isolation |
| **Access logging** | ALB, CloudFront, S3, VPC flow logs → centralized bucket |
| **IMDSv2** | Enforced on all EC2/EKS nodes via SCP + launch template |
| **Tag enforcement** | SCP requires Tenant + Environment tags |
| **Audit protection** | SCP prevents disabling CloudTrail, GuardDuty, Config |

## Reusable Modules

| Module | Purpose |
|--------|---------|
| **alerting** | SNS topics (critical/warning/info), Slack/PagerDuty integration |
| **backup-plan** | AWS Backup with daily/weekly/monthly, cross-region DR |
| **budget-alerts** | Cost budgets with anomaly detection |
| **cloudtrail** | Audit logging with S3, CloudWatch, KMS |
| **cloudwatch-dashboard** | Pre-built metric dashboards |
| **github-oidc** | Secure CI/CD without long-lived credentials |
| **iam-role** | Service, cross-account, and OIDC roles |
| **kms-key** | Customer-managed encryption keys |
| **route53-zone** | Hosted zones with health checks |
| **security-baseline** | GuardDuty, Security Hub, AWS Config, IAM Access Analyzer |
| **vpc-endpoints** | Gateway (S3, DynamoDB) + Interface endpoints |
| **vpc-lite** | Cost-optimized VPC ($0-$32/mo NAT options) |
| **waf-alb** | AWS WAF with managed rules, rate limiting, geo-blocking |

## Terragrunt Support

For DRY multi-environment configuration:

```bash
live/
├── terragrunt.hcl          # Root config
├── prod/
│   ├── env.hcl             # Environment variables
│   └── network/
│       └── terragrunt.hcl
├── staging/
│   └── env.hcl
└── dev/
    └── env.hcl
```

Copy `terragrunt.hcl` to your `live/` directory and customize `env.hcl` per environment.

## Documentation

- [Security Architecture](docs/SECURITY.md) — Encryption, access control, audit logging
- [Cost Optimization](docs/COST-OPTIMIZATION.md) — Savings strategies, right-sizing guide

## Roadmap

- [x] ~~Add 03-platform (shared ECR, CI/CD)~~
- [x] ~~Add 05-workloads templates (ECS, Lambda, RDS, EKS)~~
- [x] ~~Security hardening (KMS, VPC Flow Logs, IMDSv2)~~
- [x] ~~Terragrunt support~~
- [x] ~~Event-driven templates (EventBridge, Step Functions)~~
- [x] ~~Security baseline (GuardDuty, Security Hub, Config)~~
- [x] ~~WAF module for ALB protection~~
- [x] ~~Alerting module (SNS, Slack, PagerDuty)~~
- [ ] GCP/Azure modules (future)
- [ ] Service mesh (AWS App Mesh)
- [ ] Prometheus/Grafana on EKS

## License

MIT

## AI-Assisted Development (MCP Servers)

This repository includes MCP (Model Context Protocol) server configurations for AI-assisted infrastructure development.

### Available MCP Servers

| Server | Purpose |
|--------|---------|
| `terraform` | HashiCorp Terraform Registry integration |
| `awslabs.terraform-mcp-server` | AWS-specific Terraform resources |
| `awslabs.aws-documentation-mcp-server` | Real-time AWS documentation |
| `awslabs.cdk-mcp-server` | AWS CDK best practices |
| `awslabs.core-mcp-server` | Core AWS utilities |
| `awslabs.cost-analysis-mcp-server` | Cost Explorer analysis |
| `awslabs.cloudformation-mcp-server` | CloudFormation operations |

### Setup

1. **Install prerequisites**:
   ```bash
   # Node.js (for HashiCorp MCP server)
   npm install -g npx

   # Python uv (for AWS Labs servers)
   pip install uv
   # or
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Configure your MCP client**:

   For **Claude Code**:
   ```bash
   # Already configured in .mcp.json
   claude-code .
   ```

   For **Cursor**:
   ```bash
   cp .mcp.json .cursor/mcp.json
   ```

   For **VS Code**:
   ```bash
   cp .mcp.json .vscode/mcp.json
   ```

### Usage Examples

With MCP servers enabled, your AI assistant can:

- **Generate Terraform configurations** using latest provider schemas
- **Look up AWS documentation** for service configurations
- **Apply best practices** from AWS Well-Architected Framework
- **Analyze costs** and suggest optimizations
- **Validate security** against AWS security guidelines

```
# Example prompts with MCP
"Create a Terraform module for an ECS service with Fargate"
"What are the latest IAM best practices for GitHub OIDC?"
"Analyze the cost impact of this RDS configuration"
```

### Security Note

MCP servers with AWS credentials (`cost-analysis`, `cloudformation`) are disabled by default. Enable them only when needed and ensure proper IAM permissions.
