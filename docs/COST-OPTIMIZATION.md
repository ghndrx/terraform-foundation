# Cost Optimization Guide

This document outlines cost-saving strategies implemented in this foundation and recommendations for further optimization.

## Built-In Cost Savings

### 1. Shared VPC Architecture

**Savings: ~$256/month per 3 tenants**

| Approach | NAT Gateways | Monthly Cost |
|----------|--------------|--------------|
| VPC per tenant (3 tenants, 2 AZ) | 6 | ~$192 |
| **Shared VPC (single NAT)** | 1 | ~$32 |

The shared VPC with tenant isolation via security groups provides the same logical separation at a fraction of the cost.

### 2. Single NAT Gateway

For non-production or cost-sensitive workloads:

```hcl
# terraform/02-network/main.tf
variable "enable_nat" {
  default = true  # Set to false to save ~$32/mo (no private subnet egress)
}
```

**Alternative**: NAT Instance (~$3/mo for t4g.nano) for dev environments.

### 3. GP3 Storage (Default)

All EBS and RDS storage uses GP3:
- 20% cheaper than GP2
- 3,000 IOPS included (vs 100 IOPS/GB for GP2)
- Configurable IOPS and throughput

### 4. Fargate Spot (ECS)

```hcl
# Configured in ECS template
default_capacity_provider_strategy {
  base              = 1      # 1 On-Demand for availability
  weight            = 100
  capacity_provider = "FARGATE"  # Change to FARGATE_SPOT for 70% savings
}
```

**Savings**: Up to 70% on Fargate compute.

### 5. EKS Spot Instances

```hcl
# Uncomment in EKS template
node_groups = {
  spot = {
    instance_types = ["t3.medium", "t3.large", "t3a.medium"]  # Diversify!
    capacity_type  = "SPOT"
    # ...
  }
}
```

**Savings**: Up to 90% on EC2 compute.

### 6. S3 Intelligent-Tiering

For logs bucket (already configured):

```hcl
lifecycle_configuration {
  rule {
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = 2555  # 7 years
    }
  }
}
```

### 7. CloudWatch Log Retention

All log groups configured with retention (default 30 days):

```hcl
retention_in_days = 30  # Adjust based on compliance needs
```

**Cost**: ~$0.03/GB/month for ingestion + storage.

## Recommendations

### Compute Right-Sizing

1. **Start Small**: Use `t3.micro` or `t3.small` for non-prod
2. **Monitor**: Use CloudWatch Container Insights / Compute Optimizer
3. **Scale Down**: Reduce replica counts in dev/staging

### Reserved Capacity

| Resource | Savings | Commitment |
|----------|---------|------------|
| EC2 Reserved | 30-72% | 1-3 years |
| RDS Reserved | 30-60% | 1-3 years |
| Savings Plans (Compute) | 20-66% | 1-3 years |
| ElastiCache Reserved | 30-55% | 1-3 years |

**Recommendation**: After 3 months of stable usage, purchase Compute Savings Plans.

### Database Optimization

1. **Aurora Serverless v2**: For variable workloads (scales to 0.5 ACU)
2. **RDS Proxy**: Pool connections, reduce instance size
3. **Read Replicas**: Only for read-heavy workloads
4. **Stop Dev Databases**: Use Lambda to stop/start on schedule

```hcl
# Example: Smaller dev database
locals {
  instance_class = local.env == "prod" ? "db.r6g.large" : "db.t3.micro"
}
```

### Networking

1. **VPC Endpoints**: For S3, ECR, Secrets Manager (~$7/mo each, but saves NAT costs)
2. **PrivateLink**: For high-volume AWS service access
3. **CloudFront**: Cache static content, reduce origin load

### Monitoring Cost Control

```hcl
# Reduce metric granularity in non-prod
enhanced_monitoring_interval = local.env == "prod" ? 60 : 0

# Disable Performance Insights in dev
performance_insights = local.env != "dev"
```

### EKS Specific

1. **Karpenter**: Better bin-packing than Cluster Autoscaler
2. **Bottlerocket OS**: Smaller footprint, faster boot
3. **Fargate for Batch**: No idle nodes

## Cost Monitoring

### AWS Tools

1. **Cost Explorer**: Built-in, tag-based analysis
2. **Budgets**: Already configured per-tenant
3. **Cost Anomaly Detection**: ML-based alerts

### Third-Party

1. **Infracost**: PR-level cost estimation (in Makefile)
2. **Kubecost**: Kubernetes cost allocation
3. **Spot.io**: Spot instance management

## Environment-Based Defaults

```hcl
locals {
  # Automatically scale down non-prod
  instance_class = {
    prod    = "db.r6g.large"
    staging = "db.t3.small"
    dev     = "db.t3.micro"
  }[local.env]

  desired_count = {
    prod    = 3
    staging = 2
    dev     = 1
  }[local.env]

  multi_az = local.env == "prod"
}
```

## Estimated Monthly Costs

### Minimal Setup (Dev/POC)

| Resource | Spec | Est. Cost |
|----------|------|-----------|
| NAT Gateway | 1 | $32 |
| RDS | db.t3.micro | $13 |
| ECS Fargate | 0.25 vCPU, 0.5GB x 2 | $15 |
| ALB | 1 | $16 |
| S3 + CloudWatch | Minimal | $5 |
| **Total** | | **~$80/mo** |

### Production (Small)

| Resource | Spec | Est. Cost |
|----------|------|-----------|
| NAT Gateway | 1 | $32 |
| RDS | db.r6g.large, Multi-AZ | $350 |
| ECS Fargate | 1 vCPU, 2GB x 4 | $120 |
| ALB | 1 | $25 |
| EKS | Control plane | $73 |
| EKS Nodes | 2x t3.medium | $60 |
| S3 + CloudWatch | Moderate | $30 |
| **Total** | | **~$690/mo** |

### Production (With Savings Plans)

Same as above with 1-year Compute Savings Plan: **~$480/mo** (30% savings)
