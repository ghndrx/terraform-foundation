# Security Architecture

This document outlines the security controls implemented in this Terraform foundation. These controls align with common compliance frameworks (HIPAA, SOC 2, ISO 27001, HITRUST) without being prescriptive to any specific framework.

## Encryption

### At Rest

| Resource | Encryption | Key Management |
|----------|------------|----------------|
| S3 Buckets | SSE-KMS | Customer-managed KMS keys |
| RDS/Aurora | AES-256 | Customer-managed KMS keys |
| EBS Volumes | AES-256 | Customer-managed KMS keys |
| DynamoDB | AES-256 | Customer-managed KMS keys |
| EKS Secrets | Envelope encryption | Customer-managed KMS keys |
| Secrets Manager | AES-256 | AWS-managed or customer KMS |

### In Transit

| Resource | Protocol | Enforcement |
|----------|----------|-------------|
| S3 | TLS 1.2+ | Bucket policy denies non-HTTPS |
| RDS | TLS 1.2+ | `ca_cert_identifier` configured |
| ALB | TLS 1.2+ | HTTPS listeners with modern policy |
| EKS API | TLS 1.2+ | AWS-managed certificates |

## Access Control

### Network Isolation

```
┌─────────────────────────────────────────────────────────────┐
│                    Shared VPC                                │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  Public Subnet  │  │  Public Subnet  │  ← ALB only       │
│  │    (AZ-a)       │  │    (AZ-b)       │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                    │                             │
│  ┌────────▼────────┐  ┌────────▼────────┐                   │
│  │ Private Subnet  │  │ Private Subnet  │  ← Workloads      │
│  │    (AZ-a)       │  │    (AZ-b)       │    (no public IP) │
│  └─────────────────┘  └─────────────────┘                   │
│                                                              │
│  Default SG: DENY ALL (no rules)                            │
└─────────────────────────────────────────────────────────────┘
```

### Tenant Isolation

1. **Security Groups**: Each tenant has isolated SGs; cross-tenant traffic is denied by default
2. **ABAC (Attribute-Based Access Control)**: IAM policies require `Tenant` tag match
3. **Resource Tagging**: All resources tagged with `Tenant`, `App`, `Environment`

### Identity & Authentication

| Component | Authentication Method |
|-----------|----------------------|
| AWS Console | IAM + MFA (configure separately) |
| EKS Cluster | OIDC + IAM Roles for Service Accounts |
| RDS | Password + IAM Database Authentication |
| Secrets | Secrets Manager with rotation support |

## Audit & Logging

### Log Sources

| Source | Destination | Retention |
|--------|-------------|-----------|
| VPC Flow Logs | CloudWatch Logs | 90 days |
| ALB Access Logs | S3 (logs bucket) | 7 years |
| RDS Audit Logs | CloudWatch Logs | 30 days |
| EKS Control Plane | CloudWatch Logs | 30 days |
| CloudTrail | S3 (configure separately) | 7 years recommended |

### Log Protection

- S3 logs bucket: Versioning enabled, lifecycle to Glacier at 90 days
- CloudWatch Logs: Configurable KMS encryption
- Immutable: S3 Object Lock available (enable for compliance)

## Compute Security

### EKS Nodes

- **IMDSv2 Enforced**: Prevents SSRF-based credential theft
- **Hop Limit = 1**: Containers cannot access node metadata
- **Encrypted EBS**: All node volumes encrypted
- **Private Subnets**: No public IPs on worker nodes

### ECS/Fargate

- **No EC2 Management**: Fargate abstracts host security
- **Task IAM Roles**: Least-privilege per service
- **awsvpc Network Mode**: Each task gets own ENI

### Lambda

- **VPC Optional**: Deploy in VPC for database access
- **X-Ray Tracing**: Request tracking enabled
- **Reserved Concurrency**: Prevent noisy-neighbor DoS

## Data Protection

### Secrets Management

```hcl
# Secrets Manager with automatic rotation
resource "aws_secretsmanager_secret" "db" {
  recovery_window_in_days = 30  # Prod: prevent accidental deletion
}
```

### Database Security

- **No Public Access**: `publicly_accessible = false`
- **Security Group**: Only allows traffic from tenant base SG
- **TLS Required**: Certificate validation enforced
- **IAM Auth**: Token-based authentication available

## Vulnerability Management

### Recommendations

1. **ECR Image Scanning**: Enabled by default (`scan_on_push = true`)
2. **Dependency Scanning**: Use Dependabot or Snyk in CI/CD
3. **tfsec**: Security scanning in GitHub Actions workflow
4. **AWS Inspector**: Enable for EC2/EKS vulnerability assessment

## Incident Response

### Recommendations

1. **GuardDuty**: Enable for threat detection
2. **Security Hub**: Aggregate findings across services
3. **CloudWatch Alarms**: CPU, connections, storage alerts configured
4. **SNS Topics**: Wire alarms to PagerDuty/Slack

## Compliance Mapping

| Control | HIPAA | SOC 2 | ISO 27001 | HITRUST |
|---------|-------|-------|-----------|---------|
| Encryption at rest | ✓ | ✓ | ✓ | ✓ |
| Encryption in transit | ✓ | ✓ | ✓ | ✓ |
| Access logging | ✓ | ✓ | ✓ | ✓ |
| Network isolation | ✓ | ✓ | ✓ | ✓ |
| Least privilege IAM | ✓ | ✓ | ✓ | ✓ |
| Key management | ✓ | ✓ | ✓ | ✓ |

## What's NOT Included (Configure Separately)

- CloudTrail (account-level, usually in audit account)
- AWS Config Rules
- GuardDuty
- Security Hub
- AWS WAF (per-application decision)
- MFA enforcement (IAM policy)
- Password policies (IAM)
- Backup policies (AWS Backup)

## Cost Considerations

Security features with cost impact:

| Feature | Cost Impact | Recommendation |
|---------|-------------|----------------|
| KMS keys | ~$1/mo per key | Use for production |
| VPC Flow Logs | ~$0.50/GB | Enable for compliance |
| Enhanced Monitoring | ~$0.10/instance/mo | Production only |
| Performance Insights | Free (7 days) | Always enable |
| S3 Glacier | ~$0.004/GB/mo | Use for log archival |
