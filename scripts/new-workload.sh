#!/bin/bash
################################################################################
# Create a new workload from template
# Usage: ./scripts/new-workload.sh <type> <tenant> <name>
#
# Types: ecs, lambda, rds
################################################################################

set -e

TYPE="$1"
TENANT="$2"
NAME="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TF_DIR="$PROJECT_DIR/terraform"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Show usage
usage() {
    echo "Usage: $0 <type> <tenant> <name>"
    echo ""
    echo "Compute:"
    echo "  ecs        - ECS Fargate service with ALB"
    echo "  eks        - EKS Kubernetes cluster"
    echo "  lambda     - Lambda function with API Gateway"
    echo ""
    echo "Data:"
    echo "  rds        - RDS database (PostgreSQL/MySQL/Aurora)"
    echo "  dynamodb   - DynamoDB NoSQL table"
    echo "  redis      - ElastiCache Redis cluster"
    echo "  s3         - S3 bucket (data lake, backups, media)"
    echo ""
    echo "API & Messaging:"
    echo "  apigw      - API Gateway REST API"
    echo "  sqs        - SQS queue with DLQ"
    echo "  eventbus   - EventBridge custom event bus"
    echo "  stepfn     - Step Functions workflow"
    echo ""
    echo "Auth & Email:"
    echo "  cognito    - Cognito User Pool (auth)"
    echo "  ses        - SES email (transactional/marketing)"
    echo ""
    echo "Web:"
    echo "  static     - Static site (S3 + CloudFront)"
    echo ""
    echo "Examples:"
    echo "  $0 ecs acme api"
    echo "  $0 rds acme main"
    echo "  $0 dynamodb acme orders"
    echo "  $0 eventbus acme events"
    echo "  $0 stepfn acme order-processor"
    exit 1
}

# Validate input
if [ -z "$TYPE" ] || [ -z "$TENANT" ] || [ -z "$NAME" ]; then
    usage
fi

# Map type to template directory
case $TYPE in
    ecs)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/ecs-service"
        ;;
    eks)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/eks-cluster"
        ;;
    lambda)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/lambda-function"
        ;;
    rds)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/rds-database"
        ;;
    dynamodb)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/dynamodb-table"
        ;;
    redis)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/elasticache-redis"
        ;;
    s3)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/s3-bucket"
        ;;
    cognito)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/cognito-auth"
        ;;
    ses)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/ses-email"
        ;;
    apigw)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/api-gateway"
        ;;
    sqs)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/sqs-queue"
        ;;
    eventbus)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/eventbridge-bus"
        ;;
    stepfn)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/step-function"
        ;;
    static)
        TEMPLATE_DIR="$TF_DIR/05-workloads/_template/static-site"
        ;;
    *)
        echo -e "${RED}Unknown type: $TYPE${NC}"
        usage
        ;;
esac

WORKLOAD_NAME="${TENANT}-${NAME}"
WORKLOAD_DIR="$TF_DIR/05-workloads/$WORKLOAD_NAME"

# Check if workload already exists
if [ -d "$WORKLOAD_DIR" ]; then
    echo -e "${RED}Workload '$WORKLOAD_NAME' already exists at: $WORKLOAD_DIR${NC}"
    exit 1
fi

# Check template exists
if [ ! -f "$TEMPLATE_DIR/main.tf" ]; then
    echo -e "${RED}Template not found at: $TEMPLATE_DIR${NC}"
    exit 1
fi

# Check tenant exists
if [ ! -d "$TF_DIR/04-tenants/$TENANT" ] && [ "$TENANT" != "_template" ]; then
    echo -e "${YELLOW}Warning: Tenant '$TENANT' doesn't exist yet.${NC}"
    echo "Create it first: ./scripts/new-tenant.sh $TENANT"
    echo ""
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${GREEN}Creating workload: $WORKLOAD_NAME (type: $TYPE)${NC}"

# Copy template
cp -r "$TEMPLATE_DIR" "$WORKLOAD_DIR"

# Replace placeholders
find "$WORKLOAD_DIR" -type f -name "*.tf" -exec sed -i "s/<TENANT>/$TENANT/g" {} \;
find "$WORKLOAD_DIR" -type f -name "*.tf" -exec sed -i "s/<APP>/$NAME/g" {} \;

echo -e "${GREEN}✓ Created workload directory: $WORKLOAD_DIR${NC}"

# Type-specific instructions
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo ""
echo "1. Edit the configuration:"
echo "   ${GREEN}vim $WORKLOAD_DIR/main.tf${NC}"
echo ""

case $TYPE in
    ecs)
        echo "   Update these values:"
        echo "   - container_image (ECR URL)"
        echo "   - container_port"
        echo "   - cpu, memory"
        echo "   - desired_count, min_count, max_count"
        echo "   - environment variables"
        echo "   - secrets (ARNs)"
        ;;
    eks)
        echo "   Update these values:"
        echo "   - cluster_version (1.29, 1.30, etc.)"
        echo "   - node_groups (instance types, scaling config)"
        echo "   - enable_fargate (for serverless pods)"
        echo "   - admin_arns (IAM principals for cluster access)"
        echo "   - cluster_endpoint_public (false for private-only)"
        echo ""
        echo "   After apply, configure kubectl:"
        echo "   aws eks update-kubeconfig --name ${TENANT}-prod"
        ;;
    lambda)
        echo "   Update these values:"
        echo "   - runtime (python3.12, nodejs20.x, etc.)"
        echo "   - handler"
        echo "   - source_dir OR s3_bucket/s3_key OR image_uri"
        echo "   - enable_vpc (true for database access)"
        echo "   - enable_api (true for HTTP endpoint)"
        echo "   - schedule_expression (for cron jobs)"
        ;;
    rds)
        echo "   Update these values:"
        echo "   - engine (postgres, mysql, aurora-postgresql)"
        echo "   - engine_version"
        echo "   - instance_class"
        echo "   - storage_gb"
        echo "   - multi_az (true for prod)"
        ;;
    redis)
        echo "   Update these values:"
        echo "   - engine_version (7.1, 7.0, etc.)"
        echo "   - node_type (cache.t3.micro, cache.r6g.large)"
        echo "   - num_cache_clusters (2 for Multi-AZ)"
        echo "   - maxmemory_policy (volatile-lru, allkeys-lru)"
        ;;
    s3)
        echo "   Update these values:"
        echo "   - lifecycle_rules (tiering, expiration)"
        echo "   - enable_replication (cross-region DR)"
        echo "   - lambda_notifications (event triggers)"
        echo "   - cors_enabled (for web access)"
        ;;
    cognito)
        echo "   Update these values:"
        echo "   - app_clients (web, mobile, m2m)"
        echo "   - password policy, MFA settings"
        echo "   - social_providers (Google, Facebook)"
        echo "   - custom_domain, lambda_triggers"
        ;;
    ses)
        echo "   Update these values:"
        echo "   - domain, hosted_zone_id"
        echo "   - email_identities (sender addresses)"
        echo "   - tracking_options (open/click tracking)"
        echo "   - DMARC policy"
        ;;
    apigw)
        echo "   Update these values:"
        echo "   - lambda_integrations (path -> Lambda ARN)"
        echo "   - domain_name, hosted_zone_id (custom domain)"
        echo "   - usage_plans (quota/throttle)"
        echo "   - cors_origins (CORS allowed origins)"
        ;;
    sqs)
        echo "   Update these values:"
        echo "   - fifo_queue (true for exactly-once processing)"
        echo "   - visibility_timeout_seconds"
        echo "   - max_receive_count (DLQ threshold)"
        echo "   - message_retention_seconds"
        ;;
    dynamodb)
        echo "   Update these values:"
        echo "   - hash_key, range_key (primary key)"
        echo "   - billing_mode (PAY_PER_REQUEST or PROVISIONED)"
        echo "   - global_secondary_indexes"
        echo "   - ttl_attribute (for auto-expiry)"
        ;;
    eventbus)
        echo "   Update these values:"
        echo "   - event_rules (pattern matching and targets)"
        echo "   - enable_archive (for event replay)"
        echo "   - allowed_source_accounts (cross-account)"
        ;;
    stepfn)
        echo "   Update these values:"
        echo "   - state_machine_definition (workflow JSON)"
        echo "   - type (STANDARD or EXPRESS)"
        echo "   - lambda_arns, dynamodb_arns, etc. (permissions)"
        echo "   - schedule_expression (for scheduled runs)"
        ;;
    static)
        echo "   Update these values:"
        echo "   - domain_name (e.g., www.example.com)"
        echo "   - hosted_zone_id (Route53 zone)"
        echo "   - price_class (PriceClass_100 cheapest)"
        echo ""
        echo "   Deploy content:"
        echo "   aws s3 sync ./dist s3://BUCKET --delete"
        ;;
esac

echo ""
echo "2. Initialize and apply:"
echo "   ${GREEN}cd $WORKLOAD_DIR${NC}"
echo "   ${GREEN}terraform init -backend-config=../../00-bootstrap/backend.hcl${NC}"
echo "   ${GREEN}terraform plan -var=\"state_bucket=YOUR_BUCKET\"${NC}"
echo "   ${GREEN}terraform apply -var=\"state_bucket=YOUR_BUCKET\"${NC}"
echo ""
