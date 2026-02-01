#!/bin/bash
################################################################################
# Create a new tenant from template
# Usage: ./scripts/new-tenant.sh <tenant-name>
################################################################################

set -e

TENANT_NAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TF_DIR="$PROJECT_DIR/terraform"
TEMPLATE_DIR="$TF_DIR/04-tenants/_template"
TENANT_DIR="$TF_DIR/04-tenants/$TENANT_NAME"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Validate input
if [ -z "$TENANT_NAME" ]; then
    echo -e "${RED}Usage: $0 <tenant-name>${NC}"
    echo ""
    echo "Tenant name requirements:"
    echo "  - Lowercase letters, numbers, and hyphens only"
    echo "  - 3-20 characters"
    echo "  - Must start with a letter"
    exit 1
fi

# Validate tenant name format
if ! [[ "$TENANT_NAME" =~ ^[a-z][a-z0-9-]{2,19}$ ]]; then
    echo -e "${RED}Invalid tenant name: $TENANT_NAME${NC}"
    echo "Must be 3-20 chars, start with letter, contain only lowercase letters, numbers, hyphens"
    exit 1
fi

# Check if tenant already exists
if [ -d "$TENANT_DIR" ]; then
    echo -e "${RED}Tenant '$TENANT_NAME' already exists at: $TENANT_DIR${NC}"
    exit 1
fi

# Check template exists
if [ ! -f "$TEMPLATE_DIR/main.tf" ]; then
    echo -e "${RED}Template not found at: $TEMPLATE_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}Creating tenant: $TENANT_NAME${NC}"

# Copy template
cp -r "$TEMPLATE_DIR" "$TENANT_DIR"

# Replace placeholders in all files
find "$TENANT_DIR" -type f -name "*.tf" -exec sed -i "s/<TENANT_NAME>/$TENANT_NAME/g" {} \;

echo -e "${GREEN}✓ Created tenant directory: $TENANT_DIR${NC}"

# Show next steps
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo ""
echo "1. Edit the configuration:"
echo "   ${GREEN}vim $TENANT_DIR/main.tf${NC}"
echo ""
echo "   Update these values:"
echo "   - tenant (should be '$TENANT_NAME')"
echo "   - env (prod, staging, dev)"
echo "   - apps (name, port, budget, owner)"
echo "   - budget (monthly total)"
echo "   - alert_emails"
echo ""
echo "2. Initialize and apply:"
echo "   ${GREEN}cd $TENANT_DIR${NC}"
echo "   ${GREEN}terraform init -backend-config=../../00-bootstrap/backend.hcl${NC}"
echo "   ${GREEN}terraform plan -var=\"state_bucket=YOUR_BUCKET\"${NC}"
echo "   ${GREEN}terraform apply -var=\"state_bucket=YOUR_BUCKET\"${NC}"
echo ""
echo "3. (Optional) Create workloads for this tenant:"
echo ""
echo "   ECS Service:"
echo "   ${GREEN}cp -r $TF_DIR/05-workloads/_template/ecs-service $TF_DIR/05-workloads/${TENANT_NAME}-api${NC}"
echo ""
echo "   Lambda Function:"
echo "   ${GREEN}cp -r $TF_DIR/05-workloads/_template/lambda-function $TF_DIR/05-workloads/${TENANT_NAME}-worker${NC}"
echo ""
echo "   RDS Database:"
echo "   ${GREEN}cp -r $TF_DIR/05-workloads/_template/rds-database $TF_DIR/05-workloads/${TENANT_NAME}-db${NC}"
echo ""
