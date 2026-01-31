#!/bin/bash
set -e

# Apply all layers in order
# Usage: ./apply-all.sh [plan|apply]

ACTION=${1:-plan}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="$SCRIPT_DIR/../terraform"

echo "=========================================="
echo "AWS Landing Zone - Layered Deployment"
echo "Action: $ACTION"
echo "=========================================="

# Layer 00: Bootstrap (no backend config needed)
echo ""
echo ">>> Layer 00: Bootstrap"
cd "$TF_DIR/00-bootstrap"
terraform init
terraform $ACTION

if [ "$ACTION" == "apply" ]; then
    STATE_BUCKET=$(terraform output -raw state_bucket)
    echo "State bucket: $STATE_BUCKET"
fi

# Layer 01: Organization
echo ""
echo ">>> Layer 01: Organization"
cd "$TF_DIR/01-organization"
terraform init -backend-config="$TF_DIR/00-bootstrap/backend.hcl"
terraform $ACTION

# Layer 02: Network
echo ""
echo ">>> Layer 02: Network"
cd "$TF_DIR/02-network"
terraform init -backend-config="$TF_DIR/00-bootstrap/backend.hcl"
terraform $ACTION -var="state_bucket=$STATE_BUCKET"

# Layer 03: Platform (if exists)
if [ -f "$TF_DIR/03-platform/main.tf" ]; then
    echo ""
    echo ">>> Layer 03: Platform"
    cd "$TF_DIR/03-platform"
    terraform init -backend-config="$TF_DIR/00-bootstrap/backend.hcl"
    terraform $ACTION -var="state_bucket=$STATE_BUCKET"
fi

# Layer 04: Tenants
echo ""
echo ">>> Layer 04: Tenants"
for tenant_dir in "$TF_DIR/04-tenants"/*/; do
    tenant=$(basename "$tenant_dir")
    if [ "$tenant" != "_template" ] && [ -f "$tenant_dir/main.tf" ]; then
        echo "    Tenant: $tenant"
        cd "$tenant_dir"
        terraform init -backend-config="$TF_DIR/00-bootstrap/backend.hcl"
        terraform $ACTION -var="state_bucket=$STATE_BUCKET"
    fi
done

echo ""
echo "=========================================="
echo "Done!"
echo "=========================================="
