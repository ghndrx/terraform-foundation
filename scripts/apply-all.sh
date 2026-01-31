#!/bin/bash
################################################################################
# Apply all Terraform layers in order
# Usage: ./scripts/apply-all.sh [plan|apply|destroy]
################################################################################

set -e

ACTION="${1:-plan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(dirname "$SCRIPT_DIR")/terraform"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Validate action
if [[ ! "$ACTION" =~ ^(plan|apply|destroy)$ ]]; then
    echo -e "${RED}Usage: $0 [plan|apply|destroy]${NC}"
    exit 1
fi

# Check if bootstrap has been run
if [ ! -f "$TF_DIR/00-bootstrap/backend.hcl" ]; then
    echo -e "${YELLOW}Warning: backend.hcl not found. Run bootstrap first:${NC}"
    echo "  cd terraform/00-bootstrap && terraform init && terraform apply"
    
    if [ "$ACTION" != "plan" ]; then
        exit 1
    fi
fi

# Read config from bootstrap if available
if [ -f "$TF_DIR/00-bootstrap/backend.hcl" ]; then
    STATE_BUCKET=$(grep 'bucket' "$TF_DIR/00-bootstrap/backend.hcl" | cut -d'"' -f2)
    REGION=$(grep 'region' "$TF_DIR/00-bootstrap/backend.hcl" | cut -d'"' -f2)
fi

# Determine deployment mode (check if we have organization state)
DEPLOYMENT_MODE="single-account"
if [ -f "$TF_DIR/01-organization/.terraform/terraform.tfstate" ]; then
    DEPLOYMENT_MODE="multi-account"
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Terraform Foundation - ${ACTION}${NC}"
echo -e "${GREEN}Mode: ${DEPLOYMENT_MODE}${NC}"
echo -e "${GREEN}========================================${NC}"

# Define layers based on deployment mode
if [ "$DEPLOYMENT_MODE" = "multi-account" ]; then
    LAYERS=("00-bootstrap" "01-organization" "02-network" "03-platform")
else
    LAYERS=("00-bootstrap" "02-network" "03-platform")
fi

# Reverse for destroy
if [ "$ACTION" = "destroy" ]; then
    echo -e "${RED}⚠️  DESTROYING infrastructure in reverse order${NC}"
    LAYERS=($(printf '%s\n' "${LAYERS[@]}" | tac))
fi

# Process each layer
for layer in "${LAYERS[@]}"; do
    layer_dir="$TF_DIR/$layer"
    
    # Skip if main.tf doesn't exist
    if [ ! -f "$layer_dir/main.tf" ]; then
        echo -e "${YELLOW}Skipping $layer (no main.tf)${NC}"
        continue
    fi
    
    echo ""
    echo -e "${GREEN}>>> Layer: $layer${NC}"
    cd "$layer_dir"
    
    # Initialize
    if [ "$layer" = "00-bootstrap" ]; then
        terraform init -input=false
    else
        terraform init -input=false -backend-config=../00-bootstrap/backend.hcl 2>/dev/null || terraform init -input=false -backend=false
    fi
    
    # Build var args
    VAR_ARGS=""
    if [ -n "$STATE_BUCKET" ] && [ "$layer" != "00-bootstrap" ]; then
        VAR_ARGS="-var=state_bucket=$STATE_BUCKET"
    fi
    
    # Add project_name for platform layer if we can detect it
    if [ "$layer" = "03-platform" ] && [ -n "$STATE_BUCKET" ]; then
        PROJECT_NAME=$(echo "$STATE_BUCKET" | sed 's/-terraform-state$//')
        VAR_ARGS="$VAR_ARGS -var=project_name=$PROJECT_NAME"
    fi
    
    # Execute action
    case $ACTION in
        plan)
            terraform plan $VAR_ARGS
            ;;
        apply)
            terraform apply $VAR_ARGS -auto-approve
            ;;
        destroy)
            terraform destroy $VAR_ARGS -auto-approve
            ;;
    esac
    
    cd - > /dev/null
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

# Process tenants if applying
if [ "$ACTION" = "apply" ]; then
    TENANT_DIRS=$(find "$TF_DIR/04-tenants" -maxdepth 1 -type d ! -name "_template" ! -name "04-tenants" 2>/dev/null)
    if [ -n "$TENANT_DIRS" ]; then
        echo ""
        echo -e "${YELLOW}Tenant directories found. Apply separately:${NC}"
        for tenant_dir in $TENANT_DIRS; do
            tenant=$(basename "$tenant_dir")
            echo "  cd terraform/04-tenants/$tenant && terraform apply -var=\"state_bucket=$STATE_BUCKET\""
        done
    fi
fi
