#!/bin/bash
set -e

# Create a new tenant from template
# Usage: ./new-tenant.sh <tenant-name>

if [ -z "$1" ]; then
    echo "Usage: $0 <tenant-name>"
    echo "Example: $0 acme"
    exit 1
fi

TENANT=$1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TENANTS_DIR="$SCRIPT_DIR/../terraform/04-tenants"
TEMPLATE_DIR="$TENANTS_DIR/_template"
TARGET_DIR="$TENANTS_DIR/$TENANT"

# Validate tenant name format
if [[ ! "$TENANT" =~ ^[a-z][a-z0-9-]*$ ]]; then
    echo "Error: Tenant name must start with letter, lowercase alphanumeric + hyphens"
    exit 1
fi

# Validate length (AWS resource names have limits)
if [ ${#TENANT} -gt 20 ]; then
    echo "Error: Tenant name must be 20 characters or less"
    exit 1
fi

# Check if tenant already exists
if [ -d "$TARGET_DIR" ]; then
    echo "Error: Tenant '$TENANT' already exists at $TARGET_DIR"
    exit 1
fi

# Copy template
echo "Creating tenant: $TENANT"
cp -r "$TEMPLATE_DIR" "$TARGET_DIR"

# Replace placeholders (works on both macOS and Linux)
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/<TENANT_NAME>/$TENANT/g" "$TARGET_DIR/main.tf"
else
    sed -i "s/<TENANT_NAME>/$TENANT/g" "$TARGET_DIR/main.tf"
fi

echo ""
echo "✅ Tenant created: $TARGET_DIR"
echo ""
echo "Next steps:"
echo "  1. cd $TARGET_DIR"
echo "  2. Edit main.tf - update:"
echo "     • env (prod, staging, dev)"
echo "     • apps (ports and budgets)"
echo "     • budget (total tenant budget)"
echo "     • alert_emails"
echo ""
echo "  3. Deploy:"
echo "     terraform init -backend-config=../../00-bootstrap/backend.hcl"
echo "     terraform apply -var=\"state_bucket=<YOUR_BUCKET>\""
echo ""
