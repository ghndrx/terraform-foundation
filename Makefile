# Terraform Foundation - Makefile
# Common commands for managing the infrastructure

.PHONY: help init fmt validate plan apply destroy docs clean

# Default target
help:
	@echo "Terraform Foundation - Available Commands"
	@echo ""
	@echo "  make init          Initialize all Terraform layers"
	@echo "  make fmt           Format all Terraform files"
	@echo "  make validate      Validate all configurations"
	@echo "  make plan          Plan all layers (dry run)"
	@echo "  make apply         Apply all layers"
	@echo "  make docs          Generate documentation"
	@echo "  make clean         Clean up local artifacts"
	@echo ""
	@echo "Layer-specific commands:"
	@echo "  make plan-bootstrap"
	@echo "  make plan-org"
	@echo "  make plan-network"
	@echo "  make plan-platform"
	@echo ""
	@echo "Tenant commands:"
	@echo "  make new-tenant NAME=acme"
	@echo "  make plan-tenant NAME=acme"
	@echo "  make apply-tenant NAME=acme"

# Configuration
TF_DIR := terraform
STATE_BUCKET ?= $(shell cat $(TF_DIR)/00-bootstrap/backend.hcl 2>/dev/null | grep bucket | cut -d'"' -f2)
REGION ?= us-east-1

# Initialize all layers
init:
	@echo "Initializing Terraform layers..."
	@cd $(TF_DIR)/00-bootstrap && terraform init
	@if [ -n "$(STATE_BUCKET)" ]; then \
		for dir in 01-organization 02-network 03-platform; do \
			if [ -f "$(TF_DIR)/$$dir/main.tf" ]; then \
				echo "Initializing $$dir..."; \
				cd $(TF_DIR)/$$dir && terraform init -backend-config=../00-bootstrap/backend.hcl; \
				cd - > /dev/null; \
			fi; \
		done; \
	else \
		echo "Note: Run 'make apply-bootstrap' first to configure remote state"; \
	fi

# Format all Terraform files
fmt:
	@echo "Formatting Terraform files..."
	@terraform fmt -recursive $(TF_DIR)

# Validate all configurations
validate: fmt
	@echo "Validating Terraform configurations..."
	@for dir in $(TF_DIR)/00-bootstrap $(TF_DIR)/01-organization $(TF_DIR)/02-network $(TF_DIR)/03-platform; do \
		if [ -f "$$dir/main.tf" ]; then \
			echo "Validating $$dir..."; \
			cd $$dir && terraform init -backend=false -input=false >/dev/null 2>&1 && terraform validate && cd - > /dev/null; \
		fi; \
	done
	@echo "✓ All configurations valid"

# Plan all layers
plan:
	@./scripts/apply-all.sh plan

# Apply all layers
apply:
	@./scripts/apply-all.sh apply

# Destroy (use with caution!)
destroy:
	@echo "⚠️  This will destroy ALL infrastructure!"
	@read -p "Type 'destroy' to confirm: " confirm && [ "$$confirm" = "destroy" ]
	@./scripts/apply-all.sh destroy

# Layer-specific targets
plan-bootstrap:
	@cd $(TF_DIR)/00-bootstrap && terraform plan

apply-bootstrap:
	@cd $(TF_DIR)/00-bootstrap && terraform apply

plan-org:
	@cd $(TF_DIR)/01-organization && terraform plan

apply-org:
	@cd $(TF_DIR)/01-organization && terraform apply

plan-network:
	@cd $(TF_DIR)/02-network && terraform plan -var="state_bucket=$(STATE_BUCKET)"

apply-network:
	@cd $(TF_DIR)/02-network && terraform apply -var="state_bucket=$(STATE_BUCKET)"

plan-platform:
	@cd $(TF_DIR)/03-platform && terraform plan -var="state_bucket=$(STATE_BUCKET)" -var="project_name=$(PROJECT_NAME)"

apply-platform:
	@cd $(TF_DIR)/03-platform && terraform apply -var="state_bucket=$(STATE_BUCKET)" -var="project_name=$(PROJECT_NAME)"

# Tenant commands
new-tenant:
	@if [ -z "$(NAME)" ]; then echo "Usage: make new-tenant NAME=<tenant>"; exit 1; fi
	@./scripts/new-tenant.sh $(NAME)

plan-tenant:
	@if [ -z "$(NAME)" ]; then echo "Usage: make plan-tenant NAME=<tenant>"; exit 1; fi
	@cd $(TF_DIR)/04-tenants/$(NAME) && terraform plan -var="state_bucket=$(STATE_BUCKET)"

apply-tenant:
	@if [ -z "$(NAME)" ]; then echo "Usage: make apply-tenant NAME=<tenant>"; exit 1; fi
	@cd $(TF_DIR)/04-tenants/$(NAME) && terraform apply -var="state_bucket=$(STATE_BUCKET)"

# Generate documentation
docs:
	@echo "Generating documentation..."
	@which terraform-docs > /dev/null 2>&1 || (echo "Install terraform-docs: brew install terraform-docs" && exit 1)
	@for dir in $(TF_DIR)/modules/*; do \
		if [ -d "$$dir" ]; then \
			terraform-docs markdown table $$dir > $$dir/README.md 2>/dev/null || true; \
		fi; \
	done
	@echo "✓ Documentation generated"

# Clean up local artifacts
clean:
	@echo "Cleaning up..."
	@find $(TF_DIR) -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@find $(TF_DIR) -name "*.tfstate*" -type f -delete 2>/dev/null || true
	@find $(TF_DIR) -name ".terraform.lock.hcl" -type f -delete 2>/dev/null || true
	@find $(TF_DIR) -name "tfplan" -type f -delete 2>/dev/null || true
	@find $(TF_DIR) -name "lambda.zip" -type f -delete 2>/dev/null || true
	@echo "✓ Cleanup complete"

# Security scan
security:
	@echo "Running security scan..."
	@which tfsec > /dev/null 2>&1 || (echo "Install tfsec: brew install tfsec" && exit 1)
	@tfsec $(TF_DIR)

# Cost estimate (requires Infracost)
cost:
	@echo "Estimating costs..."
	@which infracost > /dev/null 2>&1 || (echo "Install infracost: brew install infracost" && exit 1)
	@infracost breakdown --path $(TF_DIR)
