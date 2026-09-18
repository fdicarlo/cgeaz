#!/usr/bin/env bash
# Bootstrap the Terraform remote-state storage for the CGE-AZ pipeline.
# Run once, before your first `terraform init` in stages/01-foundation.
# Chicken-and-egg: state storage can't manage itself, so this one piece is a script.
#
# State is audit-relevant (it records who changed governance, and holds resource
# attributes), so the state account is held to the evidence store's standard:
#   - Entra ID only: shared-key access disabled, so there is no account key to leak
#   - versioning + 30-day blob and container soft delete: every state write recoverable
#   - TLS 1.2+, no public blob access
#   - CanNotDelete lock on the resource group: a stray `az group delete` can't take it
# Idempotent: safe to re-run.
set -euo pipefail

LOCATION="${LOCATION:-eastus}"
RG_STATE="rg-grc-tfstate"
# Storage account names are globally unique, lowercase, <=24 chars.
# We derive a stable suffix from your subscription ID so re-runs are idempotent.
SUB_ID="${ARM_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"
SUFFIX=$(echo "$SUB_ID" | tr -d '-' | cut -c1-8)
SA_NAME="stgrctfstate${SUFFIX}"
CONTAINER="tfstate"

echo ">> Subscription: $SUB_ID"
echo ">> State resource group: $RG_STATE"
az group create --subscription "$SUB_ID" --name "$RG_STATE" --location "$LOCATION" \
  --tags env=shared purpose=terraform-state --output none

echo ">> State storage account: $SA_NAME (Entra-only, versioned, no public blob access)"
az storage account create \
  --subscription "$SUB_ID" \
  --name "$SA_NAME" \
  --resource-group "$RG_STATE" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --allow-shared-key-access false \
  --https-only true \
  --tags env=shared purpose=terraform-state \
  --output none

echo ">> Versioning + 30-day soft delete (every state change becomes a recoverable version)"
az storage account blob-service-properties update \
  --subscription "$SUB_ID" \
  --account-name "$SA_NAME" \
  --resource-group "$RG_STATE" \
  --enable-versioning true \
  --enable-delete-retention true --delete-retention-days 30 \
  --enable-container-delete-retention true --container-delete-retention-days 30 \
  --output none

# Terraform reads/writes state over the blob DATA plane (use_azuread_auth = true).
# Owner on the subscription is a CONTROL-plane role and does NOT include data actions,
# so grant yourself Storage Blob Data Contributor explicitly. (This is the control-plane
# vs data-plane split from lesson 01_02, biting in real life.) With shared keys off,
# even creating the container needs this role, so it comes first.
echo ">> Granting you Storage Blob Data Contributor on the state resource group"
ME=$(az ad signed-in-user show --query id -o tsv)
az role assignment create \
  --assignee-object-id "$ME" \
  --assignee-principal-type User \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/$SUB_ID/resourceGroups/$RG_STATE" \
  --output none 2>/dev/null || echo "   (already granted)"

echo ">> State container: $CONTAINER (retrying while the role grant propagates, ~1-3 min)"
for i in $(seq 1 20); do
  if az storage container create --name "$CONTAINER" --account-name "$SA_NAME" \
       --auth-mode login --output none 2>/dev/null; then
    echo "   container ready"; break
  fi
  [ "$i" -eq 20 ] && { echo "   container create still failing after ~5 min; re-run this script" >&2; exit 1; }
  sleep 15
done

echo ">> CanNotDelete lock on $RG_STATE"
az lock create --subscription "$SUB_ID" --name lock-tfstate --lock-type CanNotDelete \
  --resource-group "$RG_STATE" \
  --notes "Terraform state for the GRC pipeline. Remove deliberately at course end." \
  --output none

BACKEND_FILE="$(dirname "$0")/backend.hcl"
cat > "$BACKEND_FILE" <<EOF
resource_group_name  = "$RG_STATE"
storage_account_name = "$SA_NAME"
container_name       = "$CONTAINER"
EOF

cat <<EOF

Bootstrap complete. Backend config written to: $BACKEND_FILE

Next, from any stage directory (e.g. stages/01-foundation):

  export TF_VAR_subscription_id=$SUB_ID
  terraform init -backend-config=../../labs/03-foundation/backend.hcl

(or run scripts/deploy.sh from the repo root, which does every stage in order)
EOF
