#!/usr/bin/env bash
# Arm THIS fork's CI (compliance-gate `plan` job + drift-detection) against the sandbox,
# with a PLAN-ONLY identity. Hardened version of labs/06-loop/arm-your-fork.sh:
#
#   upstream lab:  Contributor at mg-grc + Storage Blob Data Contributor on state
#   this repo:     custom "GRC CI Planner" role at mg-grc  = */read + the handful of
#                  POST "read-like" actions terraform refresh needs (list keys/config)
#                  + Storage Blob Data READER on state (plans run with -lock=false)
#
# The CI identity can see everything a plan needs and change nothing. Applies are a
# human act from a reviewed commit (docs/ARCHITECTURE.md, identity boundaries).
# It's still a sensitive identity — listKeys can read the Functions runtime keys —
# which is why its federation names this fork only, and only main + pull_request.
#
# Usage: scripts/arm-ci.sh <github-owner> [repo] [--set-vars]
set -euo pipefail

GH_OWNER="${1:?usage: scripts/arm-ci.sh <github-owner> [repo] [--set-vars]}"
REPO="${2:-cgeaz}"
SET_VARS="${3:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
[ -f "$ROOT/config.env" ] && source "$ROOT/config.env"

SUB_ID=$(az account show --query id -o tsv)
[ -n "${SUBSCRIPTION_ID:-}" ] && [ "$SUB_ID" != "$SUBSCRIPTION_ID" ] && {
  echo "az points at $SUB_ID, config.env declares $SUBSCRIPTION_ID — refusing" >&2; exit 1; }
TENANT_ID=$(az account show --query tenantId -o tsv)
MG_SCOPE="/providers/Microsoft.Management/managementGroups/mg-grc"
APP_NAME="github-${GH_OWNER}-${REPO}-planner"

echo ">> Custom role: GRC CI Planner (assignable at mg-grc)"
ROLE_JSON=$(mktemp)
cat > "$ROLE_JSON" <<JSON
{
  "Name": "GRC CI Planner",
  "Description": "Plan-only identity for the GRC pipeline CI: read everything terraform refresh needs, write nothing.",
  "Actions": [
    "*/read",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Web/sites/config/list/action",
    "Microsoft.DocumentDB/databaseAccounts/listKeys/action",
    "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action",
    "Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action",
    "Microsoft.OperationalInsights/workspaces/sharedKeys/action",
    "Microsoft.ResourceGraph/resources/read"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["$MG_SCOPE"]
}
JSON
if az role definition list --custom-role-only true --scope "$MG_SCOPE" --query "[?roleName=='GRC CI Planner'] | length(@)" -o tsv | grep -q '^1$'; then
  az role definition update --role-definition "$ROLE_JSON" --output none
else
  az role definition create --role-definition "$ROLE_JSON" --output none
fi

echo ">> App registration: $APP_NAME"
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
[ -n "$APP_ID" ] || APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)
APP_OBJ=$(az ad app show --id "$APP_ID" --query id -o tsv)
az ad sp show --id "$APP_ID" --output none 2>/dev/null || az ad sp create --id "$APP_ID" --output none
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

# GitHub now presents immutable-ID subjects (repo:<owner>@<owner_id>/<repo>@<repo_id>:...),
# which also stop a deleted-and-recreated repo with the same name from inheriting this
# federation. Register that form, from the IDs GitHub reports for this repo.
OWNER_ID=$(gh api "repos/${GH_OWNER}/${REPO}" --jq .owner.id)
REPO_ID=$(gh api "repos/${GH_OWNER}/${REPO}" --jq .id)
PREFIX="repo:${GH_OWNER}@${OWNER_ID}/${REPO}@${REPO_ID}"
echo ">> Federated credentials: ${PREFIX} (pull_request, main)"
for sub in "${PREFIX}:pull_request|pr" "${PREFIX}:ref:refs/heads/main|main"; do
  SUBJECT="${sub%|*}"; NAME="${REPO}-${sub#*|}"
  az ad app federated-credential delete --id "$APP_OBJ" --federated-credential-id "$NAME" --output none 2>/dev/null || true
  az ad app federated-credential create --id "$APP_OBJ" --parameters "{
    \"name\": \"${NAME}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none
done

echo ">> Role assignments (retrying while the new role/SP propagate)"
grant() {
  for _ in $(seq 1 12); do
    az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
      --role "$1" --scope "$2" --output none 2>/dev/null && return 0
    sleep 10
  done
  echo "   could not grant $1 at $2" >&2; return 1
}
grant "GRC CI Planner" "$MG_SCOPE"
grant "Storage Blob Data Reader" "/subscriptions/$SUB_ID/resourceGroups/rg-grc-tfstate"

STATE_SA=$(grep storage_account_name "$ROOT/labs/03-foundation/backend.hcl" | cut -d'"' -f2)
DEPLOYER=$(az ad signed-in-user show --query id -o tsv)
TRUSTED="[\"$SP_ID\",\"$APP_ID\"]"

declare -a VARS=(
  "AZURE_CLIENT_ID=$APP_ID"
  "AZURE_TENANT_ID=$TENANT_ID"
  "AZURE_SUBSCRIPTION_ID=$SUB_ID"
  "STATE_STORAGE_ACCOUNT=$STATE_SA"
  "DEPLOYER_OBJECT_ID=$DEPLOYER"
  "TRUSTED_CALLERS=$TRUSTED"
  "OWNER_EMAIL=${OWNER_EMAIL:-<your email>}"
)

if [ "$SET_VARS" = "--set-vars" ]; then
  echo ">> Setting repository variables on ${GH_OWNER}/${REPO}"
  for kv in "${VARS[@]}"; do
    gh variable set "${kv%%=*}" --repo "${GH_OWNER}/${REPO}" --body "${kv#*=}"
  done
else
  echo; echo "Add these repository VARIABLES (not secrets — OIDC stores no credential):"
  for kv in "${VARS[@]}"; do printf '  %-22s %s\n' "${kv%%=*}" "${kv#*=}"; done
fi

cat <<EOF

Then:
  1. Put TRUSTED_CALLERS='$TRUSTED' in config.env and run: scripts/deploy.sh --stages "01"
     (the tripwire stops alerting on CI's own reads-as-writes, e.g. listKeys).
  2. Protect main: require the compliance-gate checks.
EOF
