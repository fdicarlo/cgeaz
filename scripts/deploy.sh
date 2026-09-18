#!/usr/bin/env bash
# Deploy the whole pipeline from an empty subscription, in stage order:
#
#   bootstrap state -> 01 foundation -> 02 activation -> 03 evidence store
#   -> 04 reporting -> 06 enforcement (dry-run) -> function code -> catalog seed
#   -> first collection + first reports
#
# Usage:  scripts/deploy.sh                 # everything, interactive approvals
#         scripts/deploy.sh --yes           # auto-approve applies
#         scripts/deploy.sh --stages "01"   # re-apply only these stages (e.g. after arming CI)
#         scripts/deploy.sh --code-only     # redeploy Function code + seed catalog
#
# Every step is idempotent: re-running converges, it never duplicates.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APPROVE=""
STAGES="01-foundation 02-activation 03-evidence-store 04-reporting 06-enforcement"
CODE=1; INFRA=1
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) APPROVE="-auto-approve" ;;
    --stages) shift; STAGES=""; for s in $1; do for d in stages/"${s}"*/; do STAGES="$STAGES $(basename "$d")"; done; done; CODE=0 ;;
    --code-only) INFRA=0 ;;
    *) echo "unknown flag $1" >&2; exit 2 ;;
  esac
  shift
done

[ -f config.env ] || { echo "config.env missing: cp config.env.example config.env and fill it in" >&2; exit 1; }
# shellcheck disable=SC1091
source config.env

# --- Guard: never touch a subscription other than the declared sandbox ---
CURRENT=$(az account show --query id -o tsv)
if [ "$CURRENT" != "$SUBSCRIPTION_ID" ]; then
  echo "az is pointed at $CURRENT but config.env declares $SUBSCRIPTION_ID." >&2
  echo "Run: az account set --subscription $SUBSCRIPTION_ID   (refusing to continue)" >&2
  exit 1
fi
echo ">> Target: $(az account show --query '[name, id]' -o tsv | paste -sd' ' -)"

export ARM_SUBSCRIPTION_ID="$SUBSCRIPTION_ID"
export TF_VAR_subscription_id="$SUBSCRIPTION_ID"
export TF_VAR_owner_email="$OWNER_EMAIL"
export TF_VAR_trusted_automation_callers="${TRUSTED_CALLERS:-[]}"
export TF_VAR_deployer_object_id; TF_VAR_deployer_object_id=$(az ad signed-in-user show --query id -o tsv)
export LOCATION

apply_stage() {
  local stage="$1"; shift
  echo; echo "================ stages/$stage ================"
  terraform -chdir="stages/$stage" init -input=false -reconfigure \
    -backend-config="$ROOT/labs/03-foundation/backend.hcl" >/dev/null
  terraform -chdir="stages/$stage" apply -input=false $APPROVE "$@"
}

if [ "$INFRA" = 1 ]; then
  if [ "$CODE" = 1 ]; then
    echo ">> Registering resource providers (fresh subscriptions have almost none: F1)"
    for ns in Microsoft.Management Microsoft.OperationalInsights Microsoft.Security \
              Microsoft.DocumentDB Microsoft.Web Microsoft.Storage Microsoft.Insights \
              Microsoft.PolicyInsights Microsoft.ResourceGraph Microsoft.Consumption \
              Microsoft.CostManagement Microsoft.AlertsManagement Microsoft.ManagedIdentity; do
      az provider register --namespace "$ns" --output none
    done
    until [ -z "$(az provider list --query "[?registrationState=='Registering'].namespace" -o tsv)" ]; do
      echo "   waiting for provider registration..."; sleep 15
    done
    LOCATION="$LOCATION" labs/03-foundation/bootstrap.sh
  fi
  export TF_VAR_state_storage_account
  TF_VAR_state_storage_account=$(grep storage_account_name labs/03-foundation/backend.hcl | cut -d'"' -f2)

  for stage in $STAGES; do
    case "$stage" in
      01-foundation)     apply_stage "$stage" -var "location=$LOCATION" ;;
      03-evidence-store) apply_stage "$stage" -var "location=$EVIDENCE_LOCATION" -var "functions_location=$FUNCTIONS_LOCATION" ;;
      04-reporting)      apply_stage "$stage" -var "functions_location=$FUNCTIONS_LOCATION" ;;
      *)                 apply_stage "$stage" ;;
    esac
  done
fi

[ "$CODE" = 1 ] || exit 0

EVIDENCE_RG=$(terraform -chdir=stages/01-foundation output -raw evidence_resource_group_name)
COLLECTOR=$(terraform -chdir=stages/03-evidence-store output -raw collector_function_app)
REPORTER=$(terraform -chdir=stages/04-reporting output -raw reporting_function_app)
COSMOS=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint)

deploy_code() {
  local app="$1" dir="$2" zipf
  zipf="$(mktemp -d)/$(basename "$dir").zip"
  echo; echo ">> Deploying functions/$(basename "$dir") -> $app (remote build; this holds the terminal a few minutes)"
  (cd "$dir" && zip -qr "$zipf" . -x 'tests/*' '__pycache__/*' '*.pyc' '.venv/*')
  az functionapp deployment source config-zip --name "$app" --resource-group "$EVIDENCE_RG" \
    --src "$zipf" --build-remote true --timeout 900 --output none
  for _ in $(seq 1 20); do
    n=$(az functionapp function list --name "$app" --resource-group "$EVIDENCE_RG" --query "length(@)" -o tsv 2>/dev/null || echo 0)
    [ "${n:-0}" -gt 0 ] && { echo "   $n functions indexed"; return 0; }
    sleep 15
  done
  echo "   functions not indexed yet; check: az functionapp function list -n $app -g $EVIDENCE_RG" >&2
}
deploy_code "$COLLECTOR" functions/collect_assessments
deploy_code "$REPORTER" functions/reports

echo; echo ">> Seeding framework catalogs + crosswalk (catalog/*.json -> Cosmos)"
VENV="$ROOT/.venv"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q azure-cosmos azure-identity azure-storage-blob
for _ in 1 2 3 4 5 6; do
  COSMOS_ENDPOINT="$COSMOS" "$VENV/bin/python" scripts/seed_catalog.py && break
  echo "   (Cosmos data-plane role may still be propagating; retry in 30s)"; sleep 30
done

echo; echo ">> First collection run and first reports (HTTP triggers)"
call() {
  local app="$1" fn="$2" route="$3" key
  key=$(az functionapp function keys list --name "$app" --resource-group "$EVIDENCE_RG" \
        --function-name "$fn" --query default -o tsv)
  curl -sS --fail-with-body --max-time 300 "https://$app.azurewebsites.net/api/$route?code=$key"
}
call "$COLLECTOR" collect_now collect
call "$REPORTER" poam_now poam
call "$REPORTER" framework_now framework
call "$REPORTER" sar_now sar

cat <<EOF

Pipeline deployed. Timers now accumulate run history on their own:
  collector every 6h · POA&M daily 06:15 · framework daily 06:30 · SAR Mondays 07:00 (UTC)

Next: scripts/arm-ci.sh <github-user>  (hardened OIDC identity for the gate + drift)
Proofs: scripts/prove-worm.sh · scripts/trace.py · docs/EVIDENCE.md
EOF
