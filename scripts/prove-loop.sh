#!/usr/bin/env bash
# The full enforcement loop (Lab 6), one step at a time, with the human gate explicit:
#
#   setup      create a compliant workload storage account to break (the loop target)
#   sabotage   flip it public, out of band (needs public_blob_policy_effect = Audit,
#              merged via a reviewed PR — Deny blocks the sabotage itself, by design)
#   scan       trigger a compliance scan and wait for cge-fix-public-blob: NonCompliant
#   approve    THE HUMAN GATE: show exactly what will change, ask, then create the
#              remediation task (dry-run mode = nothing remediates until this)
#   verify     property fixed, Activity Log caller = remediation identity, collector
#              re-run, POA&M regenerated -> evidence/loop-<date>.md
#
# Each step is idempotent and prints its own success signal. Waits are Azure's, not
# ours: the scan alone was ~15 min in validation (VALIDATION-LOG, Lab 6).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
STEP="${1:?usage: scripts/prove-loop.sh setup|sabotage|scan|approve|verify}"

RG="rg-grc-sandbox-dev"
SUB_ID=$(az account show --query id -o tsv)
TARGET="stgrcloop$(echo "$SUB_ID" | tr -d '-' | cut -c1-8)"
EVIDENCE_RG=$(terraform -chdir=stages/01-foundation output -raw evidence_resource_group_name)
ASSIGNMENT_ID=$(terraform -chdir=stages/06-enforcement output -raw remediation_assignment_id)
REMEDIATION_PID=$(terraform -chdir=stages/01-foundation output -raw remediation_identity_principal_id)
LOG="evidence/loop-$(date -u +%Y-%m-%d).md"
mkdir -p evidence

note() { echo "$*" | tee -a "$LOG"; }
state() {
  az policy state list --resource "$(az storage account show -n "$TARGET" -g "$RG" --query id -o tsv)" \
    --filter "policyDefinitionName eq 'cge-fix-public-blob'" --query "[0].complianceState" -o tsv 2>/dev/null
}

case "$STEP" in
  setup)
    az storage account create -n "$TARGET" -g "$RG" --sku Standard_LRS --kind StorageV2 \
      --min-tls-version TLS1_2 --allow-blob-public-access false \
      --tags env=dev purpose=loop-target --output none
    note "## $(date -u +%H:%MZ) setup: loop target \`$TARGET\` created compliant (allowBlobPublicAccess=false)"
    ;;

  sabotage)
    effect=$(az policy assignment show --scope "/providers/Microsoft.Management/managementGroups/mg-grc-sandbox" \
      -n cge-grc-baseline --query "parameters.publicBlobEffect.value" -o tsv)
    if [ "$effect" = "Deny" ]; then
      echo "Deny is active on public blob access, so the sabotage would be refused (that's the guardrail working)."
      echo "De-escalate through a reviewed PR first: public_blob_policy_effect = \"Audit\" in"
      echo "stages/01-foundation/variables.tf, merge, then: scripts/deploy.sh --stages \"01\""
      exit 1
    fi
    az storage account update -n "$TARGET" -g "$RG" --allow-blob-public-access true --output none
    note "## $(date -u +%H:%MZ) sabotage: \`$TARGET\` allowBlobPublicAccess=$(az storage account show -n "$TARGET" -g "$RG" --query allowBlobPublicAccess -o tsv) (out-of-band, by $(az ad signed-in-user show --query id -o tsv))"
    ;;

  scan)
    note "## $(date -u +%H:%MZ) scan: triggered compliance evaluation of $RG"
    az policy state trigger-scan --resource-group "$RG" --no-wait
    for _ in $(seq 1 60); do
      s=$(state || true)
      echo "   $(date -u +%H:%M) cge-fix-public-blob on $TARGET: ${s:-not evaluated yet}"
      [ "$s" = "NonCompliant" ] && { note "   detected: NonCompliant at $(date -u +%H:%MZ)"; exit 0; }
      sleep 60
    done
    echo "still not NonCompliant after 60 min; re-run this step (the scan keeps going server-side)"; exit 1
    ;;

  approve)
    [ "$(state)" = "NonCompliant" ] || { echo "nothing to approve: target is not NonCompliant"; exit 1; }
    echo "Remediation task preview"
    echo "  policy:     cge-fix-public-blob (Modify)"
    echo "  identity:   id-grc-remediation-dev ($REMEDIATION_PID)"
    echo "  resource:   $TARGET"
    echo "  change:     allowBlobPublicAccess true -> false (nothing else)"
    read -r -p "Approve this remediation? [y/N] " yn
    [ "$yn" = "y" ] || { echo "not approved; nothing changed"; exit 1; }
    task="fix-public-blob-$(date +%s)"
    az policy remediation create --name "$task" --resource-group "$RG" \
      --policy-assignment "$ASSIGNMENT_ID" --output none
    note "## $(date -u +%H:%MZ) approve: human approved remediation task \`$task\` ($(az ad signed-in-user show --query id -o tsv))"
    for _ in $(seq 1 30); do
      st=$(az policy remediation show -n "$task" -g "$RG" --query provisioningState -o tsv)
      echo "   task $task: $st"
      [ "$st" = "Succeeded" ] || [ "$st" = "Failed" ] && break
      sleep 30
    done
    q='{state:provisioningState,deployments:deploymentStatus}'
    result=$(az policy remediation show -n "$task" -g "$RG" --query "$q" -o json | tr -d '\n ')
    note "   task result: $result"
    ;;

  verify)
    public=$(az storage account show -n "$TARGET" -g "$RG" --query allowBlobPublicAccess -o tsv)
    note "## $(date -u +%H:%MZ) verify: \`$TARGET\` allowBlobPublicAccess=$public"
    caller=$(az monitor activity-log list --resource-id "$(az storage account show -n "$TARGET" -g "$RG" --query id -o tsv)" \
      --offset 6h --query "sort_by([?operationName.value=='Microsoft.Storage/storageAccounts/write' && status.value=='Succeeded'], &eventTimestamp)[-1].caller" -o tsv)
    # Activity Log ingestion lags a few minutes: re-run verify if the caller isn't there yet.
    note "   last successful write by: $caller (remediation identity principal: $REMEDIATION_PID)"
    APP=$(terraform -chdir=stages/03-evidence-store output -raw collector_function_app)
    RAPP=$(terraform -chdir=stages/04-reporting output -raw reporting_function_app)
    k=$(az functionapp function keys list -n "$APP" -g "$EVIDENCE_RG" --function-name collect_now --query default -o tsv)
    note "   collector: $(curl -sS "https://$APP.azurewebsites.net/api/collect?code=$k")"
    k=$(az functionapp function keys list -n "$RAPP" -g "$EVIDENCE_RG" --function-name poam_now --query default -o tsv)
    note "   POA&M:     $(curl -sS "https://$RAPP.azurewebsites.net/api/poam?code=$k")"
    if [ "$public" = "false" ] && [ "$caller" = "$REMEDIATION_PID" ]; then
      note "   RESULT: detected -> approved -> fixed by the remediation identity -> re-collected -> documented."
    else
      note "   NOT YET PROVEN: property=$public, last writer=$caller (Activity Log may lag; re-run verify in a few minutes)"
    fi
    echo "Now re-escalate: revert the Audit PR (Deny again), merge, scripts/deploy.sh --stages \"01\"."
    ;;

  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
