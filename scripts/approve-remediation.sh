#!/usr/bin/env bash
# The human gate for any DeployIfNotExists/Modify control in the GRC Baseline initiative.
#
#   scripts/approve-remediation.sh storage-diagnostics
#
# Lists the NonCompliant resources for that policy reference, shows what the remediation
# identity will deploy, asks y/N, then creates ONE remediation task at subscription scope
# and waits for it. Outcome and per-resource results go to evidence/remediation-<date>.md.
# (Enforcement-stage policies like cge-fix-public-blob have their own flow: prove-loop.sh.)
# shellcheck disable=SC2001  # sed over a multi-line resource list is clearer here
set -euo pipefail

REF="${1:?usage: scripts/approve-remediation.sh <policy-definition-reference-id>  (e.g. storage-diagnostics)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
mkdir -p evidence
LOG="evidence/remediation-$(date -u +%Y-%m-%d).md"
note() { echo "$*" | tee -a "$LOG"; }

SUB_ID=$(az account show --query id -o tsv)
ASSIGNMENT_ID=$(terraform -chdir=stages/01-foundation output -raw baseline_assignment_id)
REMEDIATION_PID=$(terraform -chdir=stages/01-foundation output -raw remediation_identity_principal_id)

targets=$(az policy state list --subscription "$SUB_ID" \
  --filter "policyAssignmentId eq '$ASSIGNMENT_ID' and policyDefinitionReferenceId eq '$REF' and complianceState eq 'NonCompliant'" \
  --query "[].resourceId" -o tsv | sort -u)
if [ -z "$targets" ]; then
  echo "nothing to remediate: no NonCompliant resources for '$REF'"; exit 0
fi

echo "Remediation task preview"
echo "  initiative: cge-grc-baseline  (reference: $REF)"
echo "  identity:   id-grc-remediation-dev ($REMEDIATION_PID)"
echo "  resources:"
echo "$targets" | sed 's|.*/|    - |'
[ "$REF" = "storage-diagnostics" ] && \
  echo "  change:     add diagnostic setting 'ds-to-grc-workspace' (Transaction metrics -> law-grc-sandbox); nothing else"
read -r -p "Approve this remediation? [y/N] " yn
[ "$yn" = "y" ] || { echo "not approved; nothing changed"; exit 1; }

task="remediate-${REF}-$(date +%s)"
az policy remediation create --name "$task" --subscription "$SUB_ID" \
  --policy-assignment "$ASSIGNMENT_ID" --definition-reference-id "$REF" \
  --resource-discovery-mode ExistingNonCompliant --output none
note "## $(date -u +%H:%MZ) approve: human approved remediation task \`$task\` for \`$REF\` ($(az ad signed-in-user show --query id -o tsv))"
echo "$targets" | sed 's|.*/|   target: |' | tee -a "$LOG"

for _ in $(seq 1 40); do
  st=$(az policy remediation show -n "$task" --subscription "$SUB_ID" --query provisioningState -o tsv)
  echo "   task $task: $st"
  case "$st" in Succeeded|Failed|Canceled) break ;; esac
  sleep 30
done
q='{state:provisioningState,deployments:deploymentStatus}'
result=$(az policy remediation show -n "$task" --subscription "$SUB_ID" --query "$q" -o json | tr -d '\n ')
note "   task result: $result"
az policy remediation deployment list -n "$task" --subscription "$SUB_ID" \
  --query "[].{resource:remoteResourceId, status:status, error:error.message}" -o json \
  | tr -d '\n' | sed 's/^/   deployments: /' | tee -a "$LOG"; echo | tee -a "$LOG"
