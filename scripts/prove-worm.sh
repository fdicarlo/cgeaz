#!/usr/bin/env bash
# WORM proof: try to delete and to overwrite a stored report, as a user who HOLDS
# Storage Blob Data Contributor on the account. Both must fail. Output is written to
# evidence/worm-proof-<date>.txt — the failed-delete receipt the rubric asks for.
#
# Access control says who MAY delete. Immutability says nobody CAN, for the retention
# period, whatever their role. This script demonstrates the second.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
mkdir -p evidence
OUT="evidence/worm-proof-$(date -u +%Y-%m-%d).txt"

RG=$(terraform -chdir=stages/01-foundation output -raw evidence_resource_group_name)
SA=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account)

{
  echo "# WORM proof — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "operator:   $(az ad signed-in-user show --query userPrincipalName -o tsv | sed 's/^\(..\).*@/\1***@/')"
  echo "account:    $SA (resource group $RG)"
  echo
  echo "## 1. The container policy"
  az storage container immutability-policy show --account-name "$SA" --container-name reports \
    --resource-group "$RG" --query "{state:state, retentionDays:immutabilityPeriodSinceCreationInDays, protectedAppendWritesAll:allowProtectedAppendWritesAll}" -o json
  echo
  echo "## 2. The operator's data-plane role on the account (it DOES include delete)"
  az role assignment list --assignee "$(az ad signed-in-user show --query id -o tsv)" \
    --scope "$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account_id)" \
    --query "[].roleDefinitionName" -o tsv
  echo
  BLOB=$(az storage blob list --account-name "$SA" --container-name reports --auth-mode login \
          --query "sort_by([?!contains(name, 'worm-probe')], &properties.creationTime)[-1].name" -o tsv)
  if [ -z "$BLOB" ]; then
    echo "No report in the container yet — run scripts/deploy.sh (or wait for the next POA&M timer, every 6h at :15)."
    exit 1
  fi
  echo "## 3. Target: reports/$BLOB"
  az storage blob show --account-name "$SA" --container-name reports --name "$BLOB" --auth-mode login \
    --query "{created:properties.creationTime, size:properties.contentLength, md5:properties.contentSettings.contentMd5}" -o json
  echo
  echo "## 4. Attempt DELETE (must fail)"
  if az storage blob delete --account-name "$SA" --container-name reports --name "$BLOB" --auth-mode login 2>&1; then
    echo "!!! DELETE SUCCEEDED — WORM IS NOT PROTECTING THIS CONTAINER"; exit 2
  fi
  echo
  echo "## 5. Attempt OVERWRITE (must fail)"
  TMP=$(mktemp); echo "tampered $(date -u)" > "$TMP"
  if az storage blob upload --account-name "$SA" --container-name reports --name "$BLOB" \
       --file "$TMP" --overwrite true --auth-mode login 2>&1; then
    echo "!!! OVERWRITE SUCCEEDED — WORM IS NOT PROTECTING THIS CONTAINER"; exit 2
  fi
  echo
  echo "## 6. The blob is unchanged"
  az storage blob show --account-name "$SA" --container-name reports --name "$BLOB" --auth-mode login \
    --query "{created:properties.creationTime, size:properties.contentLength, md5:properties.contentSettings.contentMd5}" -o json
  echo
  echo "RESULT: delete and overwrite both refused by the immutability policy. WORM proven."
} 2>&1 | tee "$OUT"

echo; echo "saved: $OUT"
