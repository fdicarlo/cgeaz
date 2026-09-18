# Evidence Index

Where to find proof of each claim the rubric grades. Raw outputs live in
[`evidence/`](../evidence/), produced by the scripts named below. Personal data is
masked (operator UPNs, emails). Subscription and object IDs are identifiers, not
credentials, and stay visible so the evidence can be checked against Azure.

> Status: the proofs below were captured while the pipeline ran in Azure (2026-09-18 onward).
> The environment was decommissioned afterwards (see the last section). Sections still
> marked *pending* were not demonstrated before teardown.

## Deployment

- **2026-09-18:** deployed into an empty pay-as-you-go subscription (new tenant): state
  bootstrap, then stages 01 → 02 → 03 → 04 → 06, each applied from a reviewed saved plan,
  then code, catalog seed and first runs (`scripts/deploy.sh --code-only`). The one
  failure (budget 401 on a minutes-old subscription) succeeded on re-plan
  ([VALIDATION-LOG C10](VALIDATION-LOG.md)).
- The first armed CI run (compliance-gate, plan-only identity) planned all five stages
  successfully. The first drift run caught real drift, zip deploy rewriting app settings
  ([C7](VALIDATION-LOG.md)); stages 03/04 converge after the fix.

## WORM

`scripts/prove-worm.sh`: delete and overwrite of a stored report, attempted by an
identity that holds Storage Blob Data Contributor, both refused by the immutability
policy.

- [`evidence/worm-proof-2026-09-18.txt`](../evidence/worm-proof-2026-09-18.txt): operator
  holds Storage Blob Data Contributor; DELETE and OVERWRITE of
  `reports/sar/2026/09/sar-2026-09-18T1300Z.md` both refused with
  `BlobImmutableDueToPolicy`; size and MD5 unchanged afterwards.

## Trace

`scripts/trace.py`: newest POA&M line item → its `traceQuery` → the stored document,
compared field by field; SAR headline numbers recomputed from the embedded queries.

- [`evidence/trace-2026-09-18.md`](../evidence/trace-2026-09-18.md): POA&M item
  `POAM-20260918-001` (state storage account missing diagnostics routing, a real
  finding the pipeline made about its own bootstrap) matches its Cosmos document on
  resource, status, first-detected date, run ID and owner. The SAR's
  `assessmentsInRun`, `byStatus` and `bySource` were recomputed from the store and match.

## Incidents

- [INC-01](INCIDENTS.md): plan files pushed to a public branch; contained, all keys rotated,
  gate check added.

## Gate

- **Offline proof on every push:** the `static` job of `compliance-gate` runs conftest on
  `policy/fixtures/bad-plan.json` and fails the build unless ≥ 9 named violations fire
  (current: 10). 21 unit tests in `policy/tests/`.
- **Live proof:** [PR #7](https://github.com/fdicarlo/cgeaz/pull/7) adds a "quick" public
  storage account for sharing reports (public blob, shared keys, TLS 1.0). Closed unmerged.
  Both layers blocked it independently ([run 35351750174](https://github.com/fdicarlo/cgeaz/actions/runs/35351750174)):
  - Tier 0 `static`: checkov CKV_AZURE_44, CKV_AZURE_190, CKV2_AZURE_38, CKV2_AZURE_47
  - OPA on the **live** stage 04 plan: `FAIL … azurerm_storage_account.public_share: storage
    accounts must not allow public blob access` / `shared key access must be disabled` /
    `min_tls_version must be TLS1_2 or higher`
  - The first attempt showed the plan gate being skipped whenever Tier 0 failed
    (`needs: static`). [PR #8](https://github.com/fdicarlo/cgeaz/pull/8) made the layers independent.
- **Branch protection on `main` (2026-09-18, 14:40Z):** PR required (0 approvals, since this is a
  solo repo), 6 required checks (`static` + `plan (…)` × 5 stages), enforced for admins, no
  force-push or deletion. A direct push of an empty commit was refused:
  `GH006: Protected branch update failed … Changes must be made through a pull request …
  6 of 6 required status checks are expected.`
- **Every governance change since deployment went through a gated PR:** #2, #5, #8, #9.

## Loop

`scripts/prove-loop.sh setup → sabotage → scan → approve → verify`, with the de- and
re-escalation as reviewed PRs.

- De-escalation: [PR #9](https://github.com/fdicarlo/cgeaz/pull/9), `public_blob_policy_effect` Deny → Audit (one line, gated, merged, applied)
- Loop log: [`evidence/loop-2026-09-18.md`](../evidence/loop-2026-09-18.md)
  - 13:49 sabotage (operator makes `stgrcloop0ffaa568` public), 13:54 NonCompliant
  - 13:57 **operator approves** remediation task `fix-public-blob-1789739838`: Succeeded (1 ok, 0 failed)
  - Activity Log: the only write after the sabotage is 13:57:39Z by `924ca48e…` = `id-grc-remediation-dev`
  - 14:04 rescan Compliant; POA&M 5 → 3 open items, both public-blob items gone
- Re-escalation: [PR #10](https://github.com/fdicarlo/cgeaz/pull/10), Audit → Deny. The same sabotage retried is refused with `RequestDisallowedByPolicy` (`cge-deny-public-blob`).
- Honest note: the first `verify` printed its RESULT line before the Activity Log held the remediation write (script bug, fixed in #10). The log keeps the wrong line, annotated, next to the corrected entries.

## DINE remediation

[`evidence/remediation-2026-09-18.md`](../evidence/remediation-2026-09-18.md) (`scripts/approve-remediation.sh storage-diagnostics`):
- 14:27 the operator approves task `remediate-storage-diagnostics-1789741668` for the state
  account (which existed before the policy): Succeeded, 1 ok / 0 failed.
- Activity Log: `diagnosticSettings/write` at 14:28:15Z by `924ca48e…` = `id-grc-remediation-dev`.
- The loop target got the same setting **automatically** at 14:08:11Z, same identity: DINE
  acts on create/update without a task.

## Run history

- Ledger: `SELECT c.runId, c.collectedAt, c.trigger, c.written FROM c ORDER BY c.collectedAt DESC` on `runs`
- Invocations: workspace saved search `grc-pipeline-run-history` (AppRequests)
- Nightly summary: each `drift-detection` run's job summary lists runs and failures for the last 25h
- Snapshot: *pending*

## Drift

- Detector 1 (code drift): nightly `drift-detection` runs, *pending*
- Detector 2 (out-of-band): alert `alert-grc-out-of-band-change` + nightly KQL, *pending*

## Decommissioning

**2026-09-18**, after the capstone passed. Every step was a reviewed `terraform plan -destroy`
applied as saved, in reverse stage order:

| Step | Result |
|---|---|
| 06-enforcement → 04-reporting → 03-evidence-store → 02-activation → 01-foundation | 3 + 7 + 23 + 3 + 21 resources destroyed |
| WORM `reports` container | destroyed: the policy was unlocked ([EXC-04](EXCEPTIONS.md#exc-04)) for exactly this |
| Defender for Storage / Key Vaults | back to **Free** (stage 02 destroy) |
| Out-of-band leftovers | loop target account, App Insights smart-detection action group + alert rule, CI planner role, role assignments and app registration: deleted by hand |
| State | delete lock removed, `rg-grc-tfstate` deleted last |
| GitHub | Azure repository variables deleted; the `plan`/drift jobs now skip; branch protection requires `static` only |

Verified afterwards: 0 resource groups, 0 resources, no `cge-*` policy definitions,
assignments or exemptions, no custom roles, no budget, no subscription diagnostic
settings, no CI app registration. The subscription itself was left in place (its
cancellation is an account decision).
