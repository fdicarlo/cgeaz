# Evidence Index

Where to find proof of each claim the rubric grades. Raw outputs live in
[`evidence/`](../evidence/), produced by the scripts named below. Personal data is
masked (operator UPNs, emails). Subscription and object IDs are identifiers, not
credentials, and stay visible so the evidence can be checked against Azure.

> Status: the pipeline is deployed in stages, and each section is filled in as its
> proof is captured. A section that still says *pending* has not been demonstrated yet.

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
- **Live proof:** a closed, unmerged PR that adds a non-compliant storage account; the
  `plan` job fails naming the rule and resource: *pending*

## Loop

`scripts/prove-loop.sh setup → sabotage → scan → approve → verify`, with the de- and
re-escalation as reviewed PRs.

- De-escalation PR (Deny → Audit): *pending*
- Loop log: *pending* (`evidence/loop-<date>.md`)
- Re-escalation PR (Audit → Deny): *pending*

## Run history

- Ledger: `SELECT c.runId, c.collectedAt, c.trigger, c.written FROM c ORDER BY c.collectedAt DESC` on `runs`
- Invocations: workspace saved search `grc-pipeline-run-history` (AppRequests)
- Nightly summary: each `drift-detection` run's job summary lists runs and failures for the last 25h
- Snapshot: *pending*

## Drift

- Detector 1 (code drift): nightly `drift-detection` runs, *pending*
- Detector 2 (out-of-band): alert `alert-grc-out-of-band-change` + nightly KQL, *pending*
