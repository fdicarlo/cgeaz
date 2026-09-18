# Evidence Index

Where to find proof of each claim the rubric grades. Raw outputs live in
[`evidence/`](../evidence/), produced by the scripts named below. Personal data is
masked (operator UPNs, emails). Subscription and object IDs are identifiers, not
credentials, and stay visible so the evidence can be checked against Azure.

> Status: the pipeline is deployed in stages, and each section is filled in as its
> proof is captured. A section that still says *pending* has not been demonstrated yet.

## Deployment

- Deployed from an empty free-account subscription with `scripts/deploy.sh`: *pending*
- `terraform plan` per stage converges to `No changes` after apply: *pending*

## WORM

`scripts/prove-worm.sh`: delete and overwrite of a stored report, attempted by an
identity that holds Storage Blob Data Contributor, both refused by the immutability
policy.

- Output: *pending* (`evidence/worm-proof-<date>.txt`)

## Trace

`scripts/trace.py`: newest POA&M line item → its `traceQuery` → the stored document,
compared field by field; SAR headline numbers recomputed from the embedded queries.

- Output: *pending* (`evidence/trace-<date>.md`)

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
