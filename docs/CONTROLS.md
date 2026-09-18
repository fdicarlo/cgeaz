# Control Mappings

Every policy, collector, gate rule and watcher in this repo, mapped to the NIST CSF 2.0
category it serves, with its effect and where it lives. This file is what turns the repo
from code into a control catalog. The machine-readable version of the same crosswalk is
[`catalog/crosswalk.json`](../catalog/crosswalk.json), which the reports use at runtime.
When the two disagree, that's a bug: the crosswalk file is what gets reported.

Legend: **Own** = built for this capstone beyond the course starter. Effects are the
deployed defaults; each one can be changed only through a reviewed variable.

## Stage 01: Foundation (Azure Policy at `mg-grc-sandbox`)

| Control | Effect (variable) | What it does | CSF 2.0 | 800-53 r5 | Where |
|---|---|---|---|---|---|
| Management group hierarchy + one initiative assignment | n/a | Controls inherit to every current and future subscription in the sandbox group: compliance by design | GV.PO, GV.OC | CM-2 | `main.tf`, `policies.tf` |
| `cge-require-env-tag-rg` | **Audit** (`tag_policy_effect`) | Inventory hygiene; the POA&M resolves owners from RG tags | ID.AM | CM-8 | `policies.tf` |
| `cge-deny-public-blob` | **Deny** (`public_blob_policy_effect`) | Blocks public blob exposure at the API, on create *and* update | PR.DS | AC-3, SC-7 | `policies.tf` |
| `cge-dine-storage-diagnostics` | **DeployIfNotExists** | Storage without diagnostics gets them, routed to the GRC workspace, as the remediation identity | DE.CM, PR.PS | AU-2, AU-12 | `policies.tf` |
| **Own:** `cge-audit-cosmos-local-auth` | **Audit** (`cosmos_local_auth_policy_effect`) | Cosmos DB accounts must disable key-based auth. The evidence store's zero-keys rule, applied to the whole sandbox. Audit first because it's a new control; escalate to Deny once compliance data shows no legitimate key users | PR.AA | IA-2, AC-3 | `policies.tf` |
| **Own:** `cge-audit-storage-shared-key` | **Audit** (`storage_shared_key_policy_effect`) | Storage accounts should disable shared-key authorization. Stays Audit because Functions runtime storage needs a key. Those two accounts carry time-boxed exemptions ([EXC-01](EXCEPTIONS.md#exc-01)) | PR.AA | IA-5, AC-3 | `policies.tf`; exemptions in stages 03/04 |
| Remediation identity `id-grc-remediation-dev` | n/a | Every automated change has one named, auditable author | PR.AA, GV.RR | AC-6 | `identity.tf` |
| Log Analytics + Activity Log routing (`ds-activity-to-law`) | n/a | Central audit trail beyond the 90-day platform default, queryable in KQL | DE.CM, PR.PS | AU-2, AU-6 | `main.tf`, `monitoring.tf` |
| **Own:** Out-of-band change tripwire (`alert-grc-out-of-band-change`) | alert, sev 2, hourly | Any control-plane write/delete by a caller that is neither the remediation identity nor declared automation | DE.CM, DE.AE | SI-4, AU-6 | `monitoring.tf` |
| **Own:** Budget `budget-cge-az-labs` | alert (80% actual, 100% forecast) | Cost guardrail as code | GV.RM | n/a | `monitoring.tf` |

## Stage 02: Discovery → Activation

| Control | What it does | CSF 2.0 | 800-53 r5 | Where |
|---|---|---|---|---|
| Defender tier discovery + Resource Graph inventory | Measures what runs and what's protected before anything is enabled; typed inventory + gap map outputs | ID.AM, ID.RA | CM-8, RA-5 | `main.tf`, `outputs.tf` |
| Defender plans (StorageAccounts, KeyVaults) → Standard | Activation of the baseline only; idempotent, never touches plans outside it | DE.CM | SI-4, RA-5 | `main.tf` |
| NIST CSF v2.0 initiative (built-in) | Defender's regulatory-compliance view of CSF 2.0; audit-only ([EXC-02](EXCEPTIONS.md#exc-02)) | GV.OV, ID.RA | CA-7 | `main.tf` |

## Stage 03: Evidence store

| Control | What it does | CSF 2.0 | 800-53 r5 | Where |
|---|---|---|---|---|
| Cosmos DB `grc` (assessments / runs / frameworks / mappings) | Owned evidence schema; collect once, crosswalk to every framework as data | GV.OV, ID.RA | CA-7 | `main.tf` |
| Append-only assessments (id = hash(finding + runId)) + `runs` ledger | Every past report reproducible by its runId query; run history accumulates | ID.IM, GV.OV | AU-11, CA-7 | `main.tf`, collector |
| WORM immutability on `reports` (90 days) | Report artifacts tamper-proof by platform guarantee ([proof](EVIDENCE.md#worm)) | PR.DS | AU-9, SC-28 | `main.tf` |
| Shared keys disabled, local auth disabled, data-plane RBAC | Identity or nothing: no credential to steal or rotate | PR.AA | IA-2, IA-5 | `main.tf` |
| **Own:** Cosmos continuous backup (PITR, 7 days) + blob versioning + 30-day soft delete | The store can be restored to a known moment | PR.DS, RC.RP | CP-9 | `main.tf` |
| **Own:** Data-plane access logging (blob + Cosmos → workspace) | Who read or wrote evidence, queryable next to the Activity Log | DE.CM | AU-2, AU-12 | `main.tf` |
| Collector Function (Security Reader + GRC Policy State Reader + Cosmos write) | Continuous control-test capture from two sources with lineage; can't alter what it observes | DE.CM, ID.RA | CA-7, RA-5 | `collector.tf`, `functions/collect_assessments` |
| Collector/reporter identity split | The recorder of facts cannot author the narrative (SoD by role scopes) | PR.AA, GV.RR | AC-5, AC-6 | `collector.tf`, stage 04 |
| **Own:** EXC-01 policy exemption (collector runtime storage) | Risk acceptance recorded where Azure Policy sees it; expires 2027-03-31 | GV.RM | CA-7 | `collector.tf` |

## Stage 04: Reporting (from the store only)

| Generator | Schedule | What it answers | CSF 2.0 | 800-53 r5 |
|---|---|---|---|---|
| POA&M (xlsx + json) | daily 06:15 UTC | What is open, who owns it, and when is it due (SLA from first detection) | ID.IM, GV.RM | CA-5 |
| **Own:** Framework report (md + json) | daily 06:30 UTC | Per-control state for CSF 2.0 **and** 800-53 from one collection | GV.OV | CA-7 |
| SAR (md + json) | weekly Mon 07:00 UTC | What was tested, what passed, what failed; every number with its query | ID.RA, GV.OV | CA-2 |

Every artifact embeds a `provenance` block: the run it is pinned to and the exact
Cosmos SQL that reproduces its numbers ([trace proof](EVIDENCE.md#trace)).

## Stage 06: Enforcement

| Control | Effect | What it does | CSF 2.0 | 800-53 r5 |
|---|---|---|---|---|
| `cge-fix-public-blob` | **Modify, DoNotEnforce** (`remediation_mode = "dry-run"`) | Remediation through the dedicated identity; a human creates each remediation task | PR.DS, RS.MI | AC-3, SI-2 |
| `remediation_mode` variable (audit → dry-run → enforce) | n/a | Escalation is a reviewed one-line diff: automation acts, humans authorize | GV.PO, GV.RR | CM-3 |

Blast-radius notes for each enforcement resource are in `stages/06-enforcement/main.tf`.

## Repo gates (`policy/`, run by `.github/workflows/gate.yml`)

| Rule | Mistake it makes unmergeable | CSF 2.0 | 800-53 r5 |
|---|---|---|---|
| `storage.rego` | Pipeline storage below the pipeline's own standard: public blob, shared keys (outside EXC-01), TLS < 1.2, runtime storage without its exemption | PR.DS, PR.AA | SC-8, SC-28, IA-5 |
| `policy_identity.rego` (+ `exceptions.rego`) | A policy assignment without an identity: remediation that silently never runs | PR.PS | CM-6 |
| `broad_roles.rego` | Owner/Contributor/UAA/RBAC Admin grants (by name **or** GUID), wildcard custom roles | PR.AA | AC-6 |
| **Own:** `cosmos.rego` | A Cosmos account with key auth, or without point-in-time restore | PR.AA, PR.DS | IA-2, CP-9 |
| **Own:** `exemptions.rego` | A policy exemption with no expiry or no stated reason | GV.RM | CA-7 |
| Tier 0: fmt, validate, tflint, checkov (`.checkov.yaml`, skips justified) | Unparseable, unlinted or misconfigured IaC | PR.PS | CM-6 |
| gitleaks | A committed secret | PR.AA | IA-5 |
| Gate proof: `policy/fixtures/bad-plan.json` must fail with ≥ 9 named violations | A gate that silently passes everything | GV.OV | CA-2 |

## Watchers

| Watcher | What it detects | CSF 2.0 | 800-53 r5 |
|---|---|---|---|
| `drift.yml` code-drift (plan `-detailed-exitcode` × 5 stages) | Reality no longer matches code → `drift` issue | DE.CM | CM-3, CM-6 |
| `drift.yml` out-of-band (KQL) + Azure Monitor alert | Who touched reality outside the pipeline | DE.CM, DE.AE | SI-4, AU-6 |
| `drift.yml` heartbeat (App Insights) | Collector silent for 25h → `pipeline-health` issue | DE.CM, ID.IM | SI-4 |
