# Rubric Map

Each criterion in [RUBRIC.md](RUBRIC.md) (mirror of cert.grcengclub.com/rubric/cge-az),
mapped to the file or proof that satisfies it. Run `./self-check.sh` for the
mechanical half.

## Submission requirements

| Requirement | Where |
|---|---|
| Public repo, ≤ 50 MB, ≤ 10,000 files | github.com/fdicarlo/cgeaz |
| README: pipeline + deploy from an empty subscription | [README.md](../README.md#deploy-from-an-empty-subscription), `scripts/deploy.sh` |
| Terraform: governed foundation | `stages/01-foundation` |
| Terraform: evidence store (Cosmos + immutable Blob) | `stages/03-evidence-store/main.tf` (`azurerm_cosmosdb_account.evidence`, `azurerm_storage_container_immutability_policy.reports_worm`) |
| Terraform: enforcement in dry-run | `stages/06-enforcement` (`remediation_mode = "dry-run"` → `enforce = false`) |
| ≥ 2 report generators, store-only, live timers | `functions/reports/function_app.py`: POA&M daily, Framework daily, SAR weekly; reporter identity has no live-API role (`stages/04-reporting/main.tf`) |
| Real run history | `runs` ledger + App Insights `AppRequests` ([EVIDENCE.md](EVIDENCE.md#run-history)) |
| CI gate on the repo's own Terraform | `.github/workflows/gate.yml` (`static` + `plan` jobs), `policy/` |
| Scheduled drift detection | `.github/workflows/drift.yml` (nightly) + `alert-grc-out-of-band-change` |
| CONTROLS.md mapping to CSF 2.0 | [CONTROLS.md](CONTROLS.md) |

## 1. Infrastructure-as-Code quality

| Criterion | Where |
|---|---|
| Staged root modules, separate state, output contracts | `stages/*/`, one `backend "azurerm"` key each; [ARCHITECTURE §1](ARCHITECTURE.md#1-stage-flow) |
| Pinned azurerm | `~> 4.81` in every stage + committed `.terraform.lock.hcl` (4.81.0) |
| Explicit subscription targeting | `subscription_id = var.subscription_id` in every provider block (GUID-validated in 01) |
| Discovery-first, activation conditional on the measured gap | `stages/02-activation/main.tf`: azapi tier reads + Resource Graph inventory → `activation_needed`, `plan_coverage` outputs |
| Hardened remote state | `labs/03-foundation/bootstrap.sh`: shared keys off, versioning, 30-day soft delete, CanNotDelete lock, TLS 1.2 |
| Tier 0: fmt / validate / tflint / checkov | `gate.yml` `static` job; `.tflint.hcl`; `.checkov.yaml` (each skip justified, EXC-03) |

## 2. Control implementation & identity design

| Criterion | Where |
|---|---|
| Identity block on every remediation-effect assignment | `grc_baseline` (01) and `fix_public_blob` (06); enforced by `policy/policy_identity.rego` |
| ONE named user-assigned remediation identity, whitelist roles | `id-grc-remediation-dev` (`stages/01-foundation/identity.tf`): Monitoring Contributor + Storage Account Contributor (only above audit) |
| Collector and reporter as separate identities (SoD) | [ARCHITECTURE §2](ARCHITECTURE.md#2-identity-boundaries) |
| Deliberate effects; deny where earned; escalation via reviewed variable | public blob = Deny; new controls = Audit; `remediation_mode`; `*_policy_effect` variables with validation |
| ≥ 1 own policy, correctly effected and mapped | `cge-audit-cosmos-local-auth`, `cge-audit-storage-shared-key` ([D1](DECISIONS.md#d1-two-own-controls-that-extend-the-pipelines-zero-keys-rule), [CONTROLS](CONTROLS.md), `catalog/crosswalk.json`) |

## 3. Evidence integrity & traceability

| Criterion | Where |
|---|---|
| WORM on reports, failed-delete proof | `reports_worm` (90 days); `scripts/prove-worm.sh` → [EVIDENCE#worm](EVIDENCE.md#worm) |
| Idempotent, runId + collectedAt collection | `functions/collect_assessments/function_app.py`: deterministic id = hash(finding + runId), ledger written last |
| Reports read from the store only; numbers reproducible | reporter RBAC; `provenance.queries` in every artifact; `scripts/trace.py` → [EVIDENCE#trace](EVIDENCE.md#trace) |
| Framework crosswalk as data (collect once) | `catalog/`, `mappings` container, framework report covering CSF 2.0 + 800-53 |

## 4. Pipeline operations

| Criterion | Where |
|---|---|
| Run history accumulating | collector every 6h since deployment; [EVIDENCE#run-history](EVIDENCE.md#run-history) |
| Gate demonstrably blocks | bad-plan proof on every push + closed test PR ([EVIDENCE#gate](EVIDENCE.md#gate)) |
| Enforcement in dry-run with a human at the approval gate | `scripts/prove-loop.sh approve` ([EVIDENCE#loop](EVIDENCE.md#loop)) |
| Drift both ways | code drift (plan exit 2) + out-of-band (KQL alert + nightly job) |

## 5. Documentation & control mapping

| Criterion | Where |
|---|---|
| Cold-readable README with deploy order | [README.md](../README.md) |
| CONTROLS.md current with code | [CONTROLS.md](CONTROLS.md) |
| Blast-radius notes on every enforcement policy | `stages/06-enforcement/main.tf`, `stages/01-foundation/identity.tf` |
| Architecture doc: stage flow + identity boundaries | [ARCHITECTURE.md](ARCHITECTURE.md) |
| The why for non-obvious choices | [DECISIONS.md](DECISIONS.md), [EXCEPTIONS.md](EXCEPTIONS.md) |

## Auto-fail triggers

| Trigger | Status |
|---|---|
| Private/inaccessible repo | public |
| Active secrets | none by design (OIDC + managed identity); gitleaks in CI and `self-check.sh` |
| Real PII / production credentials | owner email lives only in untracked `config.env` and repository variables; evidence masks UPNs |
| Unmodified fork | see [README: what this capstone adds](../README.md#what-this-capstone-adds-to-the-starter) |
| No README | present |
