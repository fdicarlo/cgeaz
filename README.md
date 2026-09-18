# GRC Engineering Pipeline on Azure: CGE-AZ Capstone

> **Status: decommissioned 2026-09-18.** The capstone passed, and the Azure environment was torn
> down (every stage destroyed in reverse order; see [EVIDENCE.md](docs/EVIDENCE.md#decommissioning)).
> The code, docs and evidence stay here as a reference; `scripts/deploy.sh` still
> stands the whole pipeline up again in any empty subscription.

An automated GRC pipeline that runs in its own Azure subscription. It discovers what is
running, turns on the missing Defender coverage, collects control evidence into a store
nobody can rewrite, generates auditor deliverables from that store alone, and fixes
non-compliant resources through one least-privilege identity after a human approves.
Everything is Terraform and Python, deployed from this repo.

Built for **CGE-AZ: Certified GRC Engineer, Azure Specialty** (GRC Engineering Club),
starting from the course repo [GRCEngClub/cgeaz](https://github.com/GRCEngClub/cgeaz).
What this capstone adds or changes is listed [below](#what-this-capstone-adds-to-the-starter).

```
01 Foundation ─► 02 Discovery → Activation ─► 03 Evidence store ─► 04 Reporting ─► 06 Enforcement ↺
mg hierarchy       read Defender tiers +         Cosmos (append-only)   POA&M · Framework   Modify, dry-run,
5-policy baseline  Resource Graph inventory,     + WORM Blob            · SAR, from the     human-approved,
tripwire, budget   enable only the baseline      collector hourly       store only          one remediation identity
```

Architecture, identity boundaries and the data model are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Deploy from an empty subscription

**Prerequisites:** an Azure subscription where you are Owner and can create management
groups. This one runs in a fresh pay-as-you-go subscription in its own tenant; a
[free account](https://azure.microsoft.com/free) works the same way; Azure CLI ≥ 2.60, Terraform ≥ 1.9, Python ≥ 3.11, `zip`; for CI, a
GitHub fork of this repo and the `gh` CLI.

```bash
az login
cp config.env.example config.env    # set SUBSCRIPTION_ID and OWNER_EMAIL
labs/00-setup/probe-quota.sh        # optional: confirm Consumption quota in centralus
scripts/deploy.sh                   # ~25 min, mostly Cosmos and remote builds
```

`scripts/deploy.sh` refuses to run if `az` points at a subscription other than the one
in `config.env`. It runs, in order:

| # | Step | What it creates | Where |
|---|---|---|---|
| 0 | Provider registration | the 13 resource providers the stages use (fresh subscriptions have almost none) | `scripts/deploy.sh` |
| 1 | State bootstrap | `rg-grc-tfstate`: Entra-only, versioned, soft-deleted, delete-locked state account; writes `labs/03-foundation/backend.hcl` | `labs/03-foundation/bootstrap.sh` |
| 2 | `01-foundation` | `mg-grc → mg-grc-sandbox` (subscription moved in), sandbox + evidence RGs, Log Analytics, Activity Log routing, 5-policy baseline initiative, remediation identity, tripwire alert, budget | `stages/01-foundation` |
| 3 | `02-activation` | discovery outputs; Defender for Storage + Key Vault → Standard; NIST CSF 2.0 initiative | `stages/02-activation` |
| 4 | `03-evidence-store` | Cosmos `grc` (4 containers, PITR), WORM `reports` container, collector Function + roles, App Insights, EXC-01 exemption | `stages/03-evidence-store` |
| 5 | `04-reporting` | report Function + roles (read store, write `reports/` only), EXC-01 exemption | `stages/04-reporting` |
| 6 | `06-enforcement` | `cge-fix-public-blob` Modify assignment in **dry-run** | `stages/06-enforcement` |
| 7 | Code + catalog | zip-deploys both Function apps; seeds CSF 2.0 + 800-53 and the crosswalk from `catalog/` | `functions/`, `scripts/seed_catalog.py` |
| 8 | First runs | one collection, one POA&M, one framework report, one SAR (HTTP triggers) | |

Then arm CI with a plan-only identity:

```bash
scripts/arm-ci.sh <github-owner> cgeaz --set-vars   # OIDC app + custom "GRC CI Planner" role + repo variables
# put the printed TRUSTED_CALLERS into config.env, then:
scripts/deploy.sh --stages "01"                     # tripwire now trusts CI's identity
```

New subscriptions need time before evidence appears. Defender's first assessment cycle
can take up to about 24 hours, and a new Log Analytics workspace takes 30 to 60 minutes
to show its first rows. An empty first run is a clean run, not an error.

## Operate

| Schedule (UTC) | What | Output |
|---|---|---|
| hourly | collector: Defender assessments + `cge-*` policy states → Cosmos, one ledger entry per run | `assessments`, `runs` |
| every 6h (00:15/06:15/12:15/18:15) | POA&M | `reports/poam/YYYY/MM/*.xlsx` + `.json` |
| every 6h (:30 past, same hours) | Framework report (CSF 2.0 + 800-53) | `reports/framework/YYYY/MM/*.md` + `.json` |
| daily 06:45 | SAR | `reports/sar/YYYY/MM/*.md` + `.json` |
| nightly 08:00 | drift detection: code drift, out-of-band changes, pipeline heartbeat | GitHub issues + job summary |
| hourly | out-of-band change alert | email to `OWNER_EMAIL` |
| every PR | compliance gate: Tier 0 + OPA on the real plan | required checks on `main` |

Proofs, runnable at any time:

```bash
scripts/prove-worm.sh                 # delete + overwrite of a stored report both refused
.venv/bin/python scripts/trace.py     # report number -> Cosmos document, field by field
scripts/prove-loop.sh setup           # then: sabotage, scan, approve, verify
./self-check.sh                       # the mechanical half of the rubric, locally
```

**Escalation ladder:** effects change only through reviewed variables:
`public_blob_policy_effect`, `cosmos_local_auth_policy_effect`,
`storage_shared_key_policy_effect` and `tag_policy_effect` in `stages/01-foundation`, and
`remediation_mode` (`audit` → `dry-run` → `enforce`) in `stages/06-enforcement`.
Open a PR, let the gate plan it, merge, then apply.

## What this capstone adds to the starter

| Area | Starter | This repo |
|---|---|---|
| Own controls | 3 course policies | **+2 own policies** (`cge-audit-cosmos-local-auth`, `cge-audit-storage-shared-key`), each with a matching gate rule, collected, crosswalked and reported ([D1](docs/DECISIONS.md#d1-two-own-controls-that-extend-the-pipelines-zero-keys-rule)) |
| Evidence integrity | findings overwritten each run | **append-only per run** + `runs` ledger: every past report reproducible by its runId ([D2](docs/DECISIONS.md#d2-the-evidence-store-is-append-only-per-run)); Cosmos PITR; data-plane access logs |
| Evidence sources | Defender only | Defender **+ Azure Policy states** for own controls (custom 2-action role) |
| Reports | POA&M, SAR | + **Framework report** (CSF 2.0 and 800-53 from one collection); provenance block with reproducing queries in every artifact; POA&M due dates from first detection ([D3](docs/DECISIONS.md#d3-poam-due-dates-anchor-to-first-detection)); owners resolved from stored RG tags |
| Crosswalk | CSF function list only | `catalog/` as reviewed data, seeded with stale-mapping cleanup; 800-53 added as a data change |
| Gate | 3 rules; identity rule never fired on `identity = []` | 6 rule files, **21 unit tests**, bad-plan proof on every push, broad roles caught by GUID too, exemption expiry, Cosmos rules; Tier 0 (tflint, checkov, gitleaks) in CI |
| CI identity | Contributor at mg-grc | **plan-only custom role** + state Blob Data Reader ([D4](docs/DECISIONS.md#d4-plan-only-ci-identity)) |
| Drift | plan only, CI couldn't init (backend.hcl gitignored) | plan per stage (incl. 02), **KQL out-of-band detector** as an Azure alert and a nightly job, pipeline heartbeat, deduplicated issues |
| Foundation | Activity Log routing and budget built by hand | both in Terraform; explicit `subscription_id` in every provider; one-command deploy |
| State | versioned account | + Entra-only (shared keys off), soft delete, delete lock |
| Exceptions | implicit | [register](docs/EXCEPTIONS.md) with time-boxed policy exemptions the gate checks |

## Repository layout

```
stages/      one Terraform root module per pipeline stage, each with its own state
functions/   collector and report generators (Python, timer-triggered, managed identity)
catalog/     framework catalogs + crosswalk: data, reviewed like code
policy/      OPA/conftest gate rules, unit tests, good/bad plan fixtures
scripts/     deploy, arm CI, proofs (WORM, trace, loop), catalog seeding
docs/        architecture, controls, decisions, exceptions, evidence, rubric map
evidence/    raw proof outputs referenced from docs/EVIDENCE.md
labs/        the course's six lab guides (kept for reference; bootstrap hardened)
.github/     compliance gate, drift detection, guide CI
```

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md): stage flow, identity boundaries, data model, one finding end to end
- [CONTROLS.md](docs/CONTROLS.md): every policy, collector, gate rule and watcher → NIST CSF 2.0 (+ 800-53)
- [DECISIONS.md](docs/DECISIONS.md): why the non-obvious choices were made
- [EXCEPTIONS.md](docs/EXCEPTIONS.md): where the pipeline falls short of its own rules, and until when
- [EVIDENCE.md](docs/EVIDENCE.md): proof for each graded claim
- [INCIDENTS.md](docs/INCIDENTS.md): security incidents in the pipeline itself, and what changed
- [RUBRIC-MAP.md](docs/RUBRIC-MAP.md): each rubric criterion → the file that satisfies it
- [VALIDATION-LOG.md](docs/VALIDATION-LOG.md): what broke on real accounts, and the fixes
- [SETUP.md](docs/SETUP.md) / `labs/`: the original course setup and labs

## Teardown

Reverse stage order, then the pieces outside Terraform:

```bash
for s in 06-enforcement 04-reporting 03-evidence-store 02-activation 01-foundation; do
  terraform -chdir="stages/$s" destroy
done
az lock delete --name lock-tfstate --resource-group rg-grc-tfstate
az group delete --name rg-grc-tfstate
```

The WORM container is unlocked ([EXC-04](docs/EXCEPTIONS.md#exc-04)), so the destroy
succeeds. Destroying stage 02 returns the baseline Defender plans to Free. Delete the CI
app registration with `az ad app delete --id <AZURE_CLIENT_ID>`.

---

*Course material © GRC Engineering Club (www.grcengclub.com). Capstone build by
[@fdicarlo](https://github.com/fdicarlo).*
