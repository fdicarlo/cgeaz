# Exceptions Register

Every place this pipeline deliberately falls short of its own rules, why, what
compensates, and when it gets revisited. An exception that isn't written down here is
a defect. Where Azure Policy or the gate can see an exception, it is also declared in
code (policy exemption / `policy/exceptions.rego`), and the code points back here.

| ID | Rule broken | Scope | Recorded in code | Expires / review |
|---|---|---|---|---|
| [EXC-01](#exc-01) | Zero keys (`cge-audit-storage-shared-key`, `storage.rego`) | the two Functions runtime storage accounts | `azurerm_resource_policy_exemption` in stages 03 and 04; `storage.rego` requires it | 2027-03-31 |
| [EXC-02](#exc-02) | Assignments carry an identity (`policy_identity.rego`) | `nist_csf_20` assignment | `policy/exceptions.rego` | review with each CSF initiative version bump |
| [EXC-03](#exc-03) | Tier 0 checkov findings | listed checks | `.checkov.yaml` | review before any production use |
| [EXC-04](#exc-04) | WORM locked | `reports` container | `stages/03-evidence-store/main.tf` comment | at course end |
| [EXC-05](#exc-05) | Changes go through CI | Terraform applies | n/a (process) | when CI gets an apply identity |

## EXC-01

**Functions runtime storage uses a shared key.** Consumption-plan Function Apps keep
their host state (`AzureWebJobsStorage`: timer leases, deployment packages) in a storage
account reached by account key. Identity-based host storage on Linux Consumption doesn't
cover the full deployment path the labs validated.

- *What's exposed:* two accounts, `stgrcfunc*` and `stgrcrpt*`, that hold no evidence.
  The key lives only in each Function App's settings.
- *Compensating controls:* the evidence account and Cosmos are keyless. The runtime
  accounts are TLS 1.2+, not public, soft-delete on, and log over-long SAS. The gate
  (`storage.rego`) refuses a runtime account that has no exemption in the same stage.
- *In Azure Policy:* `exc-01-collector-runtime-shared-key` and
  `exc-01-reporter-runtime-shared-key`, category Waiver, scoped to the
  `storage-shared-key` reference only, expiring **2027-03-31** (`exemption_expires_on`).
  After expiry the accounts show NonCompliant again, and the POA&M picks them up.
- *Exit:* move to Flex Consumption with identity-based host storage, then delete the
  exemptions.

## EXC-02

**The NIST CSF v2.0 built-in initiative is assigned without an identity.** It feeds
Defender's regulatory-compliance dashboard and is used for assessment only. Nothing
remediates through it, so an identity would be a standing principal with nothing to
do. `policy/exceptions.rego` lists it by address, and every other assignment must
carry an identity.

## EXC-03

**Checkov checks skipped** (see `.checkov.yaml`, one reason per line). Summary:
private endpoints and public-network-off (Consumption Functions can't join a VNet, and
access is identity-only instead), customer-managed keys (platform-managed encryption is
on and no in-scope obligation asks for CMK), zone redundancy and GRS (a sandbox, with
evidence protected by WORM, versioning, soft delete and Cosmos PITR), false positives
on azurerm 4.x attribute names, and the EXC-01 accounts. Each one would be a finding in
production.

## EXC-04

**The WORM policy is unlocked.** Retention is enforced: deletes and overwrites fail
([proof](EVIDENCE.md#worm)). Because it's unlocked, the course teardown can still
remove the container. Production locks it, after which nobody, Microsoft included, can
shorten or remove it.

## EXC-05

**Applies run from the operator's machine, not from CI.** The CI identity is plan-only
by design ([DECISIONS D4](DECISIONS.md#d4-plan-only-ci-identity)). The compensating
controls are: apply only from a commit that passed the gate on `main`, the out-of-band
tripwire records every apply by caller, and nightly drift detection proves state
converged.
