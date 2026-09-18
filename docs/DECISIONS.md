# Design Decisions

The why behind choices that aren't obvious from the code. Each entry records what was
decided, what else was considered, and what it costs.

## D1. Two own controls that extend the pipeline's zero-keys rule

**Decision:** the capstone's own policies are `cge-audit-cosmos-local-auth` and
`cge-audit-storage-shared-key`, both **Audit**.
**Why:** the pipeline already refuses keys for itself (Cosmos local auth off, evidence
storage shared keys off). A GRC system that holds itself to a standard it doesn't
check anywhere else is only half a control. These two carry the rule to every account
in the sandbox, with the same data model (policy state → collector → Cosmos → POA&M)
as Defender findings.
**Why Audit:** both are new controls, and the rubric's rule is audit first, deny where
earned. Deny on shared keys would break the Functions runtime ([EXC-01](EXCEPTIONS.md#exc-01)).
Deny on Cosmos local auth becomes a one-line change once compliance data shows nothing
depends on keys. The gate has an equivalent rule (`cosmos.rego`, `storage.rego`) that
blocks the same mistake at the pull request, before Azure Policy would see it.

## D2. The evidence store is append-only per run

**Decision:** `assessments` holds one document per finding **per run**
(`id = hash(findingKey + runId)`) instead of one document per finding, overwritten on
every sweep (the starter's design).
**Why:** the rubric says any report number must be reproducible by a stored query. With
overwrite-in-place, a SAR from last Monday references documents that have since changed
under it. With append-only, `WHERE c.runId = @run` returns exactly what the report was
built from, forever.
**Cost:** storage grows with runs × findings. At sandbox scale (a few hundred findings,
4 runs/day) that's a few MB a month on serverless Cosmos, which is pennies. Production
would add a TTL longer than the evidence retention obligation.

## D3. POA&M due dates anchor to first detection

**Decision:** `scheduledCompletion = firstSeenAt + SLA(severity)`. The collector carries
`firstSeenAt` forward from the previous run.
**Why:** the starter computed `today + SLA`, which moves every due date one day later
each morning, so no item could ever become overdue. A POA&M is a plan, and a plan's
dates don't slide.

## D4. Plan-only CI identity

**Decision:** CI gets a custom **GRC CI Planner** role (`*/read` plus the list-keys and
config actions that a Terraform refresh calls) and state **Blob Data Reader**, instead
of the lab's Contributor + Blob Data Contributor. Plans run with `-lock=false`.
**Why:** the gate and drift detection only ever plan. Contributor would let a malicious
PR's workflow change the sandbox through the pull_request federation. With a plan-only
role, a compromised workflow can read but not act.
**Cost:** applies stay manual ([EXC-05](EXCEPTIONS.md#exc-05)), and the role still
includes `listKeys`, so it can read the Functions runtime keys (EXC-01 accounts). That
is why the federation names only this fork's `main` and `pull_request` subjects.
Plans skip the state lock, which is safe because a plan never writes state.

## D5. Collector also reads Azure Policy states (own controls only)

**Decision:** the collector pulls `policyStates/latest` for `cge-*` definitions only,
through a two-action custom role, and stores them in the same schema as Defender
assessments.
**Why:** "collect once" should cover every control the repo defines. Without this, the
two own controls would be visible in the Azure portal but absent from every report.
Built-in CSF initiative results are filtered out because Defender already reports them,
and counting them twice would inflate the SAR.
**Why a custom role:** Reader would give the collector every `*/read` in the
subscription. The job needs two Policy Insights actions.

## D6. Crosswalk as data, reviewed like code

**Decision:** `catalog/frameworks.json` + `catalog/crosswalk.json` are the source of
truth. `scripts/seed_catalog.py` makes Cosmos match them, and deletes mappings that
were removed. Exact rules (a policy definition name) take precedence over Defender
category rules.
**Why:** adding NIST 800-53 took a JSON edit and a re-seed, with no re-collection. The
framework report shows both frameworks from the same run. Findings with no mapping are
counted as `unmapped` in the SAR instead of being dropped.

## D7. Owner resolution happens at collection, not at reporting

**Decision:** the collector stores each resource group's `owner` tag on the finding.
**Why:** the reporter's identity can't call ARM (store-only rule, enforced by RBAC).
Anything a report needs has to be evidence first. A missing tag is reported as
`UNASSIGNED (no owner tag on resource group …)`, which is itself a finding for the
`cge-require-env-tag-rg` owner.

## D8. The foundation is deployable from an empty subscription

**Decision:** the Activity Log diagnostic setting and the budget, which the labs create
by hand with `az rest`, are Terraform resources in stage 01, and `scripts/deploy.sh`
runs every stage in order. Lab-built resources can be adopted with the `terraform
import` commands at the top of `monitoring.tf`.
**Why:** the rubric's README requirement is deploy from an empty subscription. A
foundation that depends on two hand-run scripts isn't fully code.

## D9. No stage 5 narrative

**Decision:** the optional AI weekly digest isn't built.
**Why:** it's extra credit, and the rubric scores its absence at zero penalty. The
effort went into traceability instead (D2, D3, the trace script), which the rubric does
score. The report JSON already has the shape a digest would take as input: grounded,
with provenance.

## D10. Regions

**Decision:** the foundation is in `eastus`, the evidence store in `eastus2`, and
Functions in `centralus`. These are the course-validated defaults.
**Why:** the free account's Consumption (Y1) quota is zero in most US regions, and
`eastus` lacks Cosmos capacity ([VALIDATION-LOG F8/F9](VALIDATION-LOG.md)). The data is
synthetic sandbox posture with no residency obligation. A real EU workload would pin
every stage to an EU region and add an allowed-locations Deny to the baseline.

## D11. Collector every 6 hours, reports after the 06:00 sweep

**Decision:** collector `0 0 */6 * * *`, POA&M 06:15, framework 06:30, SAR Monday 07:00,
drift 08:00 (all UTC).
**Why:** Defender re-evaluates on a similar cadence, so more frequent runs add nothing.
Four runs a day builds a dense run history. Each report runs after a fresh sweep, and
drift runs after the reports, so a drift issue can cite the same day's evidence.
