"""CGE-AZ pipeline — Stage 3 collector.

Timer (hourly) -> managed identity -> two evidence sources -> Cosmos.

  1. Defender for Cloud assessments  (Security Reader)
  2. Azure Policy states for this repo's own cge-* controls  (GRC Policy State Reader)

Both land in ONE schema in the `assessments` container (collect once; the crosswalk
in `mappings` does the framework work). The container is APPEND-ONLY per run: one
document per finding per run, id = hash(findingKey + runId). So:
  - any past report stays reproducible forever: `WHERE c.runId = @run` returns exactly
    the documents it was built from, not today's version of them;
  - a retried run upserts the same ids — idempotent, never duplicated;
  - `firstSeenAt` is carried forward from the previous run, so POA&M due dates are
    anchored to first detection, not to "today".
Each sweep ends by appending one document to the `runs` ledger — the run history.

Also captured here, not in the reporter: resource-group `owner` tags. The reporter
must never call a live API (store-only rule), so anything a report needs is recorded
as evidence first.

Deliberately boring: if you can read this file, you can defend this pipeline's lineage.
"""

import datetime
import hashlib
import logging
import os
import time
import uuid
from collections import Counter

import azure.functions as func
import requests
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

ARM = "https://management.azure.com"
ASSESSMENTS_API = "2021-06-01"
POLICY_STATES_API = "2019-10-01"
RESOURCE_GROUPS_API = "2021-04-01"
OWN_POLICY_PREFIX = "cge-"

# Azure Policy compliance vocabulary -> Defender's, so reports see one status field.
POLICY_STATUS = {"NonCompliant": "Unhealthy", "Compliant": "Healthy", "Exempt": "Exempt"}


def _session(credential) -> requests.Session:
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {credential.get_token(f'{ARM}/.default').token}"
    return s


def _paged(session: requests.Session, method: str, url: str):
    """Yield items across ARM pages (nextLink / @odata.nextLink)."""
    while url:
        resp = session.request(method, url, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        yield from payload.get("value", [])
        url = payload.get("nextLink") or payload.get("@odata.nextLink")


def _finding_key(source: str, rule: str, resource_id: str) -> str:
    # Stable identity of a finding across runs: same source + rule + resource.
    return hashlib.sha256(f"{source}|{rule}|{resource_id.lower()}".encode()).hexdigest()[:32]


def _doc_id(finding_key: str, run_id: str) -> str:
    # One document per finding per run. Deterministic, so a retried run is idempotent.
    return hashlib.sha256(f"{finding_key}|{run_id}".encode()).hexdigest()[:32]


def _previous_state(assessments, runs, subscription_id) -> dict:
    """findingKey -> {firstSeenAt, status, statusChangedAt, previousStatus} from the last run."""
    last = list(runs.query_items(
        "SELECT TOP 1 c.runId FROM c WHERE c.subscriptionId = @s ORDER BY c.collectedAt DESC",
        parameters=[{"name": "@s", "value": subscription_id}], partition_key=subscription_id))
    if not last:
        return {}
    rows = assessments.query_items(
        "SELECT c.findingKey, c.firstSeenAt, c.status, c.statusChangedAt, c.previousStatus "
        "FROM c WHERE c.runId = @r",
        parameters=[{"name": "@r", "value": last[0]["runId"]}], partition_key=subscription_id)
    return {r["findingKey"]: r for r in rows}


def _rg_of(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    lowered = [p.lower() for p in parts]
    if "resourcegroups" in lowered:
        i = lowered.index("resourcegroups")
        if i + 1 < len(parts):
            return parts[i + 1].lower()
    return None


def _owners(session, subscription_id) -> dict:
    url = f"{ARM}/subscriptions/{subscription_id}/resourcegroups?api-version={RESOURCE_GROUPS_API}"
    return {
        rg["name"].lower(): (rg.get("tags") or {}).get("owner")
        for rg in _paged(session, "GET", url)
    }


def _defender(session, subscription_id):
    url = (f"{ARM}/subscriptions/{subscription_id}"
           f"/providers/Microsoft.Security/assessments?api-version={ASSESSMENTS_API}")
    for a in _paged(session, "GET", url):
        props = a.get("properties", {})
        details = props.get("resourceDetails", {})
        resource_id = details.get("Id") or details.get("id") or ""
        yield {
            "source": "defender",
            "assessmentId": a["name"],
            "displayName": props.get("displayName"),
            "status": props.get("status", {}).get("code"),
            "statusCause": props.get("status", {}).get("cause"),
            "severity": props.get("metadata", {}).get("severity"),
            "categories": props.get("metadata", {}).get("categories") or [],
            "resourceId": resource_id,
        }


def _policy(session, subscription_id):
    url = (f"{ARM}/subscriptions/{subscription_id}/providers/Microsoft.PolicyInsights"
           f"/policyStates/latest/queryResults?api-version={POLICY_STATES_API}")
    for s in _paged(session, "POST", url):
        definition = s.get("policyDefinitionName", "")
        if not definition.startswith(OWN_POLICY_PREFIX):
            continue  # built-in CSF initiative results already arrive via Defender
        yield {
            "source": "azure-policy",
            "assessmentId": definition,
            "displayName": definition,  # human title lives in the mappings catalog
            "status": POLICY_STATUS.get(s.get("complianceState"), s.get("complianceState")),
            "statusCause": s.get("policyDefinitionAction"),
            "severity": None,  # severity for own controls is catalog data (mappings)
            "categories": [],
            "resourceId": s.get("resourceId", ""),
            "policyAssignmentId": s.get("policyAssignmentId"),
            "policyDefinitionReferenceId": s.get("policyDefinitionReferenceId"),
        }


def _collect(trigger: str) -> dict:
    started = time.monotonic()
    subscription_id = os.environ["SUBSCRIPTION_ID"]

    # DefaultAzureCredential resolves to the Function App's managed identity in Azure
    # (and to your `az login` session when run locally). No keys, anywhere.
    credential = DefaultAzureCredential()
    session = _session(credential)
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential).get_database_client(
        os.environ["COSMOS_DATABASE"])
    assessments = db.get_container_client("assessments")
    runs = db.get_container_client("runs")

    run_id = str(uuid.uuid4())
    collected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    owners = _owners(session, subscription_id)
    previous = _previous_state(assessments, runs, subscription_id)

    counts: dict[str, Counter] = {"defender": Counter(), "azure-policy": Counter()}
    errors = []
    written = 0

    for source, rows in (("defender", _defender), ("azure-policy", _policy)):
        try:
            for row in rows(session, subscription_id):
                key = _finding_key(source, row["assessmentId"], row["resourceId"])
                prior = previous.get(key, {})
                status_changed = prior.get("status") != row["status"]
                rg = _rg_of(row["resourceId"])
                assessments.upsert_item({
                    "id": _doc_id(key, run_id),
                    "findingKey": key,
                    "subscriptionId": subscription_id,
                    **row,
                    "resourceGroup": rg,
                    "owner": owners.get(rg) if rg else None,
                    "firstSeenAt": prior.get("firstSeenAt", collected_at),
                    "statusChangedAt": collected_at if status_changed else prior.get("statusChangedAt", collected_at),
                    "previousStatus": prior.get("status") if status_changed else prior.get("previousStatus"),
                    "collectedAt": collected_at,
                    "runId": run_id,
                })
                counts[source][row["status"] or "Unknown"] += 1
                written += 1
        except requests.HTTPError as exc:
            # One source failing must not erase the other's evidence — record it and move on.
            logging.exception("collector source %s failed", source)
            errors.append({"source": source, "error": str(exc)[:500]})

    # The ledger entry is written LAST: a run exists in the history only once its
    # documents do. Reports pin to the newest ledger entry.
    runs.create_item({
        "id": run_id,
        "subscriptionId": subscription_id,
        "runId": run_id,
        "collectedAt": collected_at,
        "trigger": trigger,
        "written": written,
        "counts": {src: dict(c) for src, c in counts.items()},
        "errors": errors,
        "durationMs": int((time.monotonic() - started) * 1000),
    })
    logging.info("collection run %s (%s): %d documents, %d source errors",
                 run_id, trigger, written, len(errors))
    return {"runId": run_id, "written": written, "collectedAt": collected_at,
            "counts": {src: dict(c) for src, c in counts.items()}, "errors": errors}


@app.timer_trigger(schedule="0 0 * * * *", arg_name="timer", run_on_startup=False)
def collect_scheduled(timer: func.TimerRequest) -> None:
    """Hourly, on the hour (UTC). Sandbox cadence: see docs/DECISIONS.md D11."""
    _collect("timer")


@app.route(route="collect", auth_level=func.AuthLevel.FUNCTION)
def collect_now(req: func.HttpRequest) -> func.HttpResponse:
    """Manual trigger for labs and demos: hit the endpoint, get the run summary."""
    result = _collect("http")
    return func.HttpResponse(
        f"run {result['runId']}: {result['written']} documents at {result['collectedAt']} "
        f"counts={result['counts']} errors={len(result['errors'])}\n",
        status_code=200,
    )
