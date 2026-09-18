"""CGE-AZ pipeline — Stage 4 report generators.

Reports read from Cosmos ONLY — never from live services. Every number in every
artifact resolves to a stored, timestamped document, and each artifact embeds the
queries that reproduce it (reportlib.provenance). A report that reads live data is a
report whose numbers can't be reproduced tomorrow; a report that reads the store is a
fact with a receipt. The reporter's identity enforces this: Cosmos Data Reader and
blob write on `reports`, nothing that can reach a platform API.

Generators (timers run AFTER the 06:00 UTC collection sweep):
  POA&M      xlsx + json   daily   06:15 UTC
  Framework  md + json     daily   06:30 UTC   (NIST CSF 2.0 + 800-53 via the crosswalk)
  SAR        md + json     weekly  Mon 07:00 UTC
Each also has an HTTP trigger for labs and demos.
"""

import datetime
import hashlib
import io
import json
import logging
import os

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from openpyxl import Workbook

import reportlib

app = func.FunctionApp()


def _store():
    credential = DefaultAzureCredential()
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential).get_database_client(
        os.environ["COSMOS_DATABASE"])
    blobs = BlobServiceClient(
        account_url=os.environ["REPORTS_ACCOUNT_URL"], credential=credential
    ).get_container_client(os.environ["REPORTS_CONTAINER"])
    return db, blobs


def _query(container, sql, params=None):
    return list(container.query_items(sql, parameters=params or [], enable_cross_partition_query=True))


def _inputs(db):
    """Pin to the newest completed collection run in the ledger, then read its findings."""
    runs = _query(db.get_container_client("runs"), reportlib.Q_LATEST_RUN)
    run = runs[0] if runs else None
    findings = (
        _query(db.get_container_client("assessments"), reportlib.Q_RUN_FINDINGS,
               [{"name": "@run", "value": run["runId"]}])
        if run else []
    )
    mappings = _query(db.get_container_client("mappings"), reportlib.Q_MAPPINGS)
    return run, findings, mappings


def _put(blobs, path: str, data: bytes) -> dict:
    # overwrite=False: WORM would refuse anyway; this makes intent explicit in code.
    blobs.upload_blob(path, data, overwrite=False)
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest()}


def generate_poam() -> dict:
    db, blobs = _store()
    now = datetime.datetime.now(datetime.timezone.utc)
    run, findings, mappings = _inputs(db)
    report = reportlib.poam(run, findings, mappings, now)

    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    cols = ["poamId", "weakness", "affectedResource", "severity", "controls", "firstDetected",
            "scheduledCompletion", "overdue", "owner", "status", "evidenceDocId", "traceQuery"]
    ws.append(cols)
    for item in report["items"]:
        ws.append([json.dumps(item[c]) if isinstance(item[c], dict) else item[c] for c in cols])
    meta = wb.create_sheet("Provenance")
    for k, v in report["provenance"].items():
        meta.append([k, json.dumps(v) if isinstance(v, dict) else v])
    xlsx = io.BytesIO()
    wb.save(xlsx)

    xlsx_art = _put(blobs, reportlib.dated_path("poam", "xlsx", now), xlsx.getvalue())
    report["artifacts"] = {"xlsx": xlsx_art}
    json_art = _put(blobs, reportlib.dated_path("poam", "json", now), json.dumps(report, indent=2).encode())
    logging.info("POA&M: %d items (run %s) -> %s", report["summary"]["openItems"], report["provenance"]["runId"], xlsx_art["path"])
    return {"items": report["summary"]["openItems"], "runId": report["provenance"]["runId"],
            "xlsx": xlsx_art, "json": json_art}


def generate_sar() -> dict:
    db, blobs = _store()
    now = datetime.datetime.now(datetime.timezone.utc)
    run, findings, mappings = _inputs(db)
    report = reportlib.sar(run, findings, mappings, now)
    md = _put(blobs, reportlib.dated_path("sar", "md", now), reportlib.sar_md(report).encode())
    js = _put(blobs, reportlib.dated_path("sar", "json", now), json.dumps(report, indent=2).encode())
    logging.info("SAR: %d open findings (run %s) -> %s", len(report["findings"]), report["provenance"]["runId"], md["path"])
    return {"findings": len(report["findings"]), "runId": report["provenance"]["runId"], "md": md, "json": js}


def generate_framework() -> dict:
    db, blobs = _store()
    now = datetime.datetime.now(datetime.timezone.utc)
    run, findings, mappings = _inputs(db)
    frameworks = _query(db.get_container_client("frameworks"), reportlib.Q_FRAMEWORKS)
    report = reportlib.framework_report(run, findings, mappings, frameworks, now)
    md = _put(blobs, reportlib.dated_path("framework", "md", now), reportlib.framework_md(report).encode())
    js = _put(blobs, reportlib.dated_path("framework", "json", now), json.dumps(report, indent=2).encode())
    logging.info("Framework report: %d frameworks (run %s) -> %s", len(report["frameworks"]), report["provenance"]["runId"], md["path"])
    return {"frameworks": {f["frameworkId"]: f["summary"] for f in report["frameworks"]},
            "runId": report["provenance"]["runId"], "md": md, "json": js}


@app.timer_trigger(schedule="0 15 6 * * *", arg_name="timer", run_on_startup=False)
def poam_daily(timer: func.TimerRequest) -> None:
    generate_poam()


@app.timer_trigger(schedule="0 30 6 * * *", arg_name="timer", run_on_startup=False)
def framework_daily(timer: func.TimerRequest) -> None:
    generate_framework()


@app.timer_trigger(schedule="0 0 7 * * 1", arg_name="timer", run_on_startup=False)
def sar_weekly(timer: func.TimerRequest) -> None:
    generate_sar()


@app.route(route="poam", auth_level=func.AuthLevel.FUNCTION)
def poam_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_poam()) + "\n", status_code=200)


@app.route(route="framework", auth_level=func.AuthLevel.FUNCTION)
def framework_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_framework()) + "\n", status_code=200)


@app.route(route="sar", auth_level=func.AuthLevel.FUNCTION)
def sar_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_sar()) + "\n", status_code=200)
