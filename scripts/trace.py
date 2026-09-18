#!/usr/bin/env python3
"""The auditor's test, on demand: take the newest reports out of WORM storage and
prove every number resolves to stored evidence.

    .venv/bin/python scripts/trace.py            # newest POA&M + SAR
    .venv/bin/python scripts/trace.py --item 3   # trace POA&M line item 3 in full

For the POA&M line item it runs the item's own traceQuery against Cosmos and compares
field by field; for the SAR it re-runs the embedded provenance queries and recomputes
the headline counts. Output: evidence/trace-<date>.md. Exits non-zero on any mismatch.

Runs as YOU (az login): the deployer holds Cosmos data read (stage 03) and blob read on
the evidence account. Needs: pip install azure-cosmos azure-identity azure-storage-blob
"""

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys
from collections import Counter

from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

ROOT = pathlib.Path(__file__).resolve().parent.parent


def tf_output(stage: str, name: str) -> str:
    return subprocess.check_output(
        ["terraform", f"-chdir={ROOT / 'stages' / stage}", "output", "-raw", name], text=True).strip()


def newest(container, prefix: str, suffix: str) -> tuple[str, dict]:
    blobs = [b for b in container.list_blobs(name_starts_with=prefix) if b.name.endswith(suffix)]
    if not blobs:
        sys.exit(f"no {prefix}*{suffix} in the reports container yet")
    latest = max(blobs, key=lambda b: b.creation_time)
    return latest.name, json.loads(container.download_blob(latest.name).readall())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--item", type=int, default=1, help="POA&M line item to trace (1-based)")
    args = ap.parse_args()

    cred = DefaultAzureCredential()
    account = tf_output("03-evidence-store", "evidence_storage_account")
    reports = BlobServiceClient(f"https://{account}.blob.core.windows.net", credential=cred) \
        .get_container_client("reports")
    db = CosmosClient(tf_output("03-evidence-store", "cosmos_endpoint"), cred).get_database_client("grc")
    assessments = db.get_container_client("assessments")
    runs = db.get_container_client("runs")

    def q(container, sql, params=None):
        return list(container.query_items(sql, parameters=params or [], enable_cross_partition_query=True))

    lines, ok = [f"# Evidence trace — {dt.datetime.now(dt.timezone.utc):%Y-%m-%dT%H:%MZ}", ""], True

    # --- 1. POA&M line item -> its Cosmos document -> its collection run ---
    path, poam = newest(reports, "poam/", ".json")
    prov = poam["provenance"]
    lines += [f"## POA&M: `reports/{path}`", "",
              f"Pinned to collection run `{prov['runId']}` ({prov['collectedAt']}). "
              f"Open items: {poam['summary']['openItems']}.", ""]
    if poam["items"]:
        item = poam["items"][min(args.item, len(poam["items"])) - 1]
        doc = (q(assessments, item["traceQuery"]) or [None])[0]
        lines += [f"### Line item {item['poamId']}: {item['weakness']}", "",
                  f"Trace query (embedded in the report): `{item['traceQuery']}`", ""]
        if not doc:
            ok = False
            lines.append("**MISMATCH: no document answers the trace query.**")
        else:
            checks = [
                ("affected resource", item["affectedResource"], doc.get("resourceId")),
                ("status", "Open (Unhealthy)", "Open (Unhealthy)" if doc.get("status") == "Unhealthy" else doc.get("status")),
                ("first detected", item["firstDetected"], (doc.get("firstSeenAt") or "")[:10]),
                ("collection run", prov["runId"], doc.get("runId")),
                ("owner", item["owner"],
                 doc.get("owner") or f"UNASSIGNED (no owner tag on resource group {doc.get('resourceGroup')})"),
            ]
            lines += ["| Field | In the report | In the store | |", "|---|---|---|---|"]
            for name, rep, store in checks:
                match = rep == store
                ok &= match
                lines.append(f"| {name} | `{rep}` | `{store}` | {'✅' if match else '❌'} |")
            ledger = q(runs, "SELECT * FROM c WHERE c.runId = @r", [{"name": "@r", "value": doc["runId"]}])
            lines += ["", "Source document (as stored):", "", "```json",
                      json.dumps({k: v for k, v in doc.items() if not k.startswith("_")}, indent=2), "```", ""]
            if ledger:
                lines += [f"Run ledger entry: trigger `{ledger[0]['trigger']}`, {ledger[0]['written']} documents, "
                          f"counts {json.dumps(ledger[0]['counts'])}.", ""]
    else:
        lines += ["No open items in this run (nothing to trace line-by-line; the SAR check below still runs).", ""]

    # --- 2. SAR headline numbers -> recomputed from the store with the embedded queries ---
    path, sar = newest(reports, "sar/", ".json")
    prov = sar["provenance"]
    findings = q(assessments, prov["queries"]["findings"], [{"name": "@run", "value": prov["runId"]}]) if prov["runId"] else []
    recomputed = {
        "assessmentsInRun": len(findings),
        "byStatus": dict(Counter(f.get("status") or "Unknown" for f in findings)),
        "bySource": dict(Counter(f.get("source", "defender") for f in findings)),
    }
    lines += [f"## SAR: `reports/{path}`", "",
              f"Re-ran `{prov['queries']['findings']}` with `@run = {prov['runId']}`.", "",
              "| Number | In the report | Recomputed from the store | |", "|---|---|---|---|"]
    for key, value in recomputed.items():
        match = sar["summary"][key] == value
        ok &= match
        lines.append(f"| {key} | `{json.dumps(sar['summary'][key], sort_keys=True)}` | `{json.dumps(value, sort_keys=True)}` | {'✅' if match else '❌'} |")

    lines += ["", f"**RESULT: {'every traced number resolves to stored evidence' if ok else 'MISMATCH — investigate before submitting'}.**", ""]
    out = ROOT / "evidence" / f"trace-{dt.date.today():%Y-%m-%d}.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines))
    print("\n".join(lines))
    print(f"saved: {out.relative_to(ROOT)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
