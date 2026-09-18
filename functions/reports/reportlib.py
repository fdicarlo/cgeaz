"""Pure report logic — no Azure SDK imports, so it is unit-testable offline
(functions/reports/tests). function_app.py does the I/O: Cosmos in, WORM Blob out.

Every report carries a `provenance` block: the collection run it is pinned to, the
exact Cosmos SQL that produced its inputs, and the generation time. Any number in a
report can be reproduced by re-running those queries against the store.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict

GENERATOR_VERSION = "cgeaz-reports/2.0"

# Severity-based SLAs, measured from FIRST detection (firstSeenAt), not from the day
# the report runs. A due date that moves every morning is not a plan.
SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}
DEFAULT_SEVERITY = "Medium"
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

Q_LATEST_RUN = "SELECT TOP 1 * FROM c ORDER BY c.collectedAt DESC"
Q_RUN_FINDINGS = "SELECT * FROM c WHERE c.runId = @run"
Q_MAPPINGS = "SELECT * FROM c"
Q_FRAMEWORKS = "SELECT * FROM c WHERE c.type = 'framework'"


def trace_query(doc_id: str) -> str:
    return f"SELECT * FROM c WHERE c.id = '{doc_id}'"


def provenance(run: dict | None, now: dt.datetime, queries: dict) -> dict:
    return {
        "generator": GENERATOR_VERSION,
        "generatedAt": now.isoformat(),
        "runId": run.get("runId") if run else None,
        "collectedAt": run.get("collectedAt") if run else None,
        "store": "Cosmos DB `grc` (read-only identity)",
        "queries": queries,
    }


def resolve(finding: dict, mappings: list[dict]) -> dict:
    """Crosswalk a finding: exact rule (source + assessmentId) beats category rules."""
    source = finding.get("source", "defender")
    exact = [m for m in mappings
             if m["match"].get("source") == source
             and m["match"].get("assessmentId") == finding.get("assessmentId")]
    rules = exact or [m for m in mappings
                      if m["match"].get("source") == source
                      and m["match"].get("category") in (finding.get("categories") or [])]
    controls: dict[str, set] = defaultdict(set)
    title = severity = None
    for m in rules:
        controls[m["frameworkId"]].update(m.get("controls", []))
        title = title or m.get("title")
        severity = severity or m.get("severity")
    return {
        "title": finding.get("displayName") if source == "defender" else (title or finding.get("displayName")),
        "severity": finding.get("severity") or severity or DEFAULT_SEVERITY,
        "controls": {fw: sorted(c) for fw, c in controls.items()},
        "mapped": bool(rules),
    }


def _date(iso: str | None, fallback: dt.date) -> dt.date:
    try:
        return dt.datetime.fromisoformat(iso).date() if iso else fallback
    except ValueError:
        return fallback


def poam(run: dict | None, findings: list[dict], mappings: list[dict], now: dt.datetime) -> dict:
    today = now.date()
    items = []
    open_findings = [f for f in findings if f.get("status") == "Unhealthy"]
    for f in open_findings:
        r = resolve(f, mappings)
        detected = _date(f.get("firstSeenAt"), today)
        due = detected + dt.timedelta(days=SLA_DAYS.get(r["severity"], SLA_DAYS[DEFAULT_SEVERITY]))
        items.append({
            "weakness": r["title"],
            "source": f.get("source", "defender"),
            "affectedResource": f.get("resourceId"),
            "severity": r["severity"],
            "controls": r["controls"],
            "firstDetected": detected.isoformat(),
            "scheduledCompletion": due.isoformat(),
            "overdue": due < today,
            "owner": f.get("owner") or f"UNASSIGNED (no owner tag on resource group {f.get('resourceGroup')})",
            "status": "Open",
            "evidenceDocId": f["id"],
            "traceQuery": trace_query(f["id"]),
        })
    items.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 3), i["scheduledCompletion"], i["evidenceDocId"]))
    for n, item in enumerate(items, 1):
        # Stable within a report; the evidenceDocId is the durable identity across reports.
        item["poamId"] = f"POAM-{today:%Y%m%d}-{n:03d}"
    return {
        "report": "poam",
        "provenance": provenance(run, now, {"run": Q_LATEST_RUN, "findings": Q_RUN_FINDINGS + " AND c.status = 'Unhealthy'", "mappings": Q_MAPPINGS}),
        "summary": {
            "openItems": len(items),
            "overdue": sum(i["overdue"] for i in items),
            "bySeverity": dict(Counter(i["severity"] for i in items)),
            "unassigned": sum(i["owner"].startswith("UNASSIGNED") for i in items),
        },
        "items": items,
    }


def sar(run: dict | None, findings: list[dict], mappings: list[dict], now: dt.datetime) -> dict:
    by_status = Counter(f.get("status") or "Unknown" for f in findings)
    by_source = Counter(f.get("source", "defender") for f in findings)
    unhealthy = [f for f in findings if f.get("status") == "Unhealthy"]
    exempt = [f for f in findings if f.get("status") == "Exempt"]
    resolved = {f["id"]: resolve(f, mappings) for f in findings}
    healthy = by_status.get("Healthy", 0)
    tested = healthy + len(unhealthy)
    return {
        "report": "sar",
        "provenance": provenance(run, now, {"run": Q_LATEST_RUN, "findings": Q_RUN_FINDINGS, "mappings": Q_MAPPINGS}),
        "summary": {
            "assessmentsInRun": len(findings),
            "byStatus": dict(by_status),
            "bySource": dict(by_source),
            "passRate": round(healthy / tested, 3) if tested else None,
            "openBySeverity": dict(Counter(resolved[f["id"]]["severity"] for f in unhealthy)),
            "unmapped": sum(not r["mapped"] for r in resolved.values()),
        },
        "findings": [
            {
                "title": resolved[f["id"]]["title"],
                "severity": resolved[f["id"]]["severity"],
                "source": f.get("source", "defender"),
                "resourceId": f.get("resourceId"),
                "controls": resolved[f["id"]]["controls"],
                "firstSeenAt": f.get("firstSeenAt"),
                "evidenceDocId": f["id"],
            }
            for f in sorted(unhealthy, key=lambda x: (SEVERITY_ORDER.get(resolved[x["id"]]["severity"], 3), x["id"]))
        ],
        "exemptions": [
            {"title": resolved[f["id"]]["title"], "resourceId": f.get("resourceId"), "evidenceDocId": f["id"]}
            for f in exempt
        ],
    }


def framework_report(run: dict | None, findings: list[dict], mappings: list[dict],
                     frameworks: list[dict], now: dt.datetime) -> dict:
    """Per-control status for every framework in the catalog, from ONE collection."""
    per_control: dict[tuple, Counter] = defaultdict(Counter)
    evidence: dict[tuple, list] = defaultdict(list)
    for f in findings:
        r = resolve(f, mappings)
        for fw, controls in r["controls"].items():
            for c in controls:
                per_control[(fw, c)][f.get("status") or "Unknown"] += 1
                if f.get("status") == "Unhealthy":
                    evidence[(fw, c)].append(f["id"])
    out = []
    for fw in frameworks:
        rows = []
        for cid, name in fw["controls"].items():
            counts = per_control.get((fw["frameworkId"], cid), Counter())
            if counts.get("Unhealthy"):
                state = "Not satisfied"
            elif counts.get("Healthy"):
                state = "Satisfied"
            else:
                state = "No automated evidence"
            rows.append({
                "control": cid, "name": name, "state": state,
                "healthy": counts.get("Healthy", 0), "unhealthy": counts.get("Unhealthy", 0),
                "exempt": counts.get("Exempt", 0),
                "failingEvidenceDocIds": sorted(evidence.get((fw["frameworkId"], cid), [])),
            })
        states = Counter(r["state"] for r in rows)
        out.append({"frameworkId": fw["frameworkId"], "name": fw["name"],
                    "summary": dict(states), "controls": rows})
    return {
        "report": "framework",
        "provenance": provenance(run, now, {"run": Q_LATEST_RUN, "findings": Q_RUN_FINDINGS,
                                            "mappings": Q_MAPPINGS, "frameworks": Q_FRAMEWORKS}),
        "frameworks": out,
    }


# --- Markdown renderers (humans); the JSON above is for machines. Always both. ---

def _prov_md(p: dict) -> list[str]:
    lines = ["## Provenance", "",
             f"- Collection run: `{p['runId']}` (collected {p['collectedAt']})",
             f"- Generated: {p['generatedAt']} by `{p['generator']}`",
             f"- Source: {p['store']}", "",
             "Reproduce every number above against the store:", "", "```sql"]
    for name, q in p["queries"].items():
        lines.append(f"-- {name}\n{q}")
    return lines + ["```", ""]


def sar_md(r: dict) -> str:
    s = r["summary"]
    lines = ["# Security Assessment Report (SAR)", "",
             f"- **Assessments in run:** {s['assessmentsInRun']}",
             f"- **By status:** " + (", ".join(f"{k}: {v}" for k, v in sorted(s["byStatus"].items())) or "none"),
             f"- **By source:** " + (", ".join(f"{k}: {v}" for k, v in sorted(s["bySource"].items())) or "none"),
             f"- **Pass rate (Healthy / tested):** {s['passRate'] if s['passRate'] is not None else 'n/a'}",
             f"- **Open findings by severity:** " + (", ".join(f"{k}: {v}" for k, v in sorted(s["openBySeverity"].items())) or "none"),
             f"- **Findings with no crosswalk mapping:** {s['unmapped']}", "",
             "## Open findings", ""]
    if not r["findings"]:
        lines += ["None in this collection run.", ""]
    for f in r["findings"]:
        ctrl = "; ".join(f"{fw}: {', '.join(c)}" for fw, c in f["controls"].items()) or "unmapped"
        lines += [f"### {f['title']}", f"- Severity: {f['severity']} · Source: {f['source']}",
                  f"- Resource: `{f['resourceId']}`", f"- Controls: {ctrl}",
                  f"- First seen: {f['firstSeenAt']}",
                  f"- Evidence: `{trace_query(f['evidenceDocId'])}`", ""]
    if r["exemptions"]:
        lines += ["## Active exemptions (risk acceptances)", ""]
        lines += [f"- {e['title']} — `{e['resourceId']}`" for e in r["exemptions"]] + [""]
    return "\n".join(lines + _prov_md(r["provenance"]))


def framework_md(r: dict) -> str:
    lines = ["# Framework Compliance Report", "",
             "One collection, every framework: rows below come from the same assessment "
             "documents, crosswalked through the `mappings` container.", ""]
    for fw in r["frameworks"]:
        lines += [f"## {fw['name']}", "",
                  "Summary: " + ", ".join(f"{k}: {v}" for k, v in sorted(fw["summary"].items())), "",
                  "| Control | Name | State | Healthy | Unhealthy | Exempt |",
                  "|---|---|---|---|---|---|"]
        lines += [f"| {c['control']} | {c['name']} | {c['state']} | {c['healthy']} | {c['unhealthy']} | {c['exempt']} |"
                  for c in fw["controls"]]
        lines.append("")
    return "\n".join(lines + _prov_md(r["provenance"]))


def dated_path(kind: str, ext: str, now: dt.datetime) -> str:
    # Minute-stamped so a manual run never collides with the timer's artifact in WORM.
    return f"{kind}/{now:%Y/%m}/{kind}-{now:%Y-%m-%dT%H%MZ}.{ext}"
