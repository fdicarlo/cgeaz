"""Offline tests for the report logic: python3 -m unittest discover -s functions/reports/tests"""

import datetime as dt
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import reportlib  # noqa: E402

CATALOG = HERE.parent.parent.parent / "catalog"
NOW = dt.datetime(2026, 10, 1, 6, 15, tzinfo=dt.timezone.utc)
RUN = {"runId": "run-1", "collectedAt": "2026-10-01T06:00:00+00:00"}


def _mappings():
    """Expand catalog/crosswalk.json exactly the way scripts/seed_catalog.py does."""
    rules = json.loads((CATALOG / "crosswalk.json").read_text())["rules"]
    return [
        {"frameworkId": fw, "match": r["match"], "controls": c, "title": r.get("title"), "severity": r.get("severity")}
        for r in rules for fw, c in r["controls"].items()
    ]


def _frameworks():
    return json.loads((CATALOG / "frameworks.json").read_text())["frameworks"]


FINDINGS = [
    {"id": "a1", "source": "defender", "assessmentId": "g1", "displayName": "Storage should restrict network access",
     "status": "Unhealthy", "severity": "High", "categories": ["Data"], "resourceId": "/subscriptions/s/resourceGroups/rg/x",
     "resourceGroup": "rg", "owner": "team@example.com", "firstSeenAt": "2026-08-01T05:00:00+00:00"},
    {"id": "a2", "source": "defender", "assessmentId": "g2", "displayName": "MFA for owners",
     "status": "Healthy", "severity": "High", "categories": ["IdentityAndAccess"], "resourceId": "/subscriptions/s"},
    {"id": "p1", "source": "azure-policy", "assessmentId": "cge-audit-storage-shared-key", "displayName": "cge-audit-storage-shared-key",
     "status": "Unhealthy", "severity": None, "categories": [], "resourceId": "/subscriptions/s/resourceGroups/rg2/y",
     "resourceGroup": "rg2", "owner": None, "firstSeenAt": "2026-09-30T00:00:00+00:00"},
    {"id": "p2", "source": "azure-policy", "assessmentId": "cge-audit-storage-shared-key", "displayName": "cge-audit-storage-shared-key",
     "status": "Exempt", "categories": [], "resourceId": "/subscriptions/s/resourceGroups/rg3/func"},
    {"id": "u1", "source": "defender", "assessmentId": "g9", "displayName": "Something new",
     "status": "NotApplicable", "categories": ["Quantum"], "resourceId": "/subscriptions/s/z"},
]


class ResolveTests(unittest.TestCase):
    def test_exact_policy_rule_beats_category_and_supplies_title_and_severity(self):
        r = reportlib.resolve(FINDINGS[2], _mappings())
        self.assertEqual(r["severity"], "Medium")
        self.assertEqual(r["title"], "Storage accounts should disable shared-key authorization")
        self.assertEqual(r["controls"]["nist-csf-2.0"], ["PR.AA"])
        self.assertIn("IA-5", r["controls"]["nist-800-53-r5"])

    def test_defender_category_crosswalks_to_both_frameworks(self):
        r = reportlib.resolve(FINDINGS[0], _mappings())
        self.assertEqual(r["controls"]["nist-csf-2.0"], ["PR.DS"])
        self.assertEqual(r["controls"]["nist-800-53-r5"], ["SC-28", "SC-8"])

    def test_unknown_category_is_reported_unmapped_not_dropped(self):
        self.assertFalse(reportlib.resolve(FINDINGS[4], _mappings())["mapped"])


class PoamTests(unittest.TestCase):
    def test_due_date_anchored_to_first_detection_not_today(self):
        items = {i["evidenceDocId"]: i for i in reportlib.poam(RUN, FINDINGS, _mappings(), NOW)["items"]}
        self.assertEqual(items["a1"]["scheduledCompletion"], "2026-08-31")  # High = 30d from 08-01
        self.assertTrue(items["a1"]["overdue"])
        self.assertEqual(items["p1"]["scheduledCompletion"], "2026-12-29")  # Medium = 90d

    def test_only_unhealthy_items_and_owner_resolution(self):
        r = reportlib.poam(RUN, FINDINGS, _mappings(), NOW)
        self.assertEqual(r["summary"]["openItems"], 2)
        self.assertEqual(r["summary"]["unassigned"], 1)
        self.assertEqual(r["items"][0]["owner"], "team@example.com")
        self.assertEqual(r["items"][0]["poamId"], "POAM-20261001-001")

    def test_every_item_carries_a_trace_query(self):
        for i in reportlib.poam(RUN, FINDINGS, _mappings(), NOW)["items"]:
            self.assertEqual(i["traceQuery"], f"SELECT * FROM c WHERE c.id = '{i['evidenceDocId']}'")

    def test_empty_store_is_clean(self):
        r = reportlib.poam(None, [], _mappings(), NOW)
        self.assertEqual(r["summary"]["openItems"], 0)
        self.assertIsNone(r["provenance"]["runId"])


class SarTests(unittest.TestCase):
    def test_counts_are_reproducible_from_the_findings(self):
        s = reportlib.sar(RUN, FINDINGS, _mappings(), NOW)["summary"]
        self.assertEqual(s["assessmentsInRun"], 5)
        self.assertEqual(s["byStatus"]["Unhealthy"], 2)
        self.assertEqual(s["passRate"], round(1 / 3, 3))
        self.assertEqual(s["unmapped"], 1)

    def test_exemptions_are_listed(self):
        self.assertEqual(len(reportlib.sar(RUN, FINDINGS, _mappings(), NOW)["exemptions"]), 1)

    def test_markdown_embeds_provenance_queries(self):
        md = reportlib.sar_md(reportlib.sar(RUN, FINDINGS, _mappings(), NOW))
        self.assertIn("run-1", md)
        self.assertIn(reportlib.Q_RUN_FINDINGS, md)


class FrameworkTests(unittest.TestCase):
    def test_one_collection_many_frameworks(self):
        r = reportlib.framework_report(RUN, FINDINGS, _mappings(), _frameworks(), NOW)
        by_fw = {f["frameworkId"]: {c["control"]: c for c in f["controls"]} for f in r["frameworks"]}
        self.assertEqual(by_fw["nist-csf-2.0"]["PR.DS"]["state"], "Not satisfied")
        self.assertEqual(by_fw["nist-csf-2.0"]["PR.AA"]["state"], "Not satisfied")  # p1 fails, a2 passes
        self.assertEqual(by_fw["nist-csf-2.0"]["RC.RP"]["state"], "No automated evidence")
        self.assertEqual(by_fw["nist-800-53-r5"]["SC-28"]["failingEvidenceDocIds"], ["a1"])
        self.assertIn("|", reportlib.framework_md(r))

    def test_paths_are_minute_stamped(self):
        self.assertEqual(reportlib.dated_path("sar", "md", NOW), "sar/2026/10/sar-2026-10-01T0615Z.md")


if __name__ == "__main__":
    unittest.main()
