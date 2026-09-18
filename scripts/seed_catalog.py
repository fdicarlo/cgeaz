#!/usr/bin/env python3
"""Seed the framework catalogs and the crosswalk into the evidence store.

    COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint) \
        python3 scripts/seed_catalog.py

Source of truth is catalog/*.json in this repo — reviewed like code. This script makes
the store match it: upserts every framework/mapping document and deletes mapping
documents that are no longer in the file (a removed mapping must stop counting).
Idempotent. Authenticates as YOU (az login); stage 03 grants the deployer the Cosmos
data-plane contributor role for exactly this job.

Adding NIST 800-53 (or any framework) is a data change: add it to catalog/, re-run this.
Nothing is re-collected.
"""

import hashlib
import json
import os
import pathlib
import sys

from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

ROOT = pathlib.Path(__file__).resolve().parent.parent / "catalog"


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def main() -> int:
    endpoint = os.environ.get("COSMOS_ENDPOINT")
    if not endpoint:
        print("Set COSMOS_ENDPOINT (see docstring).", file=sys.stderr)
        return 1

    frameworks = json.loads((ROOT / "frameworks.json").read_text())["frameworks"]
    rules = json.loads((ROOT / "crosswalk.json").read_text())["rules"]
    version = _hash({"frameworks": frameworks, "rules": rules})

    db = CosmosClient(endpoint, DefaultAzureCredential()).get_database_client(
        os.environ.get("COSMOS_DATABASE", "grc"))
    fw_c = db.get_container_client("frameworks")
    map_c = db.get_container_client("mappings")

    for fw in frameworks:
        fw_c.upsert_item({"id": fw["frameworkId"], "type": "framework", "catalogVersion": version, **fw})

    wanted = set()
    for rule in rules:
        for framework_id, controls in rule["controls"].items():
            doc_id = _hash({"match": rule["match"], "frameworkId": framework_id})
            wanted.add((framework_id, doc_id))
            map_c.upsert_item({
                "id": doc_id,
                "frameworkId": framework_id,
                "match": rule["match"],
                "controls": controls,
                "title": rule.get("title"),
                "severity": rule.get("severity"),
                "catalogVersion": version,
            })

    stale = [
        (d["frameworkId"], d["id"])
        for d in map_c.query_items("SELECT c.id, c.frameworkId FROM c", enable_cross_partition_query=True)
        if (d["frameworkId"], d["id"]) not in wanted
    ]
    for framework_id, doc_id in stale:
        map_c.delete_item(doc_id, partition_key=framework_id)

    print(f"catalog {version}: {len(frameworks)} frameworks, {len(wanted)} mappings upserted, "
          f"{len(stale)} stale mappings removed -> {endpoint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
