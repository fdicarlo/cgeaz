#!/usr/bin/env bash
# Run your own capstone rubric before the grader does (docs/RUBRIC.md).
# This covers the mechanical half: if any check is red here, it will be red there.
# It cannot judge run history or writing quality — those need time and a human eye.
set -uo pipefail

PASS=0; FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== Docs =="
[ -f README.md ] && ok "README.md exists" || bad "README.md missing (auto-fail trigger)"
for f in docs/CONTROLS.md docs/ARCHITECTURE.md docs/DECISIONS.md docs/EXCEPTIONS.md docs/EVIDENCE.md; do
  [ -f "$f" ] && ok "$f exists" || bad "$f missing"
done
for p in $(grep -ho 'cge-[a-z-]*' stages/01-foundation/policies.tf stages/06-enforcement/main.tf | sort -u | grep -v '^cge-grc-baseline$'); do
  grep -q "$p" docs/CONTROLS.md && ok "CONTROLS.md maps $p" || bad "CONTROLS.md does not mention $p"
  grep -q "\"$p\"" catalog/crosswalk.json && ok "crosswalk maps $p" || bad "catalog/crosswalk.json has no rule for $p"
done
grep -qi "blast radius" stages/06-enforcement/*.tf 2>/dev/null \
  && ok "blast-radius notes present in enforcement stage" \
  || bad "no blast-radius documentation in stages/06-enforcement"

echo "== IaC quality (Tier 0 mirrors) =="
if terraform fmt -check -recursive stages/ >/dev/null 2>&1; then
  ok "terraform fmt clean across stages/"
else
  bad "terraform fmt -check has diffs (run: terraform fmt -recursive stages/)"
fi
if command -v tflint >/dev/null 2>&1; then
  (tflint --init --config "$PWD/.tflint.hcl" >/dev/null 2>&1; tflint --recursive --config "$PWD/.tflint.hcl" >/dev/null 2>&1) \
    && ok "tflint clean" || bad "tflint findings (run: tflint --recursive --config \$PWD/.tflint.hcl)"
else
  echo "  (tflint not installed — CI runs it)"
fi
if command -v checkov >/dev/null 2>&1; then
  checkov --config-file .checkov.yaml >/dev/null 2>&1 && ok "checkov clean (skips justified in .checkov.yaml)" || bad "checkov findings (run: checkov --config-file .checkov.yaml)"
else
  echo "  (checkov not installed — CI runs it)"
fi
for d in stages/*/; do
  name=$(basename "$d")
  if (cd "$d" && terraform init -backend=false -input=false >/dev/null 2>&1 \
      && terraform validate >/dev/null 2>&1); then
    ok "terraform validate: $name"
  else
    bad "terraform validate fails: $name"
  fi
done

echo "== Evidence integrity config =="
grep -rq "azurerm_storage_container_immutability_policy" stages/ \
  && ok "WORM immutability policy present" \
  || bad "no immutability policy resource found"
grep -rq "shared_access_key_enabled *= *false" stages/ \
  && ok "shared keys disabled on evidence storage" \
  || bad "shared_access_key_enabled=false not found"
grep -rq "runId" functions/collect_assessments/*.py \
  && ok "collector stamps run lineage" \
  || bad "collector has no runId stamping"
if grep -qE 'SecurityCenter|management\.azure\.com|requests\.' functions/reports/*.py; then
  bad "report generators reference a live platform API (store-only rule)"
else
  ok "report generators read the store only"
fi

echo "== Identity design =="
if grep -rqE 'role_definition_name *= *"(Owner|Contributor)"' stages/; then
  bad 'a pipeline identity holds Owner/Contributor (whitelist roles only)'
else
  ok "no broad roles granted in Terraform"
fi
grep -rq "identity {" stages/01-foundation/policies.tf stages/06-enforcement/*.tf 2>/dev/null \
  && ok "policy assignments carry identity blocks" \
  || bad "a remediation-effect assignment may be missing its identity block"
grep -q 'default *= *"dry-run"' stages/06-enforcement/variables.tf \
  && ok "enforcement defaults to dry-run" || bad "enforcement is not in dry-run"
if grep -rn "@" --include='*.tf' --include='*.json' --include='*.py' stages catalog functions 2>/dev/null \
     | grep -vE 'example\.com|@parameters|@run|@r\b|@s\b|@odata|app\.' | grep -qE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}'; then
  bad "an email address is committed in code (PII auto-fail trigger)"
else
  ok "no personal email addresses committed in code"
fi

echo "== Operations =="
[ -f .github/workflows/gate.yml ] && ok "CI gate workflow present" || bad "gate workflow missing"
[ -f .github/workflows/drift.yml ] && ok "drift workflow present" || bad "drift workflow missing"
ls policy/*.rego >/dev/null 2>&1 && ok "OPA gate rules present" || bad "no policy/*.rego rules"
if command -v conftest >/dev/null 2>&1; then
  conftest verify -p policy >/dev/null 2>&1 && ok "gate unit tests pass (conftest verify)" || bad "gate unit tests fail (conftest verify -p policy)"
  if conftest test policy/fixtures/bad-plan.json -p policy >/dev/null 2>&1; then
    bad "the gate PASSED the known-bad plan fixture"
  else
    ok "the gate blocks the known-bad plan ($(conftest test policy/fixtures/bad-plan.json -p policy --no-color 2>/dev/null | grep -c '^FAIL') violations)"
  fi
  conftest test policy/fixtures/good-plan.json -p policy >/dev/null 2>&1 && ok "the gate passes the good plan fixture" || bad "the gate fails the good plan fixture"
else
  echo "  (conftest not installed locally — CI still runs it)"
fi
python3 -m unittest discover -s functions/reports/tests >/dev/null 2>&1 && ok "report logic tests pass" || bad "report logic tests fail"

echo "== Secrets (auto-fail trigger) =="
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --no-banner --exit-code 1 >/dev/null 2>&1; then
    ok "gitleaks: no secrets detected"
  else
    bad "gitleaks found potential secrets — fix and rotate BEFORE submitting"
  fi
else
  echo "  (gitleaks not installed — the grader WILL run it; brew install gitleaks)"
fi

echo
echo "self-check: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  echo "Fix the ✗ items before submitting. The grader checks all of this and more."
  exit 1
fi
echo "Mechanical checks green. Now verify the two things this script can't:"
echo "  1. Your timers have real run history (not a burst from last night)."
echo "  2. Every number in your reports traces to a stored document."
