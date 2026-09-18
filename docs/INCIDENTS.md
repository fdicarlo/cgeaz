# Incident Log

Security incidents in the pipeline itself: what happened, how it was contained, and what
changed so it can't recur. A GRC pipeline that hides its own incidents isn't one.

## INC-01: Terraform plan files pushed to a public branch (2026-09-18)

**Severity:** Medium. Usable credentials were exposed publicly for about 20 minutes.
Rotation left nothing usable, and no misuse was observed.

### What happened

| Time (UTC) | Event |
|---|---|
| 13:12 | Commit on branch `fix/day1-live-findings` (PR #2) included `stages/*/tf.plan`. `.gitignore` covered `*.tfplan` and `tfplan`, but not the `tf.plan` name the operator had used. Pushed to the public fork. |
| 13:13 | Noticed in `git status` output straight after pushing. Saved plans embed the stage's prior state, sensitive values included. |
| 13:14 | Branch rewritten without the files and force-pushed. `.gitignore` now covers `*.plan`, `tf.plan` and plan text output. GitHub can still serve the old commit by SHA, so everything in it was treated as disclosed. |
| 13:15 | Plan contents inventoried by attribute (see below). |
| 13:16–13:18 | **Rotated:** key1+key2 on all three evidence-RG storage accounts; all four Cosmos keys; both Log Analytics shared keys; both Function Apps' publishing passwords. |
| 13:20 | App Insights instrumentation key can't be rotated, so the component was **replaced** (`-replace`). The new connection string reached both apps through Terraform. |
| 13:20 | Basic-auth publishing (FTP + WebDeploy) **disabled** on both Function Apps, so no publishing password exists any more. Code deploys now use Entra ID. |
| 13:24 | Pipeline re-verified on the new credentials: code redeployed, collection run `ccd989b4…` and all three reports succeeded. Stages 03/04 plan **No changes**. |

### What was exposed, and whether it was usable

| Secret | Usable when leaked? | Action |
|---|---|---|
| Functions runtime storage keys (`stgrcfunc*`, `stgrcrpt*`) | **Yes** | rotated both keys; apps updated through Terraform |
| Function App publishing (Kudu) passwords | **Yes** | reset; basic auth disabled permanently |
| Log Analytics shared keys | **Yes** (could post fake log data) | both regenerated |
| App Insights instrumentation key | ingestion only | component replaced |
| Evidence storage keys | No (`shared_access_key_enabled = false`) | rotated anyway |
| Cosmos keys | No (`local_authentication_enabled = false`) | rotated anyway |

Evidence integrity was never at risk. The WORM container and Cosmos accept only Entra
ID identities, which is why those keys were useless. That's the zero-keys design doing
its job, and it's also why EXC-01, the runtime storage that does use keys, was the part
that mattered.

### Root cause and corrective actions

- **Root cause:** a gap in the ignore list, plus staging with `git add -A` on a working
  tree that held saved plans.
- **Fixed:** `.gitignore` now covers every plan-file spelling. The operator workflow
  keeps saved plans only under the ignored `.scratch/`.
- **Fixed:** publishing credentials no longer exist (basic auth off), so that class of
  secret can't leak again.
- **Fixed (detection gap):** gitleaks scans content for secret patterns, and a binary
  `tf.plan` (a zip) hides them. The gate's `static` job now fails any change that tracks
  a `*.plan`, `*.tfplan` or `*.tfstate` file.
