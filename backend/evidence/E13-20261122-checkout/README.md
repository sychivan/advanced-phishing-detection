# E13 — fresh checkout audit,22 November 2026

This record was produced by an assisted code review and actual execution in a disposable Linux checkout based on `929790ec4b22c6dafc1e7ac39026fad0ad75efa0` after the PR 6 merge. The source manifest identifies the code and saved model tested with the fixes in this revision. This is not a GitHub Actions run or a new Windows/browser/Google-account test.

## Results

| Check | Observed result |
|---|---|
| Python |80 cases and 39 subtests passed; zero failures/skips; exit 0 |
| JavaScript dashboard |18 cases passed; zero failures/skips; exit 0 |
| Configured SQLite |Setup and save/read/invalid-reference rollback passed; both exit 0 |
| Legacy SQLite |Initialization and saved-artifact storage check passed; both exit 0 |
| Real loopback HTTP |Flask → V1 → SQLite workflow passed; exit 0 |
| Source syntax |28 Python files and two HTML inline JavaScript scripts parsed |

Runtime: Python 3.12.14, Flask 3.1.3, pytest 9.2.0, scikit-learn 1.9.1, joblib 1.6.0, NumPy 2.5.4, SciPy 1.18.1 and Node.js 24.22.3. The exact versions and step exit codes are in `summary.json`.

## Reproduce

Install the root README's backend, ML and development dependencies, then run from the repository root:

```text
python scripts/verify_project.py
```

The runner copies source to a temporary directory without private configuration, CSV datasets, original databases or inherited credentials. Python socket connections are blocked during unit/storage checks. The separate HTTP smoke step permits loopback only and starts its own temporary services and database. JavaScript fetch and Google calls are mocked. The legacy provider and Claude functions are mocked. No email is sent; no live mailbox is accessed; no corpus evaluation or model training runs.

The HTTP step reproduced Phishing 85.92 and Safe 40.24 from the exact synthetic input text. It verified original score/classification/reasons after quarantine and restore, correct feedback identity, admin approval, an unscored record kept separate from Low, deletion, and a 401 for reuse of the revoked bearer. Other SQLite fixtures return 36.98 and 80.91; they are different input texts and not replacements for the demonstration values.

## Fixes covered

- Missing scores stay null and display as No score, including statistics and filtering; genuine 0 stays scored.
- Latest-analysis order is consistent across list, detail and restore.
- Restoration attributes feedback to the authenticated account without inventing a submitter.
- Delayed responses cannot overwrite a new route/session; closed drawers clear private text.
- Partial bulk failures preserve failed rows for retry and reconcile successful operations.
- Mock location changes preserve the score.
- SQLite smoke modules are import-safe and use disposable/configurable paths.
- Oversized route IDs return structured 404 responses instead of SQLite overflow errors.
- The retained legacy prototype rejects absent CSRF tokens, tolerates malformed links and avoids logging private exception text.

The V1 artifact and historical `ml/reports/evaluation.json` remain byte-identical to the base revision. The dependency file now lists direct dependencies matching the estimator's saved scikit-learn version. The obsolete duplicate ZIP and empty placeholder were removed; earlier UI source remains under `archive/`.

## Evidence limits

E11's 74 Python cases plus 12 subtests came from an older local workspace containing extra ML experiment suites absent from GitHub. Do not add E11 totals to E13 or report them as the checkout suite. E13 includes the new regression cases and is separately reproducible.

Passing these checks does not prove general phishing accuracy, full security, production readiness, live Google/provider compatibility, or unchanged Gmail labels/unread state. The labelled CSV is absent. Original-scope functions such as attachment scanning, automatic mailbox quarantine, notification emails,2FA and measured load/uptime requirements remain outside the canonical MVP.
