# PhishGuard

PhishGuard analyses submitted email text with the saved AI V1 model. The dashboard shows the risk score and reasons, and lets users review, quarantine or restore local records. The optional Gmail scan reads and analyses up to five messages without changing the mailbox.

## Components

- `backend/app.py` runs the Flask API and serves `phishguard-frontend.html`.
- `ml/model_api.py` serves V1 predictions from the existing model artifact.
- `database/` contains the SQLite schema and storage code. Manual analyses and feedback are stored there. Gmail scan results stay in the Gmail view.
- `PhishGuard/` and `archive/` retain earlier prototypes. They are not the final demo: the former can modify real mailboxes and call an external model; the current V1 workflow does neither. See the [component inventory](archive/README.md).
- `scripts/verify_project.py` copies source into a temporary directory and checks the current runtime without private configuration or mailbox access.

## Install

The current checkout was verified with Python **3.12.14**, Node.js **24.22.3**, and the saved artifact’s matching scikit-learn **1.9.1**. The earlier Windows rehearsal used Python 3.15.2; it is not a portable installation prerequisite. Use the checked dependency files and a supported Python environment. The following commands use Windows PowerShell. From the repository root, create a virtual environment only if one has not already been set up.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt -r ml/requirements.txt -r requirements-dev.txt
```

### Select the interpreter in each demo terminal

```powershell
$DemoPython = (Resolve-Path '.venv/Scripts/python.exe').Path
& $DemoPython --version
```

If the existing launcher cannot access its base Python, this Capstone workspace has a verified Python 3.15.2 fallback. It uses the packages already installed in the virtual environment. This fallback is local to this workspace.

```powershell
$DemoPython = (Resolve-Path '.venv/demo-runtime/python.exe').Path
$env:PYTHONPATH = (Resolve-Path '.venv/Lib/site-packages').Path
$env:PYTHONDONTWRITEBYTECODE = '1'
& $DemoPython --version
```

## Run locally

If demo credentials have not been saved, run this one-time command. It uses hidden prompts, keeps existing settings, and fills in the local model URL if missing.

```powershell
& $DemoPython -m backend.local_config setup-demo
```

In terminal 1, start V1.

```powershell
& $DemoPython ml/model_api.py
```

In terminal 2, select the interpreter again and start Flask. The commands below use the verified **synthetic demo database** from the final rehearsal. Setup registers V1 and keeps existing rows. On a fresh workspace, the same commands create the file in `.venv`.

```powershell
$env:PHISHGUARD_DB_PATH = Join-Path $PWD '.venv/phishguard-capstone-final-20261122.sqlite3'
& $DemoPython -m backend.setup_db
& $DemoPython backend/app.py
```

Flask loads the Git-ignored `.env.phishguard.json` from the workspace root. Explicit process settings override it. Keeping the demo database override separate preserves the existing workspace database, `database/analysis.db`.

Example nonsecret local settings:

```json
{
  "AI_MODEL_URL": "http://127.0.0.1:5001/predict",
  "GOOGLE_REDIRECT_URI": "http://127.0.0.1:5000/gmail/callback"
}
```

Use the setup commands to enter credentials locally. Keep the private file and Google exports out of Git.

- [Flask health](http://127.0.0.1:5000/api/health)
- [V1 health](http://127.0.0.1:5001/health)
- [Dashboard](http://127.0.0.1:5000/gmail/app)

## Gmail test inbox

Use the existing Google **Web application** client, enable Gmail API, and add the dedicated test account in Google Cloud **Testing**. Register `http://127.0.0.1:5000/gmail/callback` exactly. PhishGuard requests the Gmail read-only scope.

If Gmail has not been set up locally, import the existing Web client export once.

```powershell
& $DemoPython -m backend.local_config setup-gmail --google-export 'C:\path\google-web-client.json'
```

Omit the export option to use hidden local prompts. Restart Flask to load newly saved settings. Open [Gmail consent](http://127.0.0.1:5000/gmail/connect?view=dashboard) using the dedicated account. The HTTP rehearsal verified the redirect to Google. The project owner separately reported completion of the browser Gmail workflow. [Setup and troubleshooting](backend/CAPSTONE_2_DEMO.md#gmail-configuration-handoff)

## Tests

The recommended verification command creates disposable copies, excludes private configuration, credentials, local databases and CSV datasets, blocks Python network access except the loopback HTTP smoke test, and runs backend, ML, database, legacy-regression and JavaScript suites. It also checks both SQLite startup paths and the real Flask → V1 → SQLite workflow. It does not train models, evaluate a corpus, contact Google, or send email.

```powershell
& $DemoPython scripts/verify_project.py
```

Logs are saved under the ignored `verification-results/` directory. A failed step produces a nonzero final exit code. Install the development requirements and ensure Node.js is on PATH. For individual suites, run the shared checks from an isolated copy of the repository without the private local configuration. Point `PHISHGUARD_DB_PATH` at a disposable SQLite file and keep real credentials out of the test process. The tests mock Google.

```powershell
& $DemoPython -m pytest backend -q --tb=short -p no:cacheprovider
node --test backend/test_gmail_dashboard.cjs
```

Prefer the scoped runner above. The standalone SQLite smoke scripts are now import-safe, but intentionally write synthetic records when executed, so use a disposable database. See [safe SQLite verification](database/README.md#setup-and-testing). The older [E11 evidence](backend/evidence/E11-20261122-122951-share/README.md) recorded 74 Python cases plus 12 subtests from a broader local workspace: several named experimental suites are absent from this repository. Those historical totals are not the fresh checkout total.

Fresh checked results: **80 Python cases +39 subtests,18 JavaScript cases, two SQLite checks and real loopback HTTP passed**. See [E13 evidence and limits](backend/evidence/E13-20261122-checkout/README.md).

## Limits and documentation

- V1 uses text and its binary cutoff is **50**. It can flag legitimate messages and does not verify sender identity or attachments.
- The stored-message dashboard groups valid scores at **40 and 70**, and shows **No score** for unanalysed records. Its percentages use all stored messages, including unscored records, as the denominator. These are display bands, distinct from the model’s binary cutoff of 50. Model accuracy requires labelled evaluation data.
- Authentication and OAuth sessions are intended for a local demo. Restarting Flask requires signing in again.

[Demo script and backend contribution](backend/CAPSTONE_2_DEMO.md) · [API reference](backend/CAPSTONE_2_DEMO.md#api-reference) · [Database](database/README.md) · [V1 and ML notes](ml/README.md)
