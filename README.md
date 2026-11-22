# PhishGuard

PhishGuard analyses submitted email text with the saved AI V1 model. The dashboard shows the risk score and reasons, and lets users review, quarantine or restore local records. The optional Gmail scan reads and analyses up to five messages without changing the mailbox.

## Components

- `backend/app.py` runs the Flask API and serves `phishguard-frontend.html`.
- `ml/model_api.py` serves V1 predictions from the existing model artifact.
- `database/` contains the SQLite schema and storage code. Manual analyses and feedback are stored there. Gmail scan results stay in the Gmail view.
- `PhishGuard/` is a separate prototype with its own setup.

## Install

Use Windows PowerShell, Python 3.15.2, and Node.js for the dashboard tests. From the repository root, create a virtual environment only if one has not already been set up.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt -r ml/requirements.txt pytest
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

Run the shared suites from an isolated copy of the repository without the private local configuration. Point `PHISHGUARD_DB_PATH` at a disposable SQLite file and keep real credentials out of the test process. The tests mock Google.

```powershell
& $DemoPython -m pytest backend -q --tb=short -p no:cacheprovider
node --test backend/test_gmail_dashboard.cjs
```

Avoid repository-wide test discovery. The legacy SQLite smoke scripts write records, and the ML audit scripts can run dataset evaluations. See [safe SQLite verification](database/README.md#setup-and-testing) and [E11 evidence](backend/evidence/E11-20261122-122951-share/README.md) for the broader isolated run, which also included local ML regression suites.

## Limits and documentation

- V1 uses text and its binary cutoff is **50**. It can flag legitimate messages and does not verify sender identity or attachments.
- The stored-message dashboard groups scores at **40 and 70**. Its percentages are shares of stored messages in those bands. Model accuracy requires labelled evaluation data.
- Authentication and OAuth sessions are intended for a local demo. Restarting Flask requires signing in again.

[Demo script and backend contribution](backend/CAPSTONE_2_DEMO.md) · [API reference](backend/CAPSTONE_2_DEMO.md#api-reference) · [Database](database/README.md) · [V1 and ML notes](ml/README.md)
