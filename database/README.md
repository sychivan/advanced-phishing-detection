# Database design and verification

The Flask backend uses this SQLite layer for saved manual analyses, local inbox and quarantine actions, and feedback. Gmail scan results stay in the Gmail view and are not inserted into these tables. The separate prototype database under `PhishGuard/` is not part of this storage path.

## Tables and timestamps

| Table | Stored data |
| --- | --- |
| `emails` | Sender, subject, body, insertion time and local status (`inbox` or `quarantine`). |
| `model_versions` | Unique version, artifact SHA-256, optional training time and supplied evaluation JSON. |
| `analysis_results` | Email and model references, classification, score, reasons and analysis time. |
| `feedback` | Suggested correction, submitter, pending/approved/rejected state and review identity/time. |

One email may have several analyses; one model may produce many analyses; an analysis may receive several feedback records. Foreign keys are enabled on every storage connection. Classification accepts Safe, Suspicious or Phishing for compatibility; the current V1 model returns only Safe or Phishing.

`created_at` records when the application inserted the local email, not when the original email was received. The API exposes this value as `receivedAt`. SQLite's `CURRENT_TIMESTAMP` values use UTC. `analysed_at` records analysis insertion time; ties use the analysis ID. The existing registration function does not populate `trained_at`, so a training date must not be inferred from it.

## Stored-message behavior

`save_analysis()` saves the email and successful analysis in one transaction. Invalid model references roll back the email insert. `save_model_response()` also requires the response's model version and artifact hash to match a registered model.

`list_messages()`, `get_message_by_id()` and restoration select the same latest analysis, ordered by `analysed_at` and then ID. A message without an analysis has a null score and classification; it must not be displayed as zero-risk or Safe. List and detail responses retain the model's reasons.

Quarantine and restore change local status without changing the prediction or score. Restoring a Phishing result can add pending Safe feedback when the backend supplies the authenticated submitter; repeated restoration reuses an existing pending correction. Restoring a Safe result does not create that correction. A direct storage call without an identity restores the record without inventing a submitter. Deletion removes related feedback and analysis rows together with the email.

The backend authenticates users and enforces reviewer permissions. Feedback is a human suggestion, separate from the model prediction. Approval does not automatically retrain the model.

## Setup

From the repository root, select `$DemoPython` using the [main README](../README.md#select-the-interpreter-in-each-demo-terminal). Set `PHISHGUARD_DB_PATH` before starting the backend or importing the storage module.

```powershell
$env:PHISHGUARD_DB_PATH = Join-Path $PWD '.venv/phishguard-demo.sqlite3'
& $DemoPython -m backend.setup_db
```

Setup creates the schema and registers the existing V1 artifact; it preserves existing rows and does not seed demonstration messages. The default path is `database/analysis.db`. Database files are excluded from Git. Re-running schema setup is idempotent, but it is not a migration of an incompatible older schema.

## Disposable verification

The regression suite creates its own temporary databases and does not load private local configuration:

```powershell
& $DemoPython -m pytest database/test_storage_regressions.py -q -p no:cacheprovider
```

For explicit saved-model smoke checks, use a fresh disposable path:

```powershell
$env:PHISHGUARD_DB_PATH = Join-Path $env:TEMP ("phishguard-sqlite-test-{0}.sqlite3" -f [guid]::NewGuid())
& $DemoPython -m database.test_storage
& $DemoPython -m database.check_storage
Remove-Item Env:PHISHGUARD_DB_PATH
```

The first script saves and retrieves a synthetic prediction through SQLite. The second uses the storage helpers and verifies foreign-key rollback. Both initialize the chosen path and use the saved V1 model. If the environment override is absent, each smoke script uses its own temporary directory and removes it afterward. Pointing the override at an existing database intentionally inserts synthetic records there, so keep it separate from the live demo path.

`database.init_db`, `database.test_storage` and `database.check_storage` are import-safe: importing them neither opens a database nor loads the model. Running `python -m database.init_db` explicitly initializes the configured path.

## Model metadata and evidence limits

`register_model(model_path, report_path)` hashes the saved artifact and reuses its existing registration ID. The stored evaluation JSON is supplied metadata; the historical report does not include an artifact hash or dataset checksum that independently binds its metrics to the model file. Registration checks identity consistency but does not rerun training or evaluate accuracy.

Current regression checks cover list/detail consistency, null scores, restore attribution, feedback behavior, rollback, registration, schema reuse, deletion and import safety. They use synthetic data and do not measure real-mail detection quality.
