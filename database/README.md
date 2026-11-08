# Database Design

Status: SQLite prototype implemented. Analysis storage, retrieval,
transaction rollback, and feedback submission and approval tested.
Backend integration is pending.

## Tables

### emails
- id: primary key
- sender: sender email address
- subject: email subject
- body: email text
- created_at: time the application stored the email

### model_versions
- id: primary key
- version: unique model version
- artifact_hash: hash identifying the saved model file
- trained_at: model training time
- metrics_json: model evaluation results

### analysis_results
- id: primary key
- email_id: foreign key referencing emails
- model_version_id: foreign key referencing model_versions
- classification: Safe, Suspicious, or Phishing
- risk_score: model score between 0 and 100
- reasons_json: explanation list
- analysed_at: analysis time

### feedback
- id: primary key
- analysis_id: foreign key referencing analysis_results
- submitted_by: reference to an authenticated user
- suggested_label: Safe or Phishing
- review_status: pending, approved, or rejected
- reviewed_by: reference to the reviewer
- created_at: submission time
- reviewed_at: review time, initially empty

## Relationships
- One email can have multiple analysis results.
- One model version can produce multiple analysis results.
- One analysis result can receive multiple feedback entries.

## Implementation Notes
- User references must match the backend's account system.
- Predictions remain separate from user feedback.
- Only approved feedback is eligible for future training.
- Failed analysis must not be stored as a successful Safe prediction.
- Quarantine storage and audit records will be designed with the
  backend developer alongside the existing PhishGuard implementation.

## Setup and Testing

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe database/init_db.py
.\.venv\Scripts\python.exe database/test_storage.py
.\.venv\Scripts\python.exe -m database.check_storage
```

The demonstration scripts add sample email and analysis records.
The local database is database/analysis.db and is excluded from Git.

## Storage Functions

storage.py provides:
- save_analysis(): saves an email and successful model prediction together.
- get_analysis(): retrieves an analysis with its email and model details.

Foreign keys are enabled on each connection.
Failed inserts roll back the transaction.

This database is currently separate from PhishGuard/phishguard.db.
Feedback functions:
- submit_feedback(): records a suggested label as pending.
- review_feedback(): approves or rejects pending feedback.
- get_feedback(): retrieves a feedback record.

The backend must supply authenticated identities and enforce reviewer
permissions. Approved feedback does not automatically retrain the model.