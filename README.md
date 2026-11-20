# PhishGuard – Advanced Phishing Detection System

**Capstone 3004 | Victoria University**

## 1. Project Overview

PhishGuard is a web-based phishing email detection and quarantine system developed as a university capstone project.

The system uses a machine learning model to analyse email content, identify potentially malicious messages, calculate phishing risk scores, and provide explanations for predictions.

PhishGuard also supports email quarantine, restoration, deletion, and user feedback to assist with reviewing potentially incorrect classifications.

## 2. Key Features

- **Email Analysis:** Analyse email sender information, subject lines, and message content.
- **Machine Learning Detection:** Classify emails and generate phishing risk scores.
- **Explainable Results:** Display reasons contributing to phishing predictions.
- **Dashboard:** View email statistics and detection summaries.
- **Email Quarantine:** Move potentially dangerous emails into quarantine.
- **Email Restoration:** Restore quarantined messages to the inbox.
- **Feedback System:** Record feedback when users identify possible false positives.
- **Permanent Deletion:** Delete emails and their related analysis records.
- **Demo Authentication:** Support local demonstration login.
- **Automated Testing:** Validate backend APIs and email workflows.

## 3. System Architecture

PhishGuard consists of four main components:

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | HTML, CSS, JavaScript | User interface and email management |
| Backend | Python, Flask | REST API and application logic |
| Machine Learning | Python, scikit-learn | Email classification and risk scoring |
| Database | SQLite | Store emails, analysis results, and feedback |

### Data Flow

1. An email is submitted for analysis.
2. The Flask backend extracts relevant email features.
3. The backend sends the features to the machine learning API.
4. The ML service returns a classification, risk score, and explanation.
5. The backend validates and stores the analysis result.
6. The frontend displays the result to the user.
7. Users can quarantine, restore, or delete messages.
8. Restoring a phishing-classified email can generate feedback for review.

## 4. Installation

### Prerequisites

- Windows 10 or Windows 11
- Python and pip
- Git
- Visual Studio Code (recommended)

The project has been tested locally using Python 3.15.2.

### Clone the Repository

```powershell
git clone https://github.com/sychivan/advanced-phishing-detection.git
cd advanced-phishing-detection
```

### Create a Virtual Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Install Dependencies

The repository contains dependency files for the machine learning and PhishGuard components:

```powershell
python -m pip install -r ml/requirements.txt
python -m pip install -r PhishGuard/requirements.txt
python -m pip install pytest
```

Dependency installation may require adjustments depending on the Python version and operating system.

## 5. Running the Application

Run the following services in separate terminals from the project root directory.

### Terminal 1 – Machine Learning API

```powershell
.\.venv\Scripts\python.exe ml/model_api.py
```

ML service:

`http://127.0.0.1:5001`

### Terminal 2 – Flask Backend

Configure the local demo environment:

```powershell
$env:AI_MODEL_URL="http://127.0.0.1:5001/predict"
$env:DEMO_EMAIL="demo@phishguard.local"
$env:DEMO_PASSWORD="1"
$env:ADMIN_EMAIL="demo@phishguard.local"

.\.venv\Scripts\python.exe backend/app.py
```

Backend service:

`http://127.0.0.1:5000`

The example credentials are intended only for local demonstration. They must not be used for production deployment.

### Terminal 3 – Frontend

```powershell
.\.venv\Scripts\python.exe -m http.server 5500
```

Open the application:

`http://127.0.0.1:5500/phishguard-frontend.html`

### Demo Login

Email: `demo@phishguard.local`

Password: `1`

### Gmail test inbox

1. In Google Cloud, enable the Gmail API. Set the OAuth audience to **External** with publishing status **Testing**, and add a Gmail test account under **Test users**.
2. Create a **Web application** OAuth client and add `http://127.0.0.1:5000/gmail/callback` under **Authorized redirect URIs**. Add the Gmail read-only scope (`https://www.googleapis.com/auth/gmail.readonly`) to the app's data access configuration.
3. Start the ML API as above. In the backend PowerShell terminal, set:

```powershell
$env:GOOGLE_CLIENT_ID = "your-client-id"
$env:GOOGLE_CLIENT_SECRET = "your-client-secret"
$env:GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000/gmail/callback"
$env:AI_MODEL_URL = "http://127.0.0.1:5001/predict"
$env:PHISHGUARD_SESSION_SECRET = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
.\.venv\Scripts\python.exe backend/app.py
```

Keep the credentials in the backend environment and out of Git. Open the frontend and select **Sign in with Google**, or open `http://127.0.0.1:5000/gmail/` directly. Sign in with the test account, grant read-only access and select **Scan up to 5 inbox messages**. PhishGuard sends message features to the configured model API. Use the local model when testing with personal mail.

Gmail results appear on the Gmail scan page. The scan runs on demand and stores the access token in the backend process for the session. Restarting Flask, signing out or reaching token expiration requires reconnecting. Sign-out clears the local session. Use your Google Account settings to remove the standing grant.

This is a local test flow. Public Gmail access requires Google verification for the restricted scope and a production deployment with HTTPS and managed sessions.

## 6. Main API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Check backend health |
| POST | `/api/analyse-email` | Analyse an email |
| GET | `/api/stats` | Retrieve dashboard statistics |
| GET | `/api/messages` | Retrieve messages |
| GET | `/api/messages/<id>` | Retrieve message details |
| POST | `/api/messages/<id>/quarantine` | Quarantine an email |
| POST | `/api/messages/<id>/restore` | Restore an email |
| DELETE | `/api/messages/<id>` | Delete an email |
| POST | `/api/auth/login` | Demo login |
| POST | `/api/auth/logout` | Demo logout |
| POST | `/api/feedback` | Submit classification feedback |
| GET | `/api/feedback/<id>` | Retrieve feedback |
| POST | `/api/feedback/<id>/review` | Review feedback |

## 7. Automated Testing

The backend includes automated tests for API behaviour, email processing, database storage, and message workflows.

Run all discovered tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -v --tb=short
```

### Latest Local Test Results

**9 tests passed (18 November 2026).**

Verified tests include:

- Email analysis
- Backend health check
- Invalid AI response handling
- Missing subject validation
- Valid AI response handling
- Email deletion
- Feedback database storage
- Email quarantine
- Email restoration with feedback creation

These tests verify selected backend behaviours. They do not constitute a complete security or production-readiness assessment.

## 8. Database

PhishGuard uses SQLite to store email records, model information, analysis results, and user feedback.

Relevant database files include:

- `database/schema.sql`
- `database/init_db.py`
- `database/storage.py`
- `database/test_storage.py`

Local database files are excluded from Git version control.

## 9. Known Limitations

PhishGuard is currently a university demonstration system.

- Email analysis primarily relies on email text features.
- Sender authenticity and attachments are not fully verified.
- Authentication uses a simplified local demo configuration.
- Administrative access is not a production-ready role-based permission system.
- The ML model requires a separate running service.
- Real-world email ingestion and production deployment require additional integration and security work.

## 10. Project Status

The core backend, ML API integration, database operations, and frontend workflows have been demonstrated locally.

Automated backend testing completed successfully with 9 passing tests.

Additional integration testing, security hardening, deployment configuration, and documentation may be required before production use.

## 11. Team Contributions

The project is developed collaboratively by a three-member capstone team.

- **Frontend Development:** User interface, navigation, and frontend integration.
- **Backend Development and AI Integration:** REST APIs, model communication, email workflows, and feedback integration.
- **Machine Learning and Database Development:** Model training, prediction service, and database-related development.

## 12. Academic Purpose

PhishGuard was developed for educational and demonstration purposes as part of the Capstone 3004 project at Victoria University.