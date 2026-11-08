# Phishing Detection Model

## Setup

Run these commands from the repository root using Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r ml/requirements.txt
```

## Start the model service

```powershell
.\.venv\Scripts\python.exe ml/model_api.py
```

The service runs at http://127.0.0.1:5001.
Check its status at http://127.0.0.1:5001/health.

## Connect the backend

Keep the model service running. Open another terminal:

```powershell
$env:AI_MODEL_URL = "http://127.0.0.1:5001/predict"
.\.venv\Scripts\python.exe backend/app.py
```

The environment variable must be set again in each new backend
terminal session.

## API format

POST /predict accepts:

```json
{
  "features": {
    "subject": "Project meeting",
    "body": "Our meeting is tomorrow."
  }
}
```

Returns classification, risk_score, model_status, and reasons.
The current classifier uses a score threshold of 50.

## Training

Download the dataset using the instructions in data/README.md, then run:

```powershell
.\.venv\Scripts\python.exe ml/train_model.py
```

This replaces the saved model and evaluation report.
Restart the model service after retraining.

## Evaluation and limitations

The baseline uses TF-IDF and Logistic Regression.
Rounded test results: 98% accuracy and 97% phishing recall.
Detailed results are in reports/evaluation.json.

These results apply to the selected dataset split.
Similar campaign messages may remain across splits.
The score has not been calibrated as a real-world probability.

Only subject and body text are analysed by this model.
Sender authenticity, attachments, and URL reputation are not verified.
Explanation terms describe model contributions, not proof of phishing.

This service connects to backend/app.py. The separate
PhishGuard/scanner.py still uses its existing rules and Claude logic.