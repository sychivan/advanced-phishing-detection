# Phishing detection model

V1 is the saved TF-IDF and Logistic Regression pipeline in `models/phishing_model.joblib`. The model service scores subject and body text; it is separate from the rules and Claude code in `PhishGuard/scanner.py`.

## Setup and compatibility

Use the repository's virtual environment and interpreter instructions in the [main README](../README.md). Install the direct runtime and training dependencies:

```powershell
& $DemoPython -m pip install -r ml/requirements.txt
```

The code audit verified CPython 3.12.14 with scikit-learn 1.9.1, joblib 1.6.0, NumPy 2.5.4, SciPy 1.18.1, pandas 3.1.1 and Flask 3.1.3. The saved estimator itself records scikit-learn 1.9.1. The requirements file keeps those direct dependencies and leaves their transitive dependencies to the resolver. pandas is used for training-data preparation.

Keep the saved model and compatible dependency versions together. Loading under scikit-learn 1.8.0 produced version warnings during the initial audit; installing the recorded 1.9.1 version removed them. Cross-version model loading is not supported by scikit-learn's [persistence guidance](https://scikit-learn.org/stable/model_persistence.html#security-maintainability-limitations).

## Run V1

```powershell
& $DemoPython ml/model_api.py
```

The service listens on `127.0.0.1:5001`. Check [health](http://127.0.0.1:5001/health). In a separate backend terminal, select the interpreter again and configure the local model endpoint:

```powershell
$env:AI_MODEL_URL = 'http://127.0.0.1:5001/predict'
& $DemoPython backend/app.py
```

The main README also supports storing this URL in the private local configuration. Explicit environment settings take precedence.

## API and interpretation

`POST /predict` accepts a JSON object:

```json
{
  "features": {
    "subject": "Project meeting",
    "body": "Our meeting is tomorrow."
  }
}
```

The response contains `classification`, `risk_score`, `model_status`, `reasons`, `model_version` and `artifact_hash`. V1 uses the phishing-class probability at a cutoff of 0.5 (50 on the displayed score scale), then rounds the returned score to two decimals. The dashboard's 40/70 score bands are a separate presentation rule.

Invalid shapes/types or an empty body return 400. Text with no recognised model vocabulary returns 422 for manual review without a classification or score. The request body limit is 200,000 bytes. Explanations identify text terms contributing to the selected class and state that sender authenticity and attachments were not verified.

The preserved artifact's SHA-256 is:

```text
633f1c0893b5f63c02097b6482485a7bcf221383759f31f65406ace70b8d5cae
```

## Regression tests

```powershell
& $DemoPython -m pytest ml/test_model_api.py -q -p no:cacheprovider
```

These tests use the saved artifact and synthetic strings through Flask's test client, with socket connections blocked during each test. They check the existing 85.92 Phishing and 40.24 Safe examples, metadata, explanations, invalid input, unknown vocabulary and the request limit. They do not train a model, load a corpus, calculate detection accuracy or establish a real network/browser result.

## Historical evaluation

`reports/evaluation.json` records:

| Split or count | Recorded value |
| --- | ---: |
| Original rows | 18,650 |
| Cleaned rows across all splits | 17,500 |
| Training rows | 12,250 |
| Validation rows | 2,625 |
| Test rows | 2,625 |
| Validation accuracy | 97.94% |
| Test accuracy | 98.48% |
| Test phishing recall | 97.45% |

The recorded test confusion matrix, with actual rows and predicted columns in Safe/Phishing order, is `[[1631, 15], [25, 954]]`. These counts are arithmetically consistent with the reported metrics. **17,500 is the cleaned total, not the number of training examples.**

The training script removes empty/unrecognised labels and short text, normalises case/whitespace for duplicate detection, removes conflicting labels and exact normalised duplicates, and uses stratified 70/15/15 splits with seed 42. The TF-IDF vocabulary and classifier are fitted only on the training partition. This avoids fitting those transforms on held-out data, consistent with scikit-learn's [data-leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).

The audit inspected this logic and the saved estimator; it did not rerun training or corpus evaluation because the labelled CSV was not present. Similar campaigns or near-duplicate messages could still span the random splits. The report lacks an artifact hash, dataset checksum and saved split identifiers, so the historical metrics are reported results, not independently reproduced performance of the current Gmail traffic.

The score has not been calibrated for current real-world mail. Sender authenticity, attachments and URL reputation are not checked. Explanation terms are model contributions, not proof of phishing.

## Future training

Dataset instructions are in [data/README.md](data/README.md). Training is a separate task:

```powershell
& $DemoPython ml/train_model.py
```

That command replaces the saved model and evaluation report. Preserve the demonstrated V1 artifact until a replacement has its own reviewed evaluation and metadata. Future evaluation should retain dataset/artifact checksums and split identifiers, and test campaign-separated or later data. Restart the service and register the replacement model before using its results in stored analyses.
