from pathlib import Path
import json
import re

import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent


def main():
    data = pd.read_csv(BASE / "data" / "Phishing_Email.csv")
    original_count = len(data)

    # Keep rows with recognised labels and usable text.
    data = data.dropna(subset=["Email Text", "Email Type"]).copy()
    data["label"] = data["Email Type"].map({
        "Safe Email": 0,
        "Phishing Email": 1,
    })
    data = data.dropna(subset=["label"])
    data["label"] = data["label"].astype(int)
    data["text"] = data["Email Text"].astype(str).str.strip()
    data = data[data["text"].str.len() >= 20].copy()

    # Normalise case and whitespace to identify duplicate messages.
    data["duplicate_key"] = data["text"].map(
        lambda text: re.sub(r"\s+", " ", text).strip().lower()
    )

    # Remove messages with conflicting labels, then remove duplicates.
    label_counts = data.groupby("duplicate_key")["label"].nunique()
    conflicts = label_counts[label_counts > 1].index
    data = data[~data["duplicate_key"].isin(conflicts)]
    data = data.drop_duplicates(subset=["duplicate_key"])

    # 70% training, 15% validation, 15% test.
    train, remaining = train_test_split(
        data,
        test_size=0.30,
        random_state=42,
        stratify=data["label"],
    )
    validation, test = train_test_split(
        remaining,
        test_size=0.50,
        random_state=42,
        stratify=remaining["label"],
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=50000,
            sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            random_state=42,
        )),
    ])

    print("Training model...")
    # The vocabulary and classifier learn only from training data.
    model.fit(train["text"], train["label"])

    reports = {}
    for name, split in [("validation", validation), ("test", test)]:
        predictions = model.predict(split["text"])
        print(f"\n{name.upper()} RESULTS")
        print(classification_report(
            split["label"],
            predictions,
            labels=[0, 1],
            target_names=["Safe", "Phishing"],
            zero_division=0,
        ))
        reports[name] = {
            "metrics": classification_report(
                split["label"],
                predictions,
                labels=[0, 1],
                target_names=["Safe", "Phishing"],
                output_dict=True,
                zero_division=0,
            ),
            # Rows: actual; columns: predicted. Order: Safe, Phishing.
            "confusion_matrix": confusion_matrix(
                split["label"], predictions, labels=[0, 1]
            ).tolist(),
        }

    (BASE / "models").mkdir(exist_ok=True)
    (BASE / "reports").mkdir(exist_ok=True)

    joblib.dump(model, BASE / "models" / "phishing_model.joblib")

    reports["dataset"] = {
        "original_rows": original_count,
        "cleaned_rows": len(data),
        "training_rows": len(train),
        "validation_rows": len(validation),
        "test_rows": len(test),
        "random_seed": 42,
        "sklearn_version": sklearn.__version__,
    }
    (BASE / "reports" / "evaluation.json").write_text(
        json.dumps(reports, indent=2),
        encoding="utf-8",
    )

    print("\nDataset counts:", reports["dataset"])
    print("Saved model: ml/models/phishing_model.joblib")
    print("Saved evaluation: ml/reports/evaluation.json")


if __name__ == "__main__":
    main()