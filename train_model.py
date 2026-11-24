"""
Phish Guard AI - train and evaluate the URL classifier.

Expected input: phish_guard_cleaned.csv with columns: url, label
label: 0 = benign, 1 = malicious

Install:
    pip install -r requirements.txt

Run:
    python train_model.py
"""
from pathlib import Path
import sys
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "phish_guard_cleaned.csv"
MODEL_PATH = BASE_DIR / "phish_guard_url_model.joblib"

def main():
    if not DATA_PATH.exists():
        sys.exit(
            "Dataset not found. Put phish_guard_cleaned.csv in the same folder as train_model.py."
        )

    df = pd.read_csv(DATA_PATH)
    required = {"url", "label"}
    if not required.issubset(df.columns):
        sys.exit(f"Dataset must contain columns: {', '.join(sorted(required))}")

    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df = df[df["label"].isin([0, 1])]
    df = df.drop_duplicates(subset=["url"], keep="first")

    if df["label"].nunique() != 2:
        sys.exit("Training data must contain both labels: 0 and 1.")

    X = df["url"]
    y = df["label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Character n-grams capture URL patterns without requiring a hand-built feature list.
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=200_000,
            sublinear_tf=True,
            dtype="float32"
        )),
        ("classifier", SGDClassifier(
            loss="log_loss",
            max_iter=10,
            tol=1e-3,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        ))
    ])

    print(f"Clean rows:   {len(df):,}")
    print(f"Train rows:   {len(X_train):,}")
    print(f"Test rows:    {len(X_test):,}")
    print("Training model; first run can take a few minutes...")
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]
    print(f"\nAccuracy: {accuracy_score(y_test, pred):.4f}")
    print(f"ROC-AUC:  {roc_auc_score(y_test, probabilities):.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test, pred, labels=[0, 1], target_names=["Benign", "Malicious"], digits=4
    ))
    print("Confusion matrix (rows=true, columns=predicted; [Benign, Malicious]):")
    print(confusion_matrix(y_test, pred, labels=[0, 1]))

    joblib.dump(model, MODEL_PATH)
    print(f"\nSaved model: {MODEL_PATH}")
    print("Next: python app.py")

if __name__ == "__main__":
    main()
