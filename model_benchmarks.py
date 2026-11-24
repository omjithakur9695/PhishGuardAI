"""
PhishGuard AI - Model Benchmark & Comparative Performance Suite
Evaluates multiple machine learning classifiers on URL classification
to generate academic evaluation tables and confusion matrices.
"""

import json
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import time

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "phish_guard_cleaned.csv"
BENCHMARK_PATH = BASE_DIR / "model_benchmarks.json"

def run_benchmarks(sample_size=20000):
    if BENCHMARK_PATH.exists():
        print("Benchmarks already exist.")
        return

    if not DATA_PATH.exists():
        print("Dataset not found, skipping benchmark calculation.")
        return

    print(f"Reading dataset sample of {sample_size} for comparative benchmarking...")
    # Read chunk
    df = pd.read_csv(DATA_PATH, nrows=sample_size * 2)
    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df = df[df["label"].isin([0, 1])]
    df["label"] = df["label"].astype(int)
    df = df.sample(n=min(sample_size, len(df)), random_state=42)

    X = df["url"]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    print("Vectorizing character n-grams...")
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 4), max_features=25000, sublinear_tf=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    models = {
        "SGDClassifier (Active Model)": SGDClassifier(loss="log_loss", max_iter=20, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=100, random_state=42),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
        "Decision Tree": DecisionTreeClassifier(max_depth=15, random_state=42),
        "Random Forest (Ensemble)": RandomForestClassifier(n_estimators=30, max_depth=15, random_state=42, n_jobs=-1)
    }

    results = []
    confusion_matrices = {}

    for name, clf in models.items():
        print(f"Evaluating {name}...")
        t0 = time.time()
        clf.fit(X_train_vec, y_train)
        train_time = round(time.time() - t0, 3)

        t1 = time.time()
        y_pred = clf.predict(X_test_vec)
        inf_time = round((time.time() - t1) / len(X_test) * 1000, 3) # ms per sample

        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test_vec)[:, 1]
            auc = round(float(roc_auc_score(y_test, y_prob)), 4)
        else:
            auc = 0.0

        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        cm = confusion_matrix(y_test, y_pred).tolist()

        results.append({
            "model_name": name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "train_time_sec": train_time,
            "latency_ms": inf_time,
            "is_active": "SGDClassifier" in name
        })
        confusion_matrices[name] = {
            "tn": cm[0][0],
            "fp": cm[0][1],
            "fn": cm[1][0],
            "tp": cm[1][1]
        }

    output = {
        "dataset_sample_size": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics_table": results,
        "confusion_matrices": confusion_matrices,
        "features_extracted": 25000,
        "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(BENCHMARK_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Benchmark results successfully saved to {BENCHMARK_PATH}")

if __name__ == "__main__":
    run_benchmarks()
