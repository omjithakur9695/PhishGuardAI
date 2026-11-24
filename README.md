# PhishGuard AI — Explainable Multi-Vector Cyber Threat Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=flat-square)
![Scikit--Learn](https://img.shields.io/badge/Scikit--Learn-1.9-orange?style=flat-square)
![ROC--AUC](https://img.shields.io/badge/ROC--AUC-0.9931-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Viva%20Ready-success?style=flat-square)

**PhishGuard AI** is a college major project implementing an enterprise-grade hybrid cyber threat intelligence platform. It fuses character n-gram machine learning, Shannon entropy lexical heuristics, social engineering NLP, and Explainable AI (XAI) to neutralize zero-hour phishing attacks across URLs, emails, and QR codes.

---

## 🌟 Key Features

1. **Hybrid URL Threat Inspection Engine**:
   - 25-parameter structural and lexical heuristic extraction.
   - Shannon Entropy calculation for automated Domain Generation Algorithm (DGA) detection.
   - Targeted brand impersonation & homograph/punycode spoofing detector.
   - Character-level (3–5 n-grams) TF-IDF machine learning model with sub-millisecond (< 0.001 ms) inference.
2. **Explainable AI (XAI) Attribution**:
   - Decomposes threat scores into transparent, human-auditable risk cards with assigned severity weights.
3. **Social Engineering & Phishing Email/SMS (Smishing) NLP Analyzer**:
   - Detects psychological manipulation (artificial urgency, fear tactics, financial/crypto bait, urgent CTAs).
   - Decomposes embedded hyperlinks and automatically executes recursive threat inspections.
4. **Quishing (QR Code Phishing) Defense Scanner**:
   - Decodes QR matrices directly in the browser and feeds extracted URLs into the deep inspection pipeline.
5. **Enterprise Batch Threat Auditor**:
   - Simultaneously audits up to 50 URLs from proxy logs or threat feeds, providing summary KPIs and CSV exports.
6. **Comparative AI Model Evaluation Lab**:
   - Side-by-side benchmark matrix comparing **SGDClassifier**, **Logistic Regression**, **Multinomial Naive Bayes**, **Decision Tree**, and **Random Forest**.
   - Interactive 2x2 Confusion Matrix visualizer (True Positives, False Positives, False Negatives, True Negatives).
7. **Persistent SQLite Forensic Audit Log**:
   - Cryptographically logs all scan activity with search, filtering, and 1-click CSV report export.
8. **RESTful API Documentation**:
   - Production-ready JSON endpoints (`/api/scan/url`, `/api/scan/email`, `/api/scan/batch`) for SIEM, firewall, and browser extension integrations.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10 or newer (tested with Python 3.10 – 3.14)
- Modern web browser (Chrome, Edge, Firefox, or Safari)

### 2. Installation & Setup

```bash
# Activate virtual environment
.\.venv\Scripts\activate

# Install dependencies (if not already installed)
pip install -r requirements.txt

# Run the automated 11-point test suite to verify everything
python test_platform.py

# Launch the SOC Dashboard
python app.py
```

Open your browser at: **`http://127.0.0.1:5000`**

---

## 📂 Project Directory Structure

```text
PhishGuardAI project/
├── app.py                      # Flask RESTful API & SOC dashboard server
├── threat_engine.py            # 25-point heuristic engine, Shannon entropy, XAI & NLP analyzer
├── database.py                 # SQLite audit log, metrics & CSV export
├── model_benchmarks.py         # Comparative ML benchmark evaluation script
├── model_benchmarks.json       # Precomputed multi-model evaluation metrics & confusion matrices
├── test_platform.py            # Automated 11-point test suite
├── train_model.py              # ML model trainer for character n-gram SGD pipeline
├── phish_guard_url_model.joblib# Serialized active machine learning model (~6.8 MB)
├── phish_guard_cleaned.csv     # Training dataset (>500,000 URLs)
├── PROJECT_REPORT.md           # 500+ line academic Major Project Report with IEEE references
├── RUN_GUIDE.md                # Viva presentation script & sample demo inputs
├── templates/
│   └── index.html              # Modern Cyber SOC 7-tab dashboard
└── static/
    ├── style.css               # Responsive dark cybersecurity UI styling
    └── app.js                  # Frontend controllers, charts & API integrations
```

---

## 📊 Experimental Results (5,000 Test Partition)

| Model Name | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SGDClassifier (Active)** | **95.24%** | **98.91%** | 82.76% | 0.9012 | **0.9931** | **0.001 ms** |
| **Logistic Regression** | 95.54% | 98.83% | 83.98% | 0.9080 | 0.9942 | 0.001 ms |
| **Multinomial Naive Bayes**| 93.92% | 95.57% | 80.55% | 0.8742 | 0.9832 | 0.006 ms |
| **Decision Tree** | 98.24% | 95.53% | 97.86% | 0.9668 | 0.9931 | 0.003 ms |
| **Random Forest (30 trees)**| 94.88% | 98.62% | 81.62% | 0.8932 | 0.9912 | 0.032 ms |

---

## 🎓 Academic Submission

For complete project synopsis, system architecture diagrams (DFDs, flowcharts), mathematical formulations (Shannon Entropy, Log-Loss SGD, sublinear TF-IDF), and the **Top 25 Viva Voce Questions & Model Answers**, refer to:
📄 **[PROJECT_REPORT.md](file:///c:/Users/OMJI/OneDrive/Desktop/phish/Work%20Done/PhishGuardAI%20project/PROJECT_REPORT.md)** and **[RUN_GUIDE.md](file:///c:/Users/OMJI/OneDrive/Desktop/phish/Work%20Done/PhishGuardAI%20project/RUN_GUIDE.md)**.
