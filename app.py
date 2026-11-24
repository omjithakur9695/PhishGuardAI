"""
PhishGuard AI - Enterprise-Grade Threat Intelligence & Phishing Defense Platform
Flask Application Backend
"""

from pathlib import Path
from urllib.parse import urlparse
import re
import io
import csv
import json
import joblib
from flask import Flask, render_template, request, jsonify, Response

import threat_engine
import database

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phish_guard_url_model.joblib"
BENCHMARK_PATH = BASE_DIR / "model_benchmarks.json"

app = Flask(__name__)
model = None

def load_model():
    """Load the trained ML model at startup."""
    global model
    if MODEL_PATH.exists():
        try:
            model = joblib.load(MODEL_PATH)
            app.logger.info("URL Threat ML model loaded successfully.")
        except Exception as e:
            app.logger.error(f"Failed to load model: {e}")
            model = None
    else:
        model = None

# Initialize audit SQLite database
database.init_db()

def normalize_url(raw_url: str) -> str:
    """Sanitizes, validates, and normalizes input URL strings."""
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Please provide a URL to analyze.")
    if len(value) > 2048:
        raise ValueError("URL exceeds safe limit (max 2048 characters).")
    if any(ch.isspace() for ch in value):
        raise ValueError("URL contains illegal space characters.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP/HTTPS URLs are supported.")
    if not parsed.hostname or "." not in parsed.hostname:
        # Check if it's an IP address
        if not threat_engine.is_ip_address(parsed.hostname or ""):
            raise ValueError("Invalid target. Provide a registered domain or IP address.")
    return value

@app.get("/")
def home():
    analytics = database.get_analytics_summary()
    return render_template(
        "index.html",
        model_ready=bool(model),
        analytics=analytics
    )

@app.get("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "database": "connected",
        "engine_version": "2.4.0-Enterprise"
    })

@app.post("/api/scan/url")
def scan_url():
    """
    Main URL Inspection endpoint.
    Performs 25-point heuristic feature extraction, ML classification,
    Explainable AI (XAI) risk attribution, and logs result to SQLite audit trail.
    """
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "")
    try:
        url = normalize_url(raw_url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # 1. Heuristic & Structural Analysis
    heuristics = threat_engine.analyze_url_heuristics(url)

    # 2. Machine Learning Inference
    ml_prob = 0.5  # Neutral default if model unavailable
    if model is not None:
        try:
            clean_url = threat_engine.prepare_url_for_ml(url)
            ml_prob = float(model.predict_proba([clean_url])[0][1])
        except Exception as e:
            app.logger.warning(f"ML prediction error: {e}")
            ml_prob = 0.5

    # 3. Composite Threat Scoring & Explainable AI
    threat_info = threat_engine.compute_composite_threat(ml_prob, heuristics)

    # 4. Audit Log to SQLite
    scan_id = database.log_scan(
        scan_type="URL",
        target=url,
        verdict=threat_info["verdict"],
        threat_score=threat_info["threat_score"],
        ml_prob=threat_info["ml_probability"],
        heuristic_score=threat_info["heuristic_score"],
        details={
            "risk_factors": heuristics["risk_factors"],
            "hostname": heuristics["hostname"],
            "domain_entropy": heuristics["domain_entropy"]
        },
        risk_factors_count=len(heuristics["risk_factors"])
    )

    return jsonify({
        "scan_id": scan_id,
        "url": url,
        "threat_score": threat_info["threat_score"],
        "verdict": threat_info["verdict"],
        "verdict_label": threat_info["verdict_label"],
        "severity": threat_info["severity"],
        "color": threat_info["color"],
        "summary": threat_info["summary"],
        "ml_probability": threat_info["ml_probability"],
        "heuristic_score": threat_info["heuristic_score"],
        "risk_factors": heuristics["risk_factors"],
        "features": {
            "hostname": heuristics["hostname"],
            "domain": heuristics["domain"],
            "tld": heuristics["tld"],
            "subdomains": heuristics["subdomains"],
            "subdomain_count": heuristics["subdomain_count"],
            "is_ip": heuristics["is_ip"],
            "is_https": heuristics["is_https"],
            "has_at": heuristics["has_at"],
            "has_dash": heuristics["has_dash"],
            "double_slash_path": heuristics["double_slash_path"],
            "is_shortener": heuristics["is_shortener"],
            "suspicious_tld": heuristics["suspicious_tld"],
            "punycode": heuristics["punycode"],
            "url_length": heuristics["url_length"],
            "domain_entropy": heuristics["domain_entropy"],
            "path_entropy": heuristics["path_entropy"],
            "path_depth": heuristics["path_depth"],
            "matched_keywords": heuristics["matched_keywords"],
            "impersonated_brands": heuristics["impersonated_brands"]
        }
    })

@app.post("/api/scan/email")
def scan_email():
    """
    Analyzes Phishing Email & Smishing SMS text.
    Extracts social engineering triggers, urgency bait, and embedded links.
    Optionally scans any links found inside the message.
    """
    payload = request.get_json(silent=True) or {}
    text = payload.get("content", "")
    if not text.strip():
        return jsonify({"error": "Please provide email or message body text."}), 400

    analysis = threat_engine.analyze_email_phishing(text)
    if "error" in analysis:
        return jsonify(analysis), 400

    # Scan embedded URLs found inside the email
    embedded_scans = []
    for link in analysis["extracted_urls"][:5]:
        try:
            norm_link = normalize_url(link)
            h = threat_engine.analyze_url_heuristics(norm_link)
            m_prob = 0.5
            if model is not None:
                try:
                    clean_link = threat_engine.prepare_url_for_ml(norm_link)
                    m_prob = float(model.predict_proba([clean_link])[0][1])
                except Exception:
                    pass
            comp = threat_engine.compute_composite_threat(m_prob, h)
            embedded_scans.append({
                "url": norm_link,
                "threat_score": comp["threat_score"],
                "verdict": comp["verdict"]
            })
        except Exception:
            pass

    analysis["embedded_scans"] = embedded_scans

    # If any embedded link is high risk/malicious, elevate email score
    if any(s["threat_score"] >= 70 for s in embedded_scans):
        analysis["phishing_score"] = min(100, max(analysis["phishing_score"], 85))
        analysis["verdict"] = "PHISHING_ATTACK"
        analysis["label"] = "High Probability Phishing / Smishing (Malicious Link Detected)"
        analysis["color"] = "#f43f5e"

    # Log to DB
    scan_id = database.log_scan(
        scan_type="EMAIL",
        target=text[:120] + "...",
        verdict=analysis["verdict"],
        threat_score=float(analysis["phishing_score"]),
        details={
            "factors": analysis["factors"],
            "urls_count": len(analysis["extracted_urls"]),
            "word_count": analysis["word_count"]
        },
        risk_factors_count=len(analysis["factors"])
    )

    analysis["scan_id"] = scan_id
    return jsonify(analysis)

@app.post("/api/scan/batch")
def scan_batch():
    """
    Batch Threat Intelligence Scanner.
    Accepts up to 50 URLs, runs scans, and returns summary distribution.
    """
    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls", [])
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Expected an array of URLs in 'urls' field."}), 400

    urls = urls[:50]  # Cap at 50 for safety
    results = []
    safe_cnt = 0
    suspicious_cnt = 0
    malicious_cnt = 0
    total_score = 0.0

    for raw in urls:
        try:
            u = normalize_url(raw)
            h = threat_engine.analyze_url_heuristics(u)
            m_prob = 0.5
            if model is not None:
                try:
                    clean_u = threat_engine.prepare_url_for_ml(u)
                    m_prob = float(model.predict_proba([clean_u])[0][1])
                except Exception:
                    pass
            comp = threat_engine.compute_composite_threat(m_prob, h)
            score = comp["threat_score"]
            total_score += score

            if score < 25.0:
                safe_cnt += 1
            elif score < 60.0:
                suspicious_cnt += 1
            else:
                malicious_cnt += 1

            results.append({
                "url": u,
                "threat_score": score,
                "verdict": comp["verdict"],
                "color": comp["color"],
                "risk_factors_count": len(h["risk_factors"])
            })
        except Exception as exc:
            results.append({
                "url": raw,
                "error": str(exc),
                "threat_score": 0,
                "verdict": "INVALID"
            })

    total = len(results)
    avg_score = round(total_score / total, 1) if total else 0.0

    return jsonify({
        "total_scanned": total,
        "safe_count": safe_cnt,
        "suspicious_count": suspicious_cnt,
        "malicious_count": malicious_cnt,
        "average_threat_score": avg_score,
        "items": results
    })

@app.get("/api/benchmarks")
def get_benchmarks():
    """Returns comparative model benchmark evaluation table & metrics."""
    if BENCHMARK_PATH.exists():
        try:
            with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({
        "error": "Benchmarks not yet computed. Run python model_benchmarks.py"
    }), 404

@app.get("/api/history")
def get_history():
    """Fetches recent scan records and aggregate analytics."""
    recent = database.get_recent_scans(limit=40)
    analytics = database.get_analytics_summary()
    return jsonify({
        "history": recent,
        "analytics": analytics
    })

@app.post("/api/history/clear")
def clear_history():
    """Clears scan audit records."""
    database.clear_scan_history()
    return jsonify({"success": True, "message": "Audit history cleared."})

@app.get("/api/export/csv")
def export_csv():
    """Exports all scan logs as a downloadable CSV."""
    records = database.get_recent_scans(limit=500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Timestamp", "Scan Type", "Target", "Verdict",
        "Threat Score (0-100)", "ML Probability (%)", "Heuristic Score", "Risk Factors Count"
    ])
    for r in records:
        writer.writerow([
            r["id"], r["timestamp"], r["scan_type"], r["target"],
            r["verdict"], r["threat_score"], r["ml_prob"],
            r["heuristic_score"], r["risk_factors_count"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=phishguard_threat_audit.csv"}
    )

# Legacy compatibility endpoint for old API requests
@app.post("/api/predict")
def legacy_predict():
    payload = request.get_json(silent=True) or {}
    try:
        url = normalize_url(payload.get("url", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    heuristics = threat_engine.analyze_url_heuristics(url)
    ml_prob = 0.5
    if model is not None:
        try:
            clean_url = threat_engine.prepare_url_for_ml(url)
            ml_prob = float(model.predict_proba([clean_url])[0][1])
        except Exception:
            pass

    comp = threat_engine.compute_composite_threat(ml_prob, heuristics)
    label = "Malicious" if comp["threat_score"] >= 50.0 else "Benign"
    return jsonify({
        "url": url,
        "prediction": label,
        "malicious_probability": comp["threat_score"],
        "confidence": comp["threat_score"] if label == "Malicious" else 100 - comp["threat_score"],
        "note": comp["summary"]
    })

if __name__ == "__main__":
    load_model()
    app.run(host="0.0.0.0", port=5000, debug=False)
