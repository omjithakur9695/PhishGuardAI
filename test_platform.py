"""
Automated End-to-End Test Suite for PhishGuard AI Platform
Uses Flask TestClient to thoroughly verify all threat detection vectors,
benchmarks, database logging, and REST endpoints.
"""

import sys
import json
from app import app, load_model

def run_tests():
    print("Initializing PhishGuard AI test suite...")
    load_model()
    client = app.test_client()

    print("\n1. Testing GET / (SOC Dashboard HTML)...")
    res = client.get("/")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert b"PHISHGUARD" in res.data
    print("   [PASS] Dashboard loaded successfully.")

    print("\n2. Testing GET /api/health...")
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    print(f"   [PASS] Health check ok, Model loaded: {data['model_loaded']}.")

    print("\n3. Testing POST /api/scan/url (Benign URL)...")
    res = client.post("/api/scan/url", json={"url": "https://www.google.com/search?q=cybersecurity"})
    assert res.status_code == 200
    data = res.get_json()
    print(f"   Verdict: {data['verdict']}, Score: {data['threat_score']}, Factors: {len(data['risk_factors'])}")
    assert data["threat_score"] < 40, f"Expected low threat score, got {data['threat_score']}"
    print("   [PASS] Benign URL verified safe.")

    print("\n4. Testing POST /api/scan/url (Phishing Brand Spoofing)...")
    res = client.post("/api/scan/url", json={"url": "http://paypal-verification-center.xyz/login.php"})
    assert res.status_code == 200
    data = res.get_json()
    print(f"   Verdict: {data['verdict']}, Score: {data['threat_score']}, Factors: {len(data['risk_factors'])}")
    assert data["threat_score"] >= 70, f"Expected high threat score, got {data['threat_score']}"
    assert any(f["code"] == "BRAND_SPOOF" for f in data["risk_factors"])
    print("   [PASS] Brand spoofing correctly detected with XAI explanation.")

    print("\n5. Testing POST /api/scan/url (Raw IP Host)...")
    res = client.post("/api/scan/url", json={"url": "http://192.168.1.55/update/login.html"})
    assert res.status_code == 200
    data = res.get_json()
    print(f"   Verdict: {data['verdict']}, Score: {data['threat_score']}")
    assert data["features"]["is_ip"] is True
    print("   [PASS] Raw IP address host anomaly flagged.")

    print("\n6. Testing POST /api/scan/email (Social Engineering / Smishing)...")
    email_sample = (
        "URGENT: Your account has been suspended due to unauthorized access. "
        "Immediate action required within 24 hours. Click here to confirm identity: "
        "http://secure-account-verify.pw/login"
    )
    res = client.post("/api/scan/email", json={"content": email_sample})
    assert res.status_code == 200
    data = res.get_json()
    print(f"   Verdict: {data['verdict']}, Phishing Score: {data['phishing_score']}")
    assert data["phishing_score"] >= 60
    assert len(data["factors"]) >= 2
    assert len(data["extracted_urls"]) == 1
    print("   [PASS] Social engineering NLP successfully identified urgency & malicious links.")

    print("\n7. Testing POST /api/scan/batch (Enterprise Batch Audit)...")
    urls = [
        "https://google.com",
        "http://paypal-fraud.xyz/login",
        "https://wikipedia.org",
        "http://10.0.0.1/auth"
    ]
    res = client.post("/api/scan/batch", json={"urls": urls})
    assert res.status_code == 200
    data = res.get_json()
    print(f"   Scanned: {data['total_scanned']}, Safe: {data['safe_count']}, Malicious: {data['malicious_count']}")
    assert data["total_scanned"] == 4
    print("   [PASS] Batch scan processed all targets.")

    print("\n8. Testing GET /api/benchmarks (AI Evaluation Lab)...")
    res = client.get("/api/benchmarks")
    assert res.status_code == 200
    data = res.get_json()
    assert "metrics_table" in data
    assert len(data["metrics_table"]) == 5
    print(f"   [PASS] Benchmark metrics loaded ({len(data['metrics_table'])} algorithms compared).")

    print("\n9. Testing GET /api/history & Database Audit Trail...")
    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["history"]) > 0
    print(f"   [PASS] SQLite audit logged {len(data['history'])} operations.")

    print("\n10. Testing GET /api/export/csv (Audit Export)...")
    res = client.get("/api/export/csv")
    assert res.status_code == 200
    assert b"Scan ID,Timestamp" in res.data
    print("   [PASS] CSV threat audit report generated.")

    print("\n11. Testing Legacy Compatibility POST /api/predict...")
    res = client.post("/api/predict", json={"url": "https://www.google.com"})
    assert res.status_code == 200
    data = res.get_json()
    assert "prediction" in data
    print(f"   [PASS] Legacy API compatibility preserved: {data['prediction']}.")

    print("\n==========================================")
    print(" ALL 11 TEST VECTORS PASSED FLAWLESSLY!   ")
    print(" System is 100% Viva & Presentation Ready ")
    print("==========================================")

if __name__ == "__main__":
    run_tests()
