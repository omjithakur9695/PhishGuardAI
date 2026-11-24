"""
PhishGuard AI - Persistent Threat Log & Security Audit Database
Implements SQLite storage for scan history, forensic logging, and analytics metrics.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = Path(__file__).resolve().parent / "phishguard_audit.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                verdict TEXT NOT NULL,
                threat_score REAL NOT NULL,
                ml_prob REAL,
                heuristic_score REAL,
                details_json TEXT,
                risk_factors_count INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON scan_logs(verdict)")
        conn.commit()

def log_scan(
    scan_type: str,
    target: str,
    verdict: str,
    threat_score: float,
    ml_prob: Optional[float] = None,
    heuristic_score: Optional[float] = None,
    details: Optional[Dict[str, Any]] = None,
    risk_factors_count: int = 0
) -> int:
    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_logs (
                timestamp, scan_type, target, verdict, threat_score,
                ml_prob, heuristic_score, details_json, risk_factors_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now_iso,
            scan_type,
            target[:1024],
            verdict,
            threat_score,
            ml_prob,
            heuristic_score,
            json.dumps(details or {}),
            risk_factors_count
        ))
        conn.commit()
        return cursor.lastrowid

def get_recent_scans(limit: int = 30) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, scan_type, target, verdict, threat_score,
                   ml_prob, heuristic_score, risk_factors_count
            FROM scan_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

def get_analytics_summary() -> Dict[str, Any]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_logs")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE verdict IN ('MALICIOUS', 'HIGH_RISK', 'PHISHING_ATTACK')")
        malicious_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE verdict IN ('SAFE', 'LIKELY_LEGITIMATE')")
        safe_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE verdict IN ('SUSPICIOUS', 'SUSPICIOUS_MESSAGE')")
        suspicious_scans = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(threat_score) FROM scan_logs")
        avg_score_row = cursor.fetchone()[0]
        avg_score = round(float(avg_score_row), 1) if avg_score_row is not None else 0.0

        # Scan types breakdown
        cursor.execute("SELECT scan_type, COUNT(*) FROM scan_logs GROUP BY scan_type")
        types_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

        return {
            "total_scans": total_scans,
            "malicious_scans": malicious_scans,
            "safe_scans": safe_scans,
            "suspicious_scans": suspicious_scans,
            "avg_threat_score": avg_score,
            "types_breakdown": types_breakdown
        }

def clear_scan_history():
    with get_connection() as conn:
        conn.execute("DELETE FROM scan_logs")
        conn.commit()
