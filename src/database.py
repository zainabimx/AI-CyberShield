import sqlite3
import json
from pathlib import Path


# ==========================================
# DATABASE LOCATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cybersecurity.db"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():
    DATA_DIR.mkdir(exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# ==========================================
# INITIALIZE DATABASE
# ==========================================

def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source TEXT,
            threat_type TEXT,
            severity TEXT,
            priority TEXT,
            confidence REAL,
            risk_score INTEGER,
            status TEXT,
            indicators TEXT,
            mitre_techniques TEXT,
            summary TEXT
        )
    """)

    connection.commit()
    connection.close()


# ==========================================
# SAVE ALERT
# ==========================================

def save_alert(alert):
    connection = get_connection()

    connection.execute("""
        INSERT OR REPLACE INTO alerts (
            alert_id,
            timestamp,
            source,
            threat_type,
            severity,
            priority,
            confidence,
            risk_score,
            status,
            indicators,
            mitre_techniques,
            summary
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["alert_id"],
        alert["timestamp"],
        alert["source"],
        alert["threat_type"],
        alert["severity"],
        alert["priority"],
        alert["confidence"],
        alert["risk_score"],
        alert["status"],
        json.dumps(alert["indicators"]),
        json.dumps(alert["mitre_techniques"]),
        alert["summary"]
    ))

    connection.commit()
    connection.close()


# ==========================================
# GET ALL ALERTS
# ==========================================

def get_all_alerts():
    connection = get_connection()

    rows = connection.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
    """).fetchall()

    connection.close()

    alerts = []

    for row in rows:
        alert = dict(row)

        alert["indicators"] = json.loads(
            alert["indicators"] or "[]"
        )

        alert["mitre_techniques"] = json.loads(
            alert["mitre_techniques"] or "[]"
        )

        alerts.append(alert)

    return alerts


# ==========================================
# GET ONE ALERT
# ==========================================

def get_alert(alert_id):
    connection = get_connection()

    row = connection.execute("""
        SELECT *
        FROM alerts
        WHERE alert_id = ?
    """, (alert_id,)).fetchone()

    connection.close()

    if row is None:
        return None

    alert = dict(row)

    alert["indicators"] = json.loads(
        alert["indicators"] or "[]"
    )

    alert["mitre_techniques"] = json.loads(
        alert["mitre_techniques"] or "[]"
    )

    return alert


# ==========================================
# UPDATE ALERT STATUS
# ==========================================

def update_alert_status(alert_id, status):
    connection = get_connection()

    connection.execute("""
        UPDATE alerts
        SET status = ?
        WHERE alert_id = ?
    """, (status, alert_id))

    connection.commit()
    connection.close()


# ==========================================
# DELETE ONE ALERT
# ==========================================

def delete_alert(alert_id):
    connection = get_connection()

    connection.execute("""
        DELETE FROM alerts
        WHERE alert_id = ?
    """, (alert_id,))

    connection.commit()
    connection.close()


# ==========================================
# DELETE OLD CLOSED ALERTS
# ==========================================

def delete_old_closed_alerts(days=30):
    connection = get_connection()

    connection.execute("""
        DELETE FROM alerts
        WHERE status = 'CLOSED'
        AND datetime(timestamp) < datetime('now', ?)
    """, (f"-{days} days",))

    deleted_count = connection.total_changes

    connection.commit()
    connection.close()

    return deleted_count


# ==========================================
# DATABASE STARTUP
# ==========================================

initialize_database()