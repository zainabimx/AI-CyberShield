"""SQLite persistence for AI CyberShield SOC alerts and incident reports."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "soc_alerts.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                priority TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                indicators TEXT NOT NULL DEFAULT '[]',
                mitre_techniques TEXT NOT NULL DEFAULT '[]',
                summary TEXT NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyst_notes (
                alert_id TEXT PRIMARY KEY,
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_reports (
                report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                verdict TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                timestamp TEXT NOT NULL,
                report TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Safe migration for databases created by earlier versions.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(incident_reports)").fetchall()}
        if "alert_id" not in columns:
            conn.execute("ALTER TABLE incident_reports ADD COLUMN alert_id TEXT")
        if "status" not in columns:
            conn.execute("ALTER TABLE incident_reports ADD COLUMN status TEXT NOT NULL DEFAULT 'OPEN'")

        conn.commit()
    finally:
        conn.close()


def _alert_from_row(row):
    if row is None:
        return None
    item = dict(row)
    for key in ("indicators", "mitre_techniques"):
        try:
            item[key] = json.loads(item.get(key) or "[]")
        except (TypeError, json.JSONDecodeError):
            item[key] = []
    return item


def save_alert(alert):
    initialize_database()
    conn = get_connection()
    try:
        conn.execute("""
            INSERT OR REPLACE INTO alerts
            (alert_id, timestamp, source, threat_type, severity, priority,
             confidence, risk_score, status, indicators, mitre_techniques, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["alert_id"], alert["timestamp"], alert["source"],
            alert["threat_type"], alert["severity"], alert["priority"],
            float(alert["confidence"]), int(alert["risk_score"]),
            alert.get("status", "OPEN"),
            json.dumps(alert.get("indicators", [])),
            json.dumps(alert.get("mitre_techniques", [])),
            alert.get("summary", ""),
        ))
        conn.commit()
    finally:
        conn.close()


def get_all_alerts():
    initialize_database()
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
        return [_alert_from_row(row) for row in rows]
    finally:
        conn.close()


def get_alert(alert_id):
    initialize_database()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (str(alert_id),)).fetchone()
        return _alert_from_row(row)
    finally:
        conn.close()


def update_alert_status(alert_id, status):
    initialize_database()
    conn = get_connection()
    try:
        conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, str(alert_id)))
        conn.commit()
    finally:
        conn.close()


def delete_alert(alert_id):
    initialize_database()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM analyst_notes WHERE alert_id = ?", (str(alert_id),))
        conn.execute("DELETE FROM alerts WHERE alert_id = ?", (str(alert_id),))
        conn.commit()
    finally:
        conn.close()


def delete_old_closed_alerts(days=30):
    initialize_database()
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(days))
    conn = get_connection()
    try:
        rows = conn.execute("SELECT alert_id, timestamp FROM alerts WHERE status IN ('CLOSED', 'RESOLVED')").fetchall()
        ids = []
        for row in rows:
            try:
                stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if stamp < cutoff:
                    ids.append(row["alert_id"])
            except (ValueError, TypeError):
                continue
        if ids:
            conn.executemany("DELETE FROM alerts WHERE alert_id = ?", [(x,) for x in ids])
        conn.commit()
        return len(ids)
    finally:
        conn.close()


def save_incident_report(*, title, source, severity, verdict, timestamp, report, alert_id=None, status="OPEN"):
    """Create a report once, then update that same report when an alert changes."""
    initialize_database()
    conn = get_connection()
    try:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        if alert_id:
            existing = conn.execute(
                "SELECT report_id FROM incident_reports WHERE alert_id = ? ORDER BY report_id ASC LIMIT 1",
                (str(alert_id),),
            ).fetchone()
            if existing:
                conn.execute("""
                    UPDATE incident_reports
                    SET title = ?, source = ?, severity = ?, verdict = ?, status = ?,
                        timestamp = ?, report = ?
                    WHERE report_id = ?
                """, (
                    str(title), str(source), str(severity), str(verdict), str(status),
                    str(timestamp), str(report), existing["report_id"],
                ))
                conn.commit()
                return existing["report_id"]

        cur = conn.execute("""
            INSERT INTO incident_reports
            (alert_id, title, source, severity, verdict, status, timestamp, report, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(alert_id) if alert_id else None, str(title), str(source), str(severity),
            str(verdict), str(status), str(timestamp), str(report), now,
        ))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_incident_report(alert_id):
    """Return the persistent incident report associated with one SOC alert."""
    initialize_database()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM incident_reports WHERE alert_id = ? ORDER BY report_id ASC LIMIT 1",
            (str(alert_id),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def update_incident_report(alert_id, *, report=None, status=None):
    """Update an existing incident report without creating a duplicate."""
    initialize_database()
    conn = get_connection()
    try:
        fields = []
        values = []
        if report is not None:
            fields.append("report = ?")
            values.append(str(report))
        if status is not None:
            fields.append("status = ?")
            values.append(str(status))
        if not fields:
            return False
        values.append(str(alert_id))
        cur = conn.execute(
            f"UPDATE incident_reports SET {', '.join(fields)} WHERE alert_id = ?",
            values,
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_all_incident_reports():
    initialize_database()
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM incident_reports ORDER BY report_id DESC").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_database_stats():
    """Return counts for SOC alerts, incident reports and analyst notes."""
    initialize_database()
    conn = get_connection()
    try:
        return {
            "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "reports": conn.execute("SELECT COUNT(*) FROM incident_reports").fetchone()[0],
            "notes": conn.execute("SELECT COUNT(*) FROM analyst_notes").fetchone()[0],
        }
    finally:
        conn.close()


def clear_all_soc_data():
    """Delete all SOC alerts, incident reports and analyst notes."""
    initialize_database()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM analyst_notes")
        conn.execute("DELETE FROM incident_reports")
        conn.execute("DELETE FROM alerts")
        conn.commit()
    finally:
        conn.close()


initialize_database()
