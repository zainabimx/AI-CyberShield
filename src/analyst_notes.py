"""Persistent analyst notes for SOC investigations."""

from src.database import get_connection, initialize_database


def _ensure_table():
    initialize_database()
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyst_notes (
                alert_id TEXT PRIMARY KEY,
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        conn.close()


def get_analyst_notes(alert_id):
    _ensure_table()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT notes FROM analyst_notes WHERE alert_id = ?",
            (str(alert_id),),
        ).fetchone()
        return str(row["notes"] or "") if row else ""
    finally:
        conn.close()


def save_analyst_notes(alert_id, notes):
    _ensure_table()
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO analyst_notes(alert_id, notes, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(alert_id) DO UPDATE SET
                notes=excluded.notes,
                updated_at=CURRENT_TIMESTAMP
        """, (str(alert_id), str(notes or "").strip()))
        conn.commit()
    finally:
        conn.close()


def delete_analyst_notes(alert_id):
    _ensure_table()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM analyst_notes WHERE alert_id = ?", (str(alert_id),))
        conn.commit()
    finally:
        conn.close()
