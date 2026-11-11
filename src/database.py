
import sqlite3

from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_DIR = BASE_DIR / "data" / "database"
DATABASE_FILE = DATABASE_DIR / "phishguard.db"


# ==========================================
# 1. DATABASE CONNECTION
# ==========================================

def get_connection():

    DATABASE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_FILE,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# 2. INITIALIZE DATABASE
# ==========================================

def initialize_database():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                url TEXT NOT NULL,

                verdict TEXT NOT NULL,

                phishing_probability REAL,

                legitimate_probability REAL,

                risk_score INTEGER,

                risk_level TEXT,

                reputation_status TEXT,

                report_filename TEXT,

                scanned_at TEXT NOT NULL

            )
        """)

        connection.commit()

    finally:
        connection.close()


# ==========================================
# 3. SAVE SCAN
# ==========================================

def save_scan(url, result, report_filename=None):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO scan_history (

                url,
                verdict,
                phishing_probability,
                legitimate_probability,
                risk_score,
                risk_level,
                reputation_status,
                report_filename,
                scanned_at

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        """, (

            url,

            result.get("verdict", "UNKNOWN"),

            result.get("phishing_probability", 0),

            result.get("legitimate_probability", 0),

            result.get("risk", {}).get("score", 0),

            result.get("risk", {}).get("level", "UNKNOWN"),

            result.get("reputation", {}).get("status", "UNKNOWN"),

            report_filename,

            datetime.now(timezone.utc).isoformat()

        ))

        connection.commit()

        return cursor.lastrowid

    finally:
        connection.close()


# ==========================================
# 4. GET ALL SCANS
# ==========================================

def get_all_scans(limit=100):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    finally:
        connection.close()


# ==========================================
# 5. GET ONE SCAN
# ==========================================

def get_scan_by_id(scan_id):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM scan_history
            WHERE id = ?
        """, (scan_id,))

        row = cursor.fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


# ==========================================
# 6. DELETE ONE SCAN
# ==========================================

def delete_scan(scan_id):

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            DELETE FROM scan_history
            WHERE id = ?
        """, (scan_id,))

        connection.commit()

        return cursor.rowcount > 0

    finally:
        connection.close()


# ==========================================
# 7. DATABASE STATISTICS
# ==========================================

def get_scan_statistics():

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) AS total_scans,

                SUM(
                    CASE WHEN verdict = 'PHISHING'
                    THEN 1 ELSE 0 END
                ) AS phishing_scans,

                SUM(
                    CASE WHEN verdict = 'LEGITIMATE'
                    THEN 1 ELSE 0 END
                ) AS legitimate_scans

            FROM scan_history
        """)

        row = cursor.fetchone()

        return {
            "total_scans": row["total_scans"] or 0,
            "phishing_scans": row["phishing_scans"] or 0,
            "legitimate_scans": row["legitimate_scans"] or 0
        }

    finally:
        connection.close()


# ==========================================
# 8. INITIALIZE ON IMPORT
# ==========================================

initialize_database()

