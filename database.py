
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "trace.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _columns(connection, table):
    return {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }


def _ensure_columns(connection, table, required):
    """Add missing columns to existing database tables."""
    existing = _columns(connection, table)

    for column_name, column_type in required.items():
        if column_name not in existing:
            connection.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {column_name} {column_type}"
            )


def initialize_database():
    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS missions (
                mission_id TEXT PRIMARY KEY,
                objective TEXT NOT NULL,
                max_budget REAL NOT NULL,
                currency TEXT NOT NULL DEFAULT 'USD',
                prohibited_add_ons TEXT DEFAULT '',
                paypal_order_id TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS agent_events (
                event_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                item_name TEXT DEFAULT '',
                description TEXT DEFAULT '',
                amount REAL,
                currency TEXT DEFAULT 'USD',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                timestamp TEXT,
                FOREIGN KEY (mission_id)
                    REFERENCES missions (mission_id)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_reviews (
                review_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT DEFAULT '',
                reviewer TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                paypal_order_id TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_resolutions (
                resolution_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                paypal_order_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                resolution_type TEXT NOT NULL,
                reason TEXT DEFAULT '',
                reviewer TEXT DEFAULT '',
                evidence_json TEXT DEFAULT '{}',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS paypal_order_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                paypal_order_id TEXT NOT NULL,
                request_json TEXT NOT NULL,
                response_json TEXT NOT NULL,
                excluded_event_ids TEXT DEFAULT '[]',
                client_id_fingerprint TEXT DEFAULT '',
                base_url TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mission_id)
                    REFERENCES missions (mission_id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS paypal_order_history (
                history_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                paypal_order_id TEXT NOT NULL UNIQUE,
                verification_status TEXT NOT NULL,
                verification_note TEXT DEFAULT '',
                client_id_fingerprint TEXT DEFAULT '',
                base_url TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mission_id)
                    REFERENCES missions (mission_id)
            )
        """)
        # Migrations for older databases.
        _ensure_columns(connection, "missions", {
            "paypal_order_id": "TEXT",
        })

        _ensure_columns(connection, "agent_events", {
            "item_name": "TEXT DEFAULT ''",
            "description": "TEXT DEFAULT ''",
            "amount": "REAL",
            "currency": "TEXT DEFAULT 'USD'",
            "created_at": "TEXT",
            "timestamp": "TEXT",
        })

        _ensure_columns(connection, "incident_reviews", {
            "incident_id": "TEXT",
            "mission_id": "TEXT",
            "decision": "TEXT",
            "reason": "TEXT DEFAULT ''",
            "reviewer": "TEXT DEFAULT ''",
            "created_at": "TEXT",
            "paypal_order_id": "TEXT",
        })

        _ensure_columns(connection, "incident_resolutions", {
            "incident_id": "TEXT",
        })

        _ensure_columns(connection, "paypal_order_snapshots", {
            "paypal_order_id": "TEXT",
        })
