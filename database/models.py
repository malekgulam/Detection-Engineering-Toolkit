import sys
import sqlite3
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config import DB_PATH

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            rule_id TEXT,
            title TEXT,
            technique TEXT,
            tactic TEXT,
            severity TEXT,
            description TEXT
        )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS validation_results (
        id INTEGER PRIMARY KEY,
        rule_id TEXT,
        title TEXT,
        technique TEXT,
        severity TEXT,
        source_ip TEXT,
        timestamp TEXT,
        expected_rule TEXT,
        actual_rule TEXT,
        should_alert INTEGER,
        result TEXT,
        validated_at TEXT
    )
""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rule_metrics (
        id INTEGER PRIMARY KEY,
        rule_id TEXT,
        title TEXT,
        total_tests INTEGER,
        passed INTEGER,
        failed INTEGER,
        fp INTEGER,
        detection_rate REAL,
        fp_rate REAL
    )
""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS overall_metrics (
        id INTEGER PRIMARY KEY,
        run_at TEXT,
        total_tests INTEGER,
        passed INTEGER,
        failed INTEGER,
        fp INTEGER,
        detection_rate REAL,
        fp_rate REAL
    )
""")
    
    conn.commit()
    conn.close()