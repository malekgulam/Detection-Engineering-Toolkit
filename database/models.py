import sqlite3
import sys
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
            author TEXT,
            description TEXT,
            false_positive_notes TEXT,
            severity_rationale TEXT,
            references_list TEXT,
            rule_type TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS validation_results (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
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
            matched_condition TEXT,
            matched_value TEXT,
            evidence TEXT,
            validated_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_metrics (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
            rule_id TEXT,
            title TEXT,
            total_tests INTEGER,
            passed INTEGER,
            failed INTEGER,
            fp INTEGER,
            detection_rate REAL,
            fp_rate REAL,
            quality_score REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS overall_metrics (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
            run_at TEXT,
            total_tests INTEGER,
            passed INTEGER,
            failed INTEGER,
            fp INTEGER,
            detection_rate REAL,
            fp_rate REAL,
            overall_quality_score REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS run_log (
            id INTEGER PRIMARY KEY,
            run_at TEXT,
            total_tests INTEGER,
            passed INTEGER,
            failed INTEGER,
            fp INTEGER,
            detection_rate REAL,
            fp_rate REAL,
            overall_quality_score REAL,
            detection_rate_delta REAL,
            fp_rate_delta REAL,
            quality_score_delta REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
            event_type TEXT,
            source_ip TEXT,
            timestamp TEXT,
            expected_rule TEXT,
            should_alert INTEGER,
            raw TEXT
        )
    """)

    conn.commit()
    conn.close()