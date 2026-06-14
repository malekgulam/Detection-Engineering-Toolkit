import sys
import sqlite3
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def save_rules(rules):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM rules")

    for rule in rules:
        cursor.execute("""
            INSERT INTO rules (rule_id, title, technique, tactic, severity, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            rule["rule_id"],
            rule["title"],
            rule["technique"],
            rule.get("tactic", ""),
            rule["severity"],
            rule.get("description", "")
        ))

    conn.commit()
    conn.close()

def save_validation_results(results):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM validation_results")
    for r in results:
        cursor.execute("""
            INSERT INTO validation_results (rule_id, title, technique, severity, source_ip, timestamp, expected_rule, actual_rule, should_alert, result, validated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r["rule_id"],
            r["title"],
            r["technique"],
            r["severity"],
            r["source_ip"],
            r["timestamp"],
            r["expected_rule"],
            r["actual_rule"],
            1 if r["should_alert"] else 0,
            r["result"],
            r["validated_at"]
        ))
    conn.commit()
    conn.close()


def save_rule_metrics(rule_metrics):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rule_metrics")
    for rm in rule_metrics:
        cursor.execute("""
            INSERT INTO rule_metrics (rule_id, title, total_tests, passed, failed, fp, detection_rate, fp_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rm["rule_id"],
            rm["title"],
            rm["total"],
            rm["passed"],
            rm["failed"],
            rm["fp"],
            rm["detection_rate"],
            rm["fp_rate"]
        ))
    conn.commit()
    conn.close()

def save_overall_metrics(metrics):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM overall_metrics")
    cursor.execute("""
        INSERT INTO overall_metrics (run_at, total_tests, passed, failed, fp, detection_rate, fp_rate)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        metrics["total_tests"],
        metrics["passed"],
        metrics["failed"],
        metrics["fp"],
        metrics["detection_rate"],
        metrics["fp_rate"]
    ))
    conn.commit()
    conn.close()

def load_rules():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rules")
    rows = cursor.fetchall()
    rules = []
    for row in rows:
        rules.append({
            "id": row[0],
            "rule_id": row[1],
            "title": row[2],
            "technique": row[3],
            "tactic": row[4],
            "severity": row[5],
            "description": row[6]
        })
    conn.close()
    return rules

def load_validation_results():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM validation_results")
    rows = cursor.fetchall()
    results = []
    for row in rows:
        results.append({
            "id": row[0],
            "rule_id": row[1],
            "title": row[2],
            "technique": row[3],
            "severity": row[4],
            "source_ip": row[5],
            "timestamp": row[6],
            "expected_rule": row[7],
            "actual_rule": row[8],
            "should_alert": bool(row[9]),
            "result": row[10],
            "validated_at": row[11]
        })
    conn.close()
    return results

def load_rule_metrics():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rule_metrics")
    rows = cursor.fetchall()
    metrics = []
    for row in rows:
        metrics.append({
            "id": row[0],
            "rule_id": row[1],
            "title": row[2],
            "total_tests": row[3],
            "passed": row[4],
            "failed": row[5],
            "fp": row[6],
            "detection_rate": row[7],
            "fp_rate": row[8]
        })
    conn.close()
    return metrics

def load_overall_metrics():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM overall_metrics")
    rows = cursor.fetchall()
    if not rows:
        return None
    row = rows[0]
    conn.close()
    return {
        "id": row[0],
        "run_at": row[1],
        "total_tests": row[2],
        "passed": row[3],
        "failed": row[4],
        "fp": row[5],
        "detection_rate": row[6],
        "fp_rate": row[7]
    }
