import sqlite3
import sys
import json
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn

def create_run():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO run_log (run_at, total_tests, passed, failed, fp,
        detection_rate, fp_rate, overall_quality_score,
        detection_rate_delta, fp_rate_delta, quality_score_delta)
        VALUES (?, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return run_id

def save_rules(rules, run_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rules")
    for rule in rules:
        cursor.execute("""
            INSERT INTO rules (
                rule_id, title, technique, tactic, severity,
                author, description, false_positive_notes,
                severity_rationale, references_list, rule_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule["rule_id"],
            rule["title"],
            rule["technique"],
            rule.get("tactic", ""),
            rule["severity"],
            rule.get("author", ""),
            rule.get("description", ""),
            rule.get("false_positive_notes", ""),
            rule.get("severity_rationale", ""),
            json.dumps(rule.get("references", [])),
            rule.get("rule_type", "")
        ))
    conn.commit()
    conn.close()

def save_events(events, run_id):
    conn = get_connection()
    cursor = conn.cursor()
    for event in events:
        cursor.execute("""
            INSERT INTO events (run_id, event_type, source_ip, timestamp,
            expected_rule, should_alert, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            event.get("event_type"),
            event.get("source_ip"),
            event.get("timestamp"),
            event.get("expected_rule"),
            1 if event.get("should_alert", True) else 0,
            json.dumps(event)
        ))
    conn.commit()
    conn.close()

def save_validation_results(results, run_id):
    conn = get_connection()
    cursor = conn.cursor()
    for r in results:
        cursor.execute("""
            INSERT INTO validation_results (
                run_id, rule_id, title, technique, severity,
                source_ip, timestamp, expected_rule, actual_rule,
                should_alert, result, matched_condition,
                matched_value, evidence, validated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
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
            r.get("matched_condition", ""),
            r.get("matched_value", ""),
            r.get("evidence", ""),
            r["validated_at"]
        ))
    conn.commit()
    conn.close()

def save_rule_metrics(rule_metrics, run_id):
    conn = get_connection()
    cursor = conn.cursor()
    for rm in rule_metrics:
        cursor.execute("""
            INSERT INTO rule_metrics (
                run_id, rule_id, title, total_tests, passed,
                failed, fp, detection_rate, fp_rate, quality_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            rm["rule_id"],
            rm["title"],
            rm["total"],
            rm["passed"],
            rm["failed"],
            rm["fp"],
            rm["detection_rate"],
            rm["fp_rate"],
            rm.get("quality_score", 0.0)
        ))
    conn.commit()
    conn.close()

def save_overall_metrics(metrics, run_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO overall_metrics (
            run_id, run_at, total_tests, passed, failed, fp,
            detection_rate, fp_rate, overall_quality_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        metrics["total_tests"],
        metrics["passed"],
        metrics["failed"],
        metrics["fp"],
        metrics["detection_rate"],
        metrics["fp_rate"],
        metrics.get("overall_quality_score", 0.0)
    ))
    conn.commit()
    conn.close()

def update_run_log(run_id, metrics):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT detection_rate, fp_rate, overall_quality_score
        FROM run_log
        WHERE id < ?
        ORDER BY id DESC
        LIMIT 1
    """, (run_id,))
    prev = cursor.fetchone()

    if prev:
        detection_rate_delta  = round(metrics["detection_rate"]        - prev[0], 2)
        fp_rate_delta         = round(metrics["fp_rate"]               - prev[1], 2)
        quality_score_delta   = round(metrics["overall_quality_score"] - prev[2], 2)
    else:
        detection_rate_delta  = 0.0
        fp_rate_delta         = 0.0
        quality_score_delta   = 0.0

    cursor.execute("""
        UPDATE run_log SET
            total_tests           = ?,
            passed                = ?,
            failed                = ?,
            fp                    = ?,
            detection_rate        = ?,
            fp_rate               = ?,
            overall_quality_score = ?,
            detection_rate_delta  = ?,
            fp_rate_delta         = ?,
            quality_score_delta   = ?
        WHERE id = ?
    """, (
        metrics["total_tests"],
        metrics["passed"],
        metrics["failed"],
        metrics["fp"],
        metrics["detection_rate"],
        metrics["fp_rate"],
        metrics["overall_quality_score"],
        detection_rate_delta,
        fp_rate_delta,
        quality_score_delta,
        run_id
    ))
    conn.commit()
    conn.close()

def load_latest_run_id():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(id) FROM run_log")
    row = cursor.fetchone()
    conn.close()
    if not row or row[0] is None:
        return None
    return row[0]

def load_rules():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rules")
    rows = cursor.fetchall()
    conn.close()
    rules = []
    for row in rows:
        rules.append({
            "id":                   row[0],
            "rule_id":              row[1],
            "title":                row[2],
            "technique":            row[3],
            "tactic":               row[4],
            "severity":             row[5],
            "author":               row[6],
            "description":          row[7],
            "false_positive_notes": row[8],
            "severity_rationale":   row[9],
            "references_list":      json.loads(row[10]) if row[10] else [],
            "rule_type":            row[11]
        })
    conn.close()
    return rules

def load_validation_results(run_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    if run_id:
        cursor.execute("""
            SELECT * FROM validation_results
            WHERE run_id = ? ORDER BY id ASC
        """, (run_id,))
    else:
        latest = load_latest_run_id()
        if not latest:
            conn.close()
            return []
        cursor.execute("""
            SELECT * FROM validation_results
            WHERE run_id = ? ORDER BY id ASC
        """, (latest,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        results.append({
            "id":                row[0],
            "run_id":            row[1],
            "rule_id":           row[2],
            "title":             row[3],
            "technique":         row[4],
            "severity":          row[5],
            "source_ip":         row[6],
            "timestamp":         row[7],
            "expected_rule":     row[8],
            "actual_rule":       row[9],
            "should_alert":      bool(row[10]),
            "result":            row[11],
            "matched_condition": row[12],
            "matched_value":     row[13],
            "evidence":          row[14],
            "validated_at":      row[15]
        })
    return results

def load_validation_result_by_id(result_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM validation_results WHERE id = ?", (result_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id":                row[0],
        "run_id":            row[1],
        "rule_id":           row[2],
        "title":             row[3],
        "technique":         row[4],
        "severity":          row[5],
        "source_ip":         row[6],
        "timestamp":         row[7],
        "expected_rule":     row[8],
        "actual_rule":       row[9],
        "should_alert":      bool(row[10]),
        "result":            row[11],
        "matched_condition": row[12],
        "matched_value":     row[13],
        "evidence":          row[14],
        "validated_at":      row[15]
    }

def load_rule_metrics(run_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    if run_id:
        cursor.execute("""
            SELECT * FROM rule_metrics WHERE run_id = ?
        """, (run_id,))
    else:
        latest = load_latest_run_id()
        if not latest:
            conn.close()
            return []
        cursor.execute("""
            SELECT * FROM rule_metrics WHERE run_id = ?
        """, (latest,))
    rows = cursor.fetchall()
    conn.close()
    metrics = []
    for row in rows:
        metrics.append({
            "id":             row[0],
            "run_id":         row[1],
            "rule_id":        row[2],
            "title":          row[3],
            "total_tests":    row[4],
            "passed":         row[5],
            "failed":         row[6],
            "fp":             row[7],
            "detection_rate": row[8],
            "fp_rate":        row[9],
            "quality_score":  row[10]
        })
    return metrics

def load_overall_metrics(run_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    if run_id:
        cursor.execute("""
            SELECT * FROM overall_metrics WHERE run_id = ?
        """, (run_id,))
    else:
        latest = load_latest_run_id()
        if not latest:
            conn.close()
            return None
        cursor.execute("""
            SELECT * FROM overall_metrics WHERE run_id = ?
        """, (latest,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id":                    row[0],
        "run_id":                row[1],
        "run_at":                row[2],
        "total_tests":           row[3],
        "passed":                row[4],
        "failed":                row[5],
        "fp":                    row[6],
        "detection_rate":        row[7],
        "fp_rate":               row[8],
        "overall_quality_score": row[9]
    }

def load_run_log():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM run_log ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    runs = []
    for row in rows:
        runs.append({
            "id":                    row[0],
            "run_at":                row[1],
            "total_tests":           row[2],
            "passed":                row[3],
            "failed":                row[4],
            "fp":                    row[5],
            "detection_rate":        row[6],
            "fp_rate":               row[7],
            "overall_quality_score": row[8],
            "detection_rate_delta":  row[9],
            "fp_rate_delta":         row[10],
            "quality_score_delta":   row[11]
        })
    return runs

def load_events(run_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    if run_id:
        cursor.execute("""
            SELECT * FROM events WHERE run_id = ? ORDER BY id ASC
        """, (run_id,))
    else:
        latest = load_latest_run_id()
        if not latest:
            conn.close()
            return []
        cursor.execute("""
            SELECT * FROM events WHERE run_id = ? ORDER BY id ASC
        """, (latest,))
    rows = cursor.fetchall()
    conn.close()
    events = []
    for row in rows:
        raw = json.loads(row[7]) if row[7] else {}
        events.append({
            "id":            row[0],
            "run_id":        row[1],
            "event_type":    row[2],
            "source_ip":     row[3],
            "timestamp":     row[4],
            "expected_rule": row[5],
            "should_alert":  bool(row[6]),
            "raw":           raw
        })
    return events