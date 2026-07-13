import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from flask import Flask, render_template, jsonify
from database.db_handler import (
    load_rules,
    load_validation_results,
    load_validation_result_by_id,
    load_rule_metrics,
    load_overall_metrics,
    load_run_log,
    load_events,
    load_latest_run_id
)
from config import ATTACK_TECHNIQUES, ATTACK_TACTICS, COMMON_TECHNIQUES_WITHOUT_COVERAGE

app = Flask(__name__)

@app.route("/")
def index():
    overall      = load_overall_metrics()
    rule_metrics = load_rule_metrics()
    run_log      = load_run_log()
    latest_run   = run_log[0] if run_log else None
    return render_template("index.html",
        overall=overall,
        rule_metrics=rule_metrics,
        latest_run=latest_run
    )

@app.route("/rules")
def rules():
    rules = load_rules()
    return render_template("rules.html", rules=rules)

@app.route("/validation")
def validation():
    results = load_validation_results()
    passed  = [r for r in results if r["result"] == "PASS"]
    failed  = [r for r in results if r["result"] == "FAIL"]
    fp      = [r for r in results if r["result"] == "FP"]
    return render_template("validation.html",
        results=results,
        passed=passed,
        failed=failed,
        fp=fp
    )

@app.route("/validation/<int:result_id>")
def validation_detail(result_id):
    result = load_validation_result_by_id(result_id)
    if not result:
        return render_template("404.html"), 404
    return render_template("validation_detail.html", result=result)

@app.route("/simulator")
def simulator():
    return render_template("simulator.html")

@app.route("/coverage")
def coverage():
    rules         = load_rules()
    covered       = []
    covered_ids   = set()

    for rule in rules:
        covered_ids.add(rule["technique"])
        covered.append({
            "technique_id":   rule["technique"],
            "technique_name": ATTACK_TECHNIQUES.get(rule["technique"], rule["technique"]),
            "tactic":         rule["tactic"],
            "rule_id":        rule["rule_id"],
            "title":          rule["title"],
            "severity":       rule["severity"]
        })

    gaps = [
        t for t in COMMON_TECHNIQUES_WITHOUT_COVERAGE
        if t["technique_id"] not in covered_ids
    ]

    return render_template("coverage.html",
        covered=covered,
        gaps=gaps,
        covered_count=len(covered),
        gap_count=len(gaps)
    )

@app.route("/metrics")
def metrics():
    overall      = load_overall_metrics()
    rule_metrics = load_rule_metrics()
    return render_template("metrics.html",
        overall=overall,
        rule_metrics=rule_metrics
    )

@app.route("/timeline")
def timeline():
    events  = load_events()
    results = load_validation_results()

    alert_map = {}
    for r in results:
        key = (r["source_ip"], r["rule_id"])
        if key not in alert_map:
            alert_map[key] = r

    timeline_events = []
    for event in events:
        key   = (event["source_ip"], event["expected_rule"])
        alert = alert_map.get(key)
        timeline_events.append({
            "timestamp":     event["timestamp"],
            "event_type":    event["event_type"],
            "source_ip":     event["source_ip"],
            "expected_rule": event["expected_rule"],
            "should_alert":  event["should_alert"],
            "alert":         alert
        })

    return render_template("timeline.html", events=timeline_events)

@app.route("/history")
def history():
    runs = load_run_log()
    return render_template("history.html", runs=runs)

@app.route("/api/run-log")
def api_run_log():
    runs = load_run_log()
    return jsonify(runs)

app.run(debug=True)