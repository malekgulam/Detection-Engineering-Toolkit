import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from flask import Flask, render_template
from database.db_handler import load_rules, load_validation_results, load_rule_metrics, load_overall_metrics
from config import ATTACK_TECHNIQUES

app = Flask(__name__)

@app.route("/")
def index():
    overall = load_overall_metrics()
    rule_metrics = load_rule_metrics()
    return render_template("index.html", overall=overall, rule_metrics=rule_metrics)

@app.route("/rules")
def rules():
    rules = load_rules()
    return render_template("rules.html", rules=rules)

@app.route("/validation")
def validation():
    results = load_validation_results()
    return render_template("validation.html", results=results)

@app.route("/coverage")
def coverage():
    rules = load_rules()
    coverage_data = []
    for rule in rules:
        coverage_data.append({
            "technique_id": rule["technique"],
            "technique_name": ATTACK_TECHNIQUES.get(rule["technique"], rule["technique"]),
            "tactic": rule["tactic"],
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"]
        })
    return render_template("coverage.html",
        coverage_data=coverage_data,
        covered_count=len(coverage_data)
    )
@app.route("/metrics")
def metrics():
    overall = load_overall_metrics()
    rule_metrics = load_rule_metrics()
    return render_template("metrics.html", overall=overall, rule_metrics=rule_metrics)

app.run(debug=True)