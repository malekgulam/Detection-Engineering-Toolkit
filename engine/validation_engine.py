import sys
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config import SEVERITY_BASE_SCORE, QUALITY_SCORE_WEIGHTS

def validate_detections(alerts, events):
    results        = []
    validated_rules = set()

    for alert in alerts:
        expected = alert["expected_rule"]
        actual   = alert["rule_id"]

        matching_events = [
            e for e in events
            if e.get("source_ip") == alert["source_ip"]
            and e.get("expected_rule") == alert["rule_id"]
        ]

        should_alert = any(e.get("should_alert", True) for e in matching_events)

        if not should_alert:
            result = "FP"
        elif expected == actual:
            result = "PASS"
        else:
            result = "FAIL"

        results.append({
            "rule_id":           alert["rule_id"],
            "title":             alert["title"],
            "technique":         alert["technique"],
            "tactic":            alert.get("tactic", ""),
            "severity":          alert["severity"],
            "source_ip":         alert["source_ip"],
            "timestamp":         alert["timestamp"],
            "expected_rule":     expected,
            "actual_rule":       actual,
            "should_alert":      should_alert,
            "result":            result,
            "matched_condition": alert.get("matched_condition", ""),
            "matched_value":     alert.get("matched_value", ""),
            "evidence":          alert.get("evidence", ""),
            "validated_at":      datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        if should_alert:
            validated_rules.add((alert["source_ip"], alert["rule_id"]))

    expected_events = [e for e in events if e.get("should_alert", True)]
    checked         = set()

    for event in expected_events:
        key = (event["source_ip"], event["expected_rule"])
        if key in checked:
            continue
        checked.add(key)

        if key not in validated_rules:
            results.append({
                "rule_id":           event["expected_rule"],
                "title":             "Missed Detection",
                "technique":         event["expected_rule"].split("-")[0],
                "tactic":            "",
                "severity":          "HIGH",
                "source_ip":         event["source_ip"],
                "timestamp":         event["timestamp"],
                "expected_rule":     event["expected_rule"],
                "actual_rule":       "NONE",
                "should_alert":      True,
                "result":            "FAIL",
                "matched_condition": "",
                "matched_value":     "",
                "evidence":          f"No alert fired for expected rule {event['expected_rule']} from {event['source_ip']}",
                "validated_at":      datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return results

def compute_quality_score(detection_rate, fp_rate, severity):
    base_score      = SEVERITY_BASE_SCORE.get(severity, 40)
    severity_bonus  = round((base_score / 100) * QUALITY_SCORE_WEIGHTS["severity_bonus"] * 100, 2)
    detection_part  = round(detection_rate * QUALITY_SCORE_WEIGHTS["detection_rate"], 2)
    fp_penalty      = round(fp_rate        * QUALITY_SCORE_WEIGHTS["fp_penalty"], 2)
    score           = round(detection_part - fp_penalty + severity_bonus, 2)
    return max(0.0, min(score, 100.0))

def get_metrics(results):
    total   = len(results)
    passed  = len([r for r in results if r["result"] == "PASS"])
    failed  = len([r for r in results if r["result"] == "FAIL"])
    fp      = len([r for r in results if r["result"] == "FP"])

    if total == 0:
        detection_rate = 0.0
        fp_rate        = 0.0
    else:
        detection_rate = round((passed / total) * 100, 2)
        fp_rate        = round((fp     / total) * 100, 2)

    overall_quality_score = compute_quality_score(detection_rate, fp_rate, "HIGH")

    return {
        "total_tests":           total,
        "passed":                passed,
        "failed":                failed,
        "fp":                    fp,
        "detection_rate":        detection_rate,
        "fp_rate":               fp_rate,
        "overall_quality_score": overall_quality_score
    }

def get_rule_metrics(results):
    rule_stats = {}

    for r in results:
        rule_id = r["rule_id"]
        title   = r["title"]

        if rule_id not in rule_stats:
            rule_stats[rule_id] = {
                "rule_id":  rule_id,
                "title":    title,
                "severity": r.get("severity", "MEDIUM"),
                "total":    0,
                "passed":   0,
                "failed":   0,
                "fp":       0
            }

        rule_stats[rule_id]["total"] += 1

        if r["result"] == "PASS":
            rule_stats[rule_id]["passed"] += 1
        elif r["result"] == "FAIL":
            rule_stats[rule_id]["failed"] += 1
        elif r["result"] == "FP":
            rule_stats[rule_id]["fp"] += 1

    metrics = []
    for rule_id, stats in rule_stats.items():
        total   = stats["total"]
        passed  = stats["passed"]
        fp      = stats["fp"]

        detection_rate = round((passed / total) * 100, 2) if total > 0 else 0.0
        fp_rate        = round((fp     / total) * 100, 2) if total > 0 else 0.0
        quality_score  = compute_quality_score(detection_rate, fp_rate, stats["severity"])

        metrics.append({
            "rule_id":        rule_id,
            "title":          stats["title"],
            "severity":       stats["severity"],
            "total":          total,
            "passed":         passed,
            "failed":         stats["failed"],
            "fp":             fp,
            "detection_rate": detection_rate,
            "fp_rate":        fp_rate,
            "quality_score":  quality_score
        })

    return metrics