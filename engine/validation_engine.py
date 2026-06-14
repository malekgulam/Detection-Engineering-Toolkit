import sys
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def validate_detections(alerts, events):
    results = []

    validated_rules = set()

    for alert in alerts:
        expected = alert["expected_rule"]
        actual = alert["rule_id"]

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
            "rule_id": alert["rule_id"],
            "title": alert["title"],
            "technique": alert["technique"],
            "severity": alert["severity"],
            "source_ip": alert["source_ip"],
            "timestamp": alert["timestamp"],
            "expected_rule": expected,
            "actual_rule": actual,
            "should_alert": should_alert,
            "result": result,
            "validated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        if should_alert:
            validated_rules.add((alert["source_ip"], alert["rule_id"]))

    expected_events = [
        e for e in events
        if e.get("should_alert", True)
    ]

    checked = set()

    for event in expected_events:
        key = (event["source_ip"], event["expected_rule"])

        if key in checked:
            continue

        checked.add(key)

        if key not in validated_rules:
            results.append({
                "rule_id": event["expected_rule"],
                "title": "Missed Detection",
                "technique": event["expected_rule"].split("-")[0],
                "severity": "HIGH",
                "source_ip": event["source_ip"],
                "timestamp": event["timestamp"],
                "expected_rule": event["expected_rule"],
                "actual_rule": "NONE",
                "should_alert": True,
                "result": "FAIL",
                "validated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return results

def get_metrics(results):
    total = len(results)
    passed = len([r for r in results if r["result"] == "PASS"])
    failed = len([r for r in results if r["result"] == "FAIL"])
    fp = len([r for r in results if r["result"] == "FP"])

    if total == 0:
        detection_rate = 0
        fp_rate = 0
    else:
        detection_rate = round((passed / total) * 100, 2)
        fp_rate = round((fp / total) * 100, 2)

    return {
        "total_tests": total,
        "passed": passed,
        "failed": failed,
        "fp": fp,
        "detection_rate": detection_rate,
        "fp_rate": fp_rate
    }

def get_rule_metrics(results):
    rule_stats = {}

    for r in results:
        rule_id = r["rule_id"]
        title = r["title"]

        if rule_id not in rule_stats:
            rule_stats[rule_id] = {
                "rule_id": rule_id,
                "title": title,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "fp": 0
            }

        rule_stats[rule_id]["total"] += 1

        if r["result"] == "PASS":
            rule_stats[rule_id]["passed"] += 1
        elif r["result"] == "FAIL":
            rule_stats[rule_id]["failed"] += 1
        elif r["result"] == "FP":
            rule_stats[rule_id]["fp"] += 1

    for rule_id in rule_stats:
        total = rule_stats[rule_id]["total"]
        passed = rule_stats[rule_id]["passed"]
        fp = rule_stats[rule_id]["fp"]

        rule_stats[rule_id]["detection_rate"] = round((passed / total) * 100, 2)
        rule_stats[rule_id]["fp_rate"] = round((fp / total) * 100, 2)

    return list(rule_stats.values())