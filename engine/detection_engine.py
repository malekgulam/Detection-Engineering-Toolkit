import sys
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from engine.rule_loader import load_rules

MONTHS = {"Jan":1, "Feb":2, "Mar":3, "Apr":4, "May":5, "Jun":6,
          "Jul":7, "Aug":8, "Sep":9, "Oct":10, "Nov":11, "Dec":12}

def parse_timestamp_auth(ts):
    parts = ts.split()
    month = MONTHS[parts[0]]
    day = int(parts[1])
    h, m, s = map(int, parts[2].split(":"))
    return datetime(2000, month, day, h, m, s)

def parse_timestamp_access(ts):
    parts = ts.split("/")
    month = MONTHS[parts[1]]
    day = int(parts[0])
    time_parts = parts[2].replace("+0000", "").split(":")
    year = int(time_parts[0])
    h, m, s = map(int, [time_parts[1], time_parts[2], time_parts[3]])
    return datetime(year, month, day, h, m, s)

def detect_brute_force(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = rule["cooldown_seconds"]
    alerts = []

    failed_events = [e for e in events if e["event_type"] == rule["event_type"]]
    if not failed_events:
        return alerts

    ip_events = {}
    for e in failed_events:
        ip_events.setdefault(e["source_ip"], []).append(e)

    ip_last_alert = {}

    for ip, ev_list in ip_events.items():
        times = [parse_timestamp_auth(e["timestamp"]) for e in ev_list]

        for i, start_time in enumerate(times):
            if ip in ip_last_alert:
                if (start_time - ip_last_alert[ip]).total_seconds() < cooldown_sec:
                    continue
            count = 1
            for j in range(i + 1, len(times)):
                if (times[j] - start_time).total_seconds() <= window_sec:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "technique": rule["technique"],
                    "event_type": rule["event_type"],
                    "source_ip": ip,
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "expected_rule": ev_list[i]["expected_rule"],
                    "status": "NEW"
                })
                ip_last_alert[ip] = start_time

    return alerts

def detect_web_scan(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = rule["cooldown_seconds"]
    alerts = []

    web_events = [e for e in events if e["event_type"] == rule["event_type"] and e["status"] == rule["status"]]
    if not web_events:
        return alerts

    ip_events = {}
    for e in web_events:
        ip_events.setdefault(e["source_ip"], []).append(e)

    ip_last_alert = {}

    for ip, ev_list in ip_events.items():
        times = [parse_timestamp_access(e["timestamp"]) for e in ev_list]

        for i, start_time in enumerate(times):
            if ip in ip_last_alert:
                if (start_time - ip_last_alert[ip]).total_seconds() < cooldown_sec:
                    continue
            count = 1
            for j in range(i + 1, len(times)):
                if (times[j] - start_time).total_seconds() <= window_sec:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "technique": rule["technique"],
                    "event_type": rule["event_type"],
                    "source_ip": ip,
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "expected_rule": ev_list[i]["expected_rule"],
                    "status": "NEW"
                })
                ip_last_alert[ip] = start_time

    return alerts

def detect_off_hours(events, rule):
    time_condition = rule["time_condition"]
    alerts = []

    rule_parts = time_condition.split("-")
    rule_start = datetime.strptime(rule_parts[0], "%H:%M")
    rule_end = datetime.strptime(rule_parts[1], "%H:%M")

    start_minute = rule_start.hour * 60 + rule_start.minute
    end_minute = rule_end.hour * 60 + rule_end.minute

    successful_logins = [e for e in events if e["event_type"] == rule["event_type"]]
    if not successful_logins:
        return alerts

    for event in successful_logins:
        dt = parse_timestamp_auth(event["timestamp"])
        event_minute = dt.hour * 60 + dt.minute
        if start_minute <= event_minute <= end_minute:
            alerts.append({
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "technique": rule["technique"],
                "event_type": rule["event_type"],
                "source_ip": event["source_ip"],
                "severity": rule["severity"],
                "timestamp": event["timestamp"],
                "expected_rule": event["expected_rule"],
                "status": "NEW"
            })

    return alerts

def detect_powershell(events, rule):
    keywords = rule["suspicious_keywords"]
    alerts = []

    ps_events = [e for e in events if e["event_type"] == rule["event_type"]]
    if not ps_events:
        return alerts

    for event in ps_events:
        command = event["command"].lower()
        for keyword in keywords:
            if keyword in command:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "technique": rule["technique"],
                    "event_type": rule["event_type"],
                    "source_ip": event["source_ip"],
                    "severity": rule["severity"],
                    "timestamp": event["timestamp"],
                    "expected_rule": event["expected_rule"],
                    "status": "NEW"
                })
                break

    return alerts
def detect_account_creation(events, rule):
    alerts = []

    account_events = [e for e in events if e["event_type"] == rule["event_type"]]
    if not account_events:
        return alerts

    for event in account_events:
        alerts.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "technique": rule["technique"],
            "event_type": rule["event_type"],
            "source_ip": event["source_ip"],
            "severity": rule["severity"],
            "timestamp": event["timestamp"],
            "expected_rule": event["expected_rule"],
            "status": "NEW"
        })

    return alerts

def detection_engine(events):
    try:
        rules = load_rules()
        alerts = []

        brute_force_rule = next((r for r in rules if r["rule_id"] == "T1110-001"), None)
        web_scan_rule = next((r for r in rules if r["rule_id"] == "T1595-001"), None)
        off_hours_rule = next((r for r in rules if r["rule_id"] == "T1078-001"), None)
        powershell_rule = next((r for r in rules if r["rule_id"] == "T1059-001"), None)
        account_creation_rule = next((r for r in rules if r["rule_id"] == "T1136-001"), None)

        alerts.extend(detect_brute_force(events, brute_force_rule) if brute_force_rule else [])
        alerts.extend(detect_web_scan(events, web_scan_rule) if web_scan_rule else [])
        alerts.extend(detect_off_hours(events, off_hours_rule) if off_hours_rule else [])
        alerts.extend(detect_powershell(events, powershell_rule) if powershell_rule else [])
        alerts.extend(detect_account_creation(events, account_creation_rule) if account_creation_rule else [])

        return alerts

    except Exception as e:
        print(f"Error : {e}")

