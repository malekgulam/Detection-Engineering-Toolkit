import sys
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from engine.rule_loader import load_rules

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

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

def build_alert(rule, event, matched_condition, matched_value, evidence):
    return {
        "rule_id":           rule["rule_id"],
        "title":             rule["title"],
        "technique":         rule["technique"],
        "tactic":            rule.get("tactic", ""),
        "event_type":        rule["event_type"],
        "source_ip":         event["source_ip"],
        "severity":          rule["severity"],
        "timestamp":         event["timestamp"],
        "expected_rule":     event["expected_rule"],
        "status":            "NEW",
        "matched_condition": matched_condition,
        "matched_value":     matched_value,
        "evidence":          evidence
    }

def detect_brute_force(events, rule):
    threshold    = rule["threshold"]
    window_sec   = rule["time_window_seconds"]
    cooldown_sec = rule["cooldown_seconds"]
    alerts       = []

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

            window_events = [
                ev_list[j] for j in range(i, len(times))
                if (times[j] - start_time).total_seconds() <= window_sec
            ]

            if len(window_events) >= threshold:
                duration = round(
                    (times[i + len(window_events) - 1] - start_time).total_seconds()
                )
                matched_condition = "threshold"
                matched_value     = f"{len(window_events)} failed logins in {duration}s"
                evidence          = (
                    f"{len(window_events)} failed login attempts from {ip} "
                    f"within {duration} seconds — threshold is {threshold}"
                )
                alerts.append(build_alert(
                    rule, ev_list[i],
                    matched_condition, matched_value, evidence
                ))
                ip_last_alert[ip] = start_time

    return alerts

def detect_web_scan(events, rule):
    threshold    = rule["threshold"]
    window_sec   = rule["time_window_seconds"]
    cooldown_sec = rule["cooldown_seconds"]
    alerts       = []

    web_events = [
        e for e in events
        if e["event_type"] == rule["event_type"] and e.get("status") == rule["status"]
    ]
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

            window_events = [
                ev_list[j] for j in range(i, len(times))
                if (times[j] - start_time).total_seconds() <= window_sec
            ]

            if len(window_events) >= threshold:
                duration = round(
                    (times[i + len(window_events) - 1] - start_time).total_seconds()
                )
                matched_condition = "threshold"
                matched_value     = f"{len(window_events)} HTTP 404s in {duration}s"
                evidence          = (
                    f"{len(window_events)} HTTP 404 responses from {ip} "
                    f"within {duration} seconds — threshold is {threshold}"
                )
                alerts.append(build_alert(
                    rule, ev_list[i],
                    matched_condition, matched_value, evidence
                ))
                ip_last_alert[ip] = start_time

    return alerts

def detect_off_hours(events, rule):
    time_condition = rule["time_condition"]
    alerts         = []

    rule_parts  = time_condition.split("-")
    rule_start  = datetime.strptime(rule_parts[0], "%H:%M")
    rule_end    = datetime.strptime(rule_parts[1], "%H:%M")
    start_minute = rule_start.hour * 60 + rule_start.minute
    end_minute   = rule_end.hour * 60 + rule_end.minute

    successful_logins = [e for e in events if e["event_type"] == rule["event_type"]]
    if not successful_logins:
        return alerts

    for event in successful_logins:
        dt           = parse_timestamp_auth(event["timestamp"])
        event_minute = dt.hour * 60 + dt.minute

        if start_minute <= event_minute <= end_minute:
            matched_condition = "time_condition"
            matched_value     = f"login at {dt.strftime('%H:%M')} — window {time_condition}"
            evidence          = (
                f"Successful login from {event['source_ip']} "
                f"at {dt.strftime('%H:%M')} — outside business hours ({time_condition})"
            )
            alerts.append(build_alert(
                rule, event,
                matched_condition, matched_value, evidence
            ))

    return alerts

def detect_powershell(events, rule):
    keywords = rule["suspicious_keywords"]
    alerts   = []

    ps_events = [e for e in events if e["event_type"] == rule["event_type"]]
    if not ps_events:
        return alerts

    for event in ps_events:
        command = event.get("command", "").lower()
        for keyword in keywords:
            if keyword in command:
                matched_condition = "keyword"
                matched_value     = f"keyword '{keyword}' found in command"
                evidence          = (
                    f"PowerShell execution from {event['source_ip']} "
                    f"contained suspicious keyword '{keyword}'"
                )
                alerts.append(build_alert(
                    rule, event,
                    matched_condition, matched_value, evidence
                ))
                break

    return alerts

def detect_account_creation(events, rule):
    alerts = []

    account_events = [e for e in events if e["event_type"] == rule["event_type"]]
    if not account_events:
        return alerts

    for event in account_events:
        matched_condition = "event_type"
        matched_value     = f"account_creation event from {event['source_ip']}"
        evidence          = (
            f"New local account created from {event['source_ip']} "
            f"at {event['timestamp']}"
        )
        alerts.append(build_alert(
            rule, event,
            matched_condition, matched_value, evidence
        ))

    return alerts

RULE_DISPATCHER = {
    "brute_force":      detect_brute_force,
    "web_scan":         detect_web_scan,
    "off_hours":        detect_off_hours,
    "powershell":       detect_powershell,
    "account_creation": detect_account_creation
}

def detection_engine(events):
    try:
        rules   = load_rules()
        alerts  = []

        for rule in rules:
            rule_type = rule.get("rule_type")
            detector  = RULE_DISPATCHER.get(rule_type)
            if detector:
                alerts.extend(detector(events, rule))
            else:
                print(f"No detector found for rule_type: {rule_type}")

        return alerts

    except Exception as e:
        print(f"Detection engine error: {e}")
        return []