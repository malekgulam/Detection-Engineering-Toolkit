import random
from datetime import datetime, timedelta

SUSPICIOUS_IPS = ["10.0.0.99", "192.168.1.200"]
NORMAL_IPS = ["192.168.1.10", "10.0.0.5"]

USERS = ["admin", "root", "john", "sarah"]

def generate_off_hours_events():
    events = []

    suspicious_ip = random.choice(SUSPICIOUS_IPS)

    for i in range(4):
        hour = random.randint(0, 4)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        suspicious_time = datetime(2024, 1, 15, hour, minute, second)

        events.append({
            "event_type": "successful_login",
            "source_ip": suspicious_ip,
            "username": random.choice(USERS),
            "timestamp": suspicious_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1078-001"
        })

    normal_ip = random.choice(NORMAL_IPS)

    for i in range(3):
        hour = random.randint(9, 17)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        normal_time = datetime(2024, 1, 15, hour, minute, second)

        events.append({
            "event_type": "successful_login",
            "source_ip": normal_ip,
            "username": random.choice(USERS),
            "timestamp": normal_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1078-001"
        })

    return events