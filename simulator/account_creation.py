import random
from datetime import datetime, timedelta

ATTACKER_IPS = ["192.168.1.105", "10.0.0.22", "172.16.0.99"]
NORMAL_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.12"]

def generate_account_creation_events():
    events = []
    current_time = datetime(2024, 1, 15, 16, 0, 0)

    attacker_ip = random.choice(ATTACKER_IPS)

    for i in range(3):
        events.append({
            "event_type": "user_creation",
            "source_ip": attacker_ip,
            "username": random.choice(["backupadmin", "svc_support", "tempadmin"]),
            "timestamp": current_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1136-001",
            "should_alert": True
        })
        current_time += timedelta(seconds=random.randint(30, 60))

    for i in range(2):
        normal_ip = random.choice(NORMAL_IPS)
        events.append({
            "event_type": "user_creation",
            "source_ip": normal_ip,
            "username": random.choice(["newhire1", "intern1", "contractor1"]),
            "timestamp": current_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1136-001",
            "should_alert": True
        })
        current_time += timedelta(seconds=random.randint(120, 300))

    return events