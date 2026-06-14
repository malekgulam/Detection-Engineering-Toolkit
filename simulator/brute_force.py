import random
from datetime import datetime, timedelta

ATTACKER_IPS = ["192.168.1.105", "10.0.0.22", "172.16.0.99"]
NORMAL_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.12"]

def generate_brute_force_events():
    events = []
    current_time = datetime(2024, 1, 15, 14, 30, 0)

    attacker_ip = random.choice(ATTACKER_IPS)

    for i in range(8):
        events.append({
            "event_type": "failed_login",
            "source_ip": attacker_ip,
            "username": "admin",
            "timestamp": current_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1110-001",
            "should_alert": True
        })
        current_time += timedelta(seconds=random.randint(5, 10))

    for i in range(6):
        normal_ip = random.choice(NORMAL_IPS)
        events.append({
            "event_type": "failed_login",
            "source_ip": normal_ip,
            "username": random.choice(["john", "sarah", "mike"]),
            "timestamp": current_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1110-001",
            "should_alert": False
        })
        current_time += timedelta(seconds=random.randint(5,25))

    return events