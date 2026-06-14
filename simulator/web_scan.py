import random
from datetime import datetime, timedelta

SCANNER_IPS = ["45.33.32.156", "198.51.100.23", "93.184.216.34"]
NORMAL_IPS = ["192.168.1.10", "10.0.0.5"]

ENDPOINTS = [
    "/admin", "/wp-admin", "/login", "/.env",
    "/config.php", "/backup.zip", "/api/users",
    "/phpmyadmin", "/shell.php", "/.git"
]

def generate_web_scan_events():
    events = []
    current_time = datetime(2024, 1, 15, 10, 0, 0)

    scanner_ip = random.choice(SCANNER_IPS)

    for i in range(15):
        events.append({
            "event_type": "web_request",
            "source_ip": scanner_ip,
            "endpoint": random.choice(ENDPOINTS),
            "method": "GET",
            "status": "404",
            "timestamp": current_time.strftime("%d/%b/%Y:%H:%M:%S+0000"),
            "expected_rule": "T1595-001",
            "should_alert": True
        })
        current_time += timedelta(seconds=random.randint(1, 3))

    for i in range(12):
        normal_ip = random.choice(NORMAL_IPS)
        events.append({
            "event_type": "web_request",
            "source_ip": normal_ip,
            "endpoint": random.choice(ENDPOINTS),
            "method": "GET",
            "status": "404",
            "timestamp": current_time.strftime("%d/%b/%Y:%H:%M:%S+0000"),
            "expected_rule": "T1595-001",
            "should_alert": False
        })
        current_time += timedelta(seconds=random.randint(1, 5))

    return events