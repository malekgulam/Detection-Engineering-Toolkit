from pathlib import Path

BASE_DIR = Path(__file__).parent

RULES_DIR = BASE_DIR / "rules"

DB_PATH = BASE_DIR / "database" / "platform.db"

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_BASE_SCORE = {
    "LOW": 15,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90
}

ATTACK_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1595": "Active Scanning",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1136": "Create Account"
}

ATTACK_TACTICS = {
    "T1110": "Credential Access",
    "T1595": "Reconnaissance",
    "T1078": "Defense Evasion",
    "T1059": "Execution",
    "T1136": "Persistence"
}

COMMON_TECHNIQUES_WITHOUT_COVERAGE = [
    {"technique_id": "T1003", "technique_name": "OS Credential Dumping",    "tactic": "Credential Access"},
    {"technique_id": "T1055", "technique_name": "Process Injection",         "tactic": "Defense Evasion"},
    {"technique_id": "T1053", "technique_name": "Scheduled Task/Job",        "tactic": "Persistence"},
    {"technique_id": "T1021", "technique_name": "Remote Services",           "tactic": "Lateral Movement"},
    {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"technique_id": "T1070", "technique_name": "Indicator Removal",         "tactic": "Defense Evasion"},
    {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer",     "tactic": "Command and Control"},
    {"technique_id": "T1027", "technique_name": "Obfuscated Files",          "tactic": "Defense Evasion"},
    {"technique_id": "T1548", "technique_name": "Abuse Elevation Control",   "tactic": "Privilege Escalation"},
    {"technique_id": "T1566", "technique_name": "Phishing",                  "tactic": "Initial Access"},
]

QUALITY_SCORE_WEIGHTS = {
    "detection_rate": 0.5,
    "fp_penalty":     0.3,
    "severity_bonus": 0.2
}