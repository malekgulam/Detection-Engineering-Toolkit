from pathlib import Path

BASE_DIR = Path(__file__).parent

RULES_DIR = BASE_DIR / "rules"

DB_PATH = BASE_DIR / "database" / "platform.db"

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

ATTACK_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1595": "Web Scanning",
    "T1078": "Valid Accounts - Off Hours",
    "T1059": "Command and Scripting Interpreter",
    "T1136": "Create Account"
}