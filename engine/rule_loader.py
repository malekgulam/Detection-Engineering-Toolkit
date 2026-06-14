import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config import RULES_DIR

def load_rules():
    rules = []

    for rule_file in RULES_DIR.glob("*.json"):
        rule = json.loads(rule_file.read_text())
        rules.append(rule)

    return rules


def get_rule_by_id(rule_id):
    rules = load_rules()
    for rule in rules:
        if rule["rule_id"] == rule_id:
            return rule
    return None
