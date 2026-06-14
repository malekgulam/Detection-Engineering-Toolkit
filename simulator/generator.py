import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from simulator.brute_force import generate_brute_force_events
from simulator.web_scan import generate_web_scan_events
from simulator.off_hours_login import generate_off_hours_events
from simulator.powershell_abuse import generate_powershell_events
from simulator.account_creation import generate_account_creation_events

def generate_all_events():
    all_events = []

    all_events.extend(generate_brute_force_events())
    all_events.extend(generate_web_scan_events())
    all_events.extend(generate_off_hours_events())
    all_events.extend(generate_powershell_events())
    all_events.extend(generate_account_creation_events())

    return all_events