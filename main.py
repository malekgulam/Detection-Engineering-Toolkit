import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.append(str(project_root))

from engine.rule_loader import load_rules
from simulator.generator import generate_all_events
from engine.detection_engine import detection_engine
from engine.validation_engine import validate_detections, get_metrics, get_rule_metrics
from database.models import init_db
from database.db_handler import save_rules, save_validation_results, save_rule_metrics, save_overall_metrics

def run_pipeline():
    print("=" * 50)
    print("  Detection Engineering Platform")
    print("=" * 50)

    print("\n[1] Initializing database...")
    init_db()
    print("    Database ready")

    print("\n[2] Loading rules...")
    rules = load_rules()
    save_rules(rules)
    print(f"    {len(rules)} rules loaded")
    for rule in rules:
        print(f"    - {rule['rule_id']} | {rule['title']} | {rule['severity']}")

    print("\n[3] Generating attack events...")
    events = generate_all_events()
    print(f"    {len(events)} events generated")

    print("\n[4] Running detection engine...")
    alerts = detection_engine(events)
    print(f"    {len(alerts)} alerts fired")
    for alert in alerts:
        print(f"    - {alert['rule_id']} | {alert['source_ip']} | {alert['severity']}")

    print("\n[5] Running validation engine...")
    results = validate_detections(alerts, events)
    rule_metrics = get_rule_metrics(results)
    overall_metrics = get_metrics(results)

    passed = overall_metrics["passed"]
    failed = overall_metrics["failed"]
    detection_rate = overall_metrics["detection_rate"]

    print(f"    Total tests   : {overall_metrics['total_tests']}")
    print(f"    Passed        : {overall_metrics['passed']}")
    print(f"    Failed        : {overall_metrics['failed']}")
    print(f"    False Positives: {overall_metrics['fp']}")
    print(f"    Detection Rate : {overall_metrics['detection_rate']}%")
    print(f"    FP Rate        : {overall_metrics['fp_rate']}%")
    
    print("\n[6] Saving results to database...")
    save_validation_results(results)
    save_rule_metrics(rule_metrics)
    save_overall_metrics(overall_metrics)
    print("    All results saved")

    print("\n[7] Per rule breakdown...")
    for rm in rule_metrics:
        print(f"    - {rm['rule_id']} | {rm['title']} | {rm['passed']}/{rm['total']} | {rm['detection_rate']}%")

    print("\n" + "=" * 50)
    print("  Pipeline complete. Run dashboard to view results.")
    print("  cd dashboard && python app.py")
    print("=" * 50)

run_pipeline()