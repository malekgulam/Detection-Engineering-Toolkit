import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.append(str(project_root))

from engine.rule_loader import load_rules
from simulator.generator import generate_all_events
from engine.detection_engine import detection_engine
from engine.validation_engine import validate_detections, get_metrics, get_rule_metrics
from database.models import init_db
from database.db_handler import (
    create_run,
    save_rules,
    save_events,
    save_validation_results,
    save_rule_metrics,
    save_overall_metrics,
    update_run_log
)

def run_pipeline():
    print("=" * 50)
    print("  Detection Engineering Platform")
    print("=" * 50)

    print("\n[1] Initializing database...")
    init_db()
    print("    Database ready")

    print("\n[2] Creating run...")
    run_id = create_run()
    print(f"    Run ID: {run_id}")

    print("\n[3] Loading rules...")
    rules = load_rules()
    save_rules(rules, run_id)
    print(f"    {len(rules)} rules loaded")
    for rule in rules:
        print(f"    - {rule['rule_id']} | {rule['title']} | {rule['severity']}")

    print("\n[4] Generating attack events...")
    events = generate_all_events()
    save_events(events, run_id)
    print(f"    {len(events)} events generated and saved")

    print("\n[5] Running detection engine...")
    alerts = detection_engine(events)
    print(f"    {len(alerts)} alerts fired")
    for alert in alerts:
        print(f"    - {alert['rule_id']} | {alert['source_ip']} | {alert['severity']}")
        print(f"      Evidence: {alert.get('evidence', 'N/A')}")

    print("\n[6] Running validation engine...")
    results        = validate_detections(alerts, events)
    rule_metrics   = get_rule_metrics(results)
    overall_metrics = get_metrics(results)

    print(f"    Total tests    : {overall_metrics['total_tests']}")
    print(f"    Passed         : {overall_metrics['passed']}")
    print(f"    Failed         : {overall_metrics['failed']}")
    print(f"    False Positives: {overall_metrics['fp']}")
    print(f"    Detection Rate : {overall_metrics['detection_rate']}%")
    print(f"    FP Rate        : {overall_metrics['fp_rate']}%")
    print(f"    Quality Score  : {overall_metrics['overall_quality_score']}")

    print("\n[7] Saving results...")
    save_validation_results(results, run_id)
    save_rule_metrics(rule_metrics, run_id)
    save_overall_metrics(overall_metrics, run_id)
    update_run_log(run_id, overall_metrics)
    print("    All results saved")

    print("\n[8] Per rule breakdown...")
    for rm in rule_metrics:
        print(
            f"    - {rm['rule_id']} | {rm['title']} | "
            f"{rm['passed']}/{rm['total']} | "
            f"DR: {rm['detection_rate']}% | "
            f"FP: {rm['fp_rate']}% | "
            f"QS: {rm['quality_score']}"
        )

    print("\n" + "=" * 50)
    print("  Pipeline complete. Run dashboard to view results.")
    print("  cd dashboard && python app.py")
    print("=" * 50)

run_pipeline()