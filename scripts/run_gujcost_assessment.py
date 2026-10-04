"""
Script to execute live audit against https://gujcost.gujarat.gov.in/Index,
generate PDF and HTML reports, and verify all 6 locked criteria.
"""

import sys
import os
import json
import logging

logging.basicConfig(level=logging.INFO)

# Ensure workspace is in path
sys.path.insert(0, os.path.abspath("."))

from guided_assessment_ui import run_staged_website_audit
from engines.report_exporter import export_assessment_pdf_and_html
from engines.assessment_store import AssessmentStore

class MockContainer:
    def info(self, msg):
        print(f"[INFO] {msg}")
    def warning(self, msg):
        print(f"[WARN] {msg}")
    def success(self, msg):
        print(f"[SUCCESS] {msg}")
    def markdown(self, *args, **kwargs):
        pass
    def empty(self):
        return self
    def container(self):
        return self
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    def columns(self, *args, **kwargs):
        class Col:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def markdown(self, *args, **kwargs): pass
            def metric(self, *args, **kwargs): pass
        return [Col(), Col(), Col(), Col()]
    def metric(self, *args, **kwargs):
        pass

def main():
    target_url = "https://gujcost.gujarat.gov.in/Index"
    print(f"=== Starting live audit for {target_url} ===")

    inp = {
        "target_type": "website",
        "url": target_url,
        "scan_profile": "owasp_core"
    }

    journey_mock = MockContainer()
    status_mock = MockContainer()

    record = run_staged_website_audit(
        inp,
        journey_container=journey_mock,
        status_container=status_mock,
        stop_checker=lambda: False
    )

    store = AssessmentStore()
    store.save_assessment(record)

    pdf_path, html_path = export_assessment_pdf_and_html(record)
    print(f"\nAudit complete! Assessment ID: {record['id']}")
    print(f"PDF exported to: {pdf_path}")
    print(f"HTML exported to: {html_path}")

    # Print summary metrics for validation
    print("\n--- Summary Verification ---")
    print(f"Launch Readiness Verdict: {record.get('launch_readiness', {}).get('verdict')}")
    print(f"Launch Readiness Code: {record.get('launch_readiness', {}).get('code')}")
    print(f"Launch Readiness Explanation: {record.get('launch_readiness', {}).get('explanation')}")
    print(f"Overall Safety Score: {record.get('overall_safety_score')} ({record.get('safety_grade')})")
    print(f"Score Label: {record.get('score_label')}")
    print(f"Breach Events Count: {record.get('breach_events_count')}")
    print(f"Deficiency Events Count: {record.get('deficiency_events_count')}")
    print(f"Defended Events Count: {record.get('defended_events_count')}")
    print(f"Unassessed Events Count: {record.get('unassessed_events_count')}")
    print(f"Unique Findings Count: {record.get('unique_findings_count')}")
    print(f"Summary: {record.get('summary')}")

    print("\n--- Findings List ---")
    for idx, f in enumerate(record.get("findings", []), 1):
        print(f"Finding #{idx}: {f.get('title', f.get('issue'))} | Sev: {f.get('severity')} | Cat: {f.get('category')} | Framework: {f.get('framework')}")

    print("\n--- Positive Observations ---")
    for idx, p in enumerate(record.get("positive_observations", []), 1):
        print(f"Pos #{idx}: [{p.get('area')}] {p.get('observation')} | Evid: {p.get('evidence')[:80]}")

    print("\n--- Execution Trials Outcome Distribution ---")
    trials = record.get("execution_trials", [])
    outcome_counts = {}
    for t in trials:
        oc = t.get("outcome_classification")
        outcome_counts[oc] = outcome_counts.get(oc, 0) + 1
    for oc, cnt in sorted(outcome_counts.items()):
        print(f"  {oc}: {cnt}")

    return record, pdf_path, html_path

if __name__ == "__main__":
    main()
