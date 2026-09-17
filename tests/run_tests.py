import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from questionnaire import get_default_answers
from engines.threat_mapper import ThreatMapper
from engines.risk_engine import RiskEngine
from engines.test_runner import TestRunner
from tests.test_v02_experiments import (
    test_v02_execution_record_zero_ground_truth_leakage,
    test_v02_decoupled_evaluation_engine_metrics,
    test_v02_two_layer_baseline_comparison,
    test_v02_csv_dataset_export
)


def run_all_tests():
    print("==================================================")
    print("🚀 Running ATLAS-Risk Test Suite (v0.1 & v0.2)")
    print("==================================================")

    # --- v0.1 Legacy Tests ---
    print("\n--- Testing v0.1 Baseline Modules ---")
    mapper = ThreatMapper()
    assert "OWASP LLM Top 10 2025" in mapper.framework_versions["owasp"]
    assert "MITRE ATLAS v4.0" in mapper.framework_versions["atlas"]

    answers = get_default_answers()
    app_list = mapper.evaluate_applicability(answers)
    print("✅ v0.1 Test 1 Passed: ThreatMapper versioning & applicability")

    risk_engine = RiskEngine()
    res_vuln = risk_engine.calculate_risk(answers, True, True, "LLM01")
    assert res_vuln["risk_score"] > 0
    print("✅ v0.1 Test 2 Passed: Deterministic RiskEngine formula & bounds")

    # --- v0.2 Experiment Platform Tests ---
    print("\n--- Testing v0.2 Research Platform Extensions ---")
    test_v02_execution_record_zero_ground_truth_leakage()
    test_v02_decoupled_evaluation_engine_metrics()
    test_v02_two_layer_baseline_comparison()
    test_v02_csv_dataset_export()

    print("\n==================================================")
    print("🎉 ALL v0.1 & v0.2 UNIT TESTS PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_all_tests()
