"""
Controlled Test Runner Module.
Executes predefined test suites for DonkAI benchmark targets, evaluates output assertions,
and logs telemetry EvidenceRecords with ground truth metrics.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from evidence import EvidenceRecord, AssessmentSessionLog
from risk_engine import RiskEngine


class TestRunner:
    def __init__(self, test_cases_path: str = None):
        if test_cases_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            test_cases_path = os.path.join(base_dir, "tests", "test_cases.json")
        
        with open(test_cases_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.test_cases = data.get("test_cases", [])

    def run_assessment_suite(
        self,
        target_name: str,
        questionnaire_answers: Dict[str, str],
        applicability_list: List[Dict[str, Any]],
        framework_versions: Dict[str, str]
    ) -> AssessmentSessionLog:
        """
        Executes predefined tests, evaluates evidence, computes deterministic risk scores,
        and records structured EvidenceRecords in an AssessmentSessionLog.
        """
        session_log = AssessmentSessionLog(
            session_id=f"SESS-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            target_name=target_name,
            assessment_type="Predefined DonkAI Benchmark Suite"
        )

        # Index applicability by OWASP ID
        app_map = {app["owasp"]["id"].split(":")[0]: app for app in applicability_list}

        for test in self.test_cases:
            owasp_code = test.get("expected_owasp", "LLM01")
            app_info = app_map.get(owasp_code, {
                "is_applicable": True,
                "owasp": {"id": f"{owasp_code}:2025", "name": "General Risk"},
                "atlas": {"id": test.get("expected_atlas", "AML.T0051"), "name": "General Technique"}
            })

            # Execute predefined test assertion against simulated/mock response
            raw_response = test.get("simulated_target_response", "")
            assertion = test.get("assertion", {})

            assertion_passed = False
            if assertion.get("type") == "contains_keyword":
                keywords = assertion.get("keywords", [])
                assertion_passed = any(kw.lower() in raw_response.lower() for kw in keywords)

            # Vulnerable if assertion detected leaked secret / injection breach
            actual_vulnerable = assertion_passed

            # Evaluate deterministic risk score
            risk_eval = RiskEngine.calculate_risk(
                answers=questionnaire_answers,
                is_applicable=app_info["is_applicable"],
                empirical_vulnerable=actual_vulnerable,
                owasp_code=owasp_code
            )

            record = EvidenceRecord(
                target_name=target_name,
                test_id=test["test_id"],
                test_name=test["name"],
                timestamp=datetime.now(timezone.utc).isoformat(),
                questionnaire_answers=questionnaire_answers,
                owasp_mapping=app_info["owasp"],
                atlas_mapping=app_info["atlas"],
                expected_vulnerable=test.get("expected_vulnerable", True),
                expected_applicable=test.get("expected_applicable", True),
                actual_applicable=app_info["is_applicable"],
                actual_vulnerable=actual_vulnerable,
                test_prompt=test.get("test_vector_prompt", ""),
                raw_response=raw_response,
                assertion_passed=assertion_passed,
                likelihood_score=risk_eval["likelihood"],
                impact_score=risk_eval["impact"],
                exposure_score=risk_eval["exposure"],
                computed_risk_score=risk_eval["risk_score"],
                severity_rating=risk_eval["severity_rating"],
                framework_versions=framework_versions,
                notes=f"{test.get('known_vulnerability', '')} - {risk_eval['finding_status']}"
            )

            session_log.add_record(record)

        return session_log
