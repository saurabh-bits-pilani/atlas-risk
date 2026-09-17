"""
Unit tests for core ATLAS Risk POC modules.
Tests deterministic threat mapping, evidence telemetry, risk formula, and ground truth metrics.
"""

import sys
import os
import pytest

# Ensure parent directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from questionnaire import get_default_answers
from threat_mapper import ThreatMapper
from risk_engine import RiskEngine
from test_runner import TestRunner


def test_threat_mapper_versioning_and_applicability():
    mapper = ThreatMapper()
    assert "OWASP LLM Top 10 2025" in mapper.framework_versions["owasp"]
    assert "MITRE ATLAS v4.0" in mapper.framework_versions["atlas"]

    answers = get_default_answers()
    app_list = mapper.evaluate_applicability(answers)
    
    assert len(app_list) == 4
    # All 4 families should be applicable under default high-risk answers
    for app in app_list:
        assert app["is_applicable"] is True
        assert "id" in app["owasp"]
        assert "id" in app["atlas"]


def test_deterministic_risk_engine_calculation():
    answers = get_default_answers()
    
    # Calculate risk for Prompt Injection (LLM01) with vulnerability confirmed
    res_vuln = RiskEngine.calculate_risk(
        answers=answers,
        is_applicable=True,
        empirical_vulnerable=True,
        owasp_code="LLM01"
    )
    
    assert res_vuln["risk_score"] > 0
    assert res_vuln["severity_rating"] in ["HIGH", "CRITICAL"]

    # Calculate risk when not applicable
    res_not_app = RiskEngine.calculate_risk(
        answers=answers,
        is_applicable=False,
        empirical_vulnerable=False,
        owasp_code="LLM01"
    )
    assert res_not_app["risk_score"] == 0.0
    assert res_not_app["severity_rating"] == "LOW (Not Applicable)"


def test_runner_and_ground_truth_metrics():
    mapper = ThreatMapper()
    answers = get_default_answers()
    app_list = mapper.evaluate_applicability(answers)

    runner = TestRunner()
    session_log = runner.run_assessment_suite(
        target_name="Test DonkAI Harness",
        questionnaire_answers=answers,
        applicability_list=app_list,
        framework_versions=mapper.framework_versions
    )

    assert len(session_log.evidence_records) == 5
    metrics = session_log.calculate_ground_truth_metrics()
    
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "accuracy" in metrics
    assert metrics["total_tests"] == 5
