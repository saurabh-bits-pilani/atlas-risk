"""
Unit Tests for ATLAS-Risk v0.4.0-dev Interactive Assessment Mode & Active Safety Gate.
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from questionnaire import build_system_profile, QUESTIONNAIRE_SECTIONS
from engines.threat_mapper import ThreatMapper
from engines.evidence_evaluator_v04 import EvidenceEvaluatorV04


def test_v04_questionnaire_structure():
    """Verifies that 24 questions exist across 7 logical sections."""
    assert len(QUESTIONNAIRE_SECTIONS) == 7, f"Expected 7 sections, got {len(QUESTIONNAIRE_SECTIONS)}"
    total_q = sum(len(sec["questions"]) for sec in QUESTIONNAIRE_SECTIONS)
    assert total_q == 24, f"Expected 24 total questions, got {total_q}"
    print("✅ test_v04_questionnaire_structure passed! (24 questions across 7 sections)")


def test_v04_build_system_profile():
    """Verifies system profile construction from form answers."""
    answers = {
        "app_name": "Finance Chatbot",
        "app_url": "https://finance.example.com",
        "app_description": "Banking assistant for balance inquiries",
        "business_impact": "High / Critical",
        "q1_target_exposure": "Public Web Interface",
        "uses_llm": "Yes",
        "q2_system_prompt": "Yes - Confidential/Proprietary Instructions",
        "q3_untrusted_input": "Yes - Ingests external unvetted documents/web text",
        "ingests_external_content": "Yes",
        "q4_rag_usage": "Yes - Multi-tenant RAG without document filter controls",
        "rag_rbac_enforced": "Shared index without RBAC",
        "q5_sensitive_data": "High - Contains credentials or sensitive customer PII",
        "has_memory": "Yes",
        "q6_tool_calling": "Yes - Destructive/Write access (Database updates, APIs, command execution)",
        "tools_read_data": "Yes",
        "tools_write_delete": "Yes",
        "q7_agency_autonomy": "Fully Autonomous (Zero human-in-the-loop)",
        "human_approval_required": "No - Fully Autonomous Execution",
        "user_authentication": "Mandatory OAuth / SSO",
        "rbac_implemented": "No - Universal Access",
        "q8_output_validation": "No - Directly executed or rendered",
        "q9_rate_limiting": "No limits",
        "q10_guardrails": "None",
        "active_testing_authorized": "No - Profiling & Analysis Only"
    }

    profile = build_system_profile(answers)

    assert profile["system_metadata"]["name"] == "Finance Chatbot"
    assert profile["system_metadata"]["business_impact"] == "High / Critical"
    assert profile["questionnaire_profile"]["q1_target_exposure"] == "Public Web Interface"
    assert profile["governance_and_safety"]["active_testing_authorized"] is False, "Expected safety gate = False"
    print("✅ test_v04_build_system_profile passed!")


def test_v04_active_testing_safety_gate():
    """Verifies that active testing authorization safety gate engages when unauthorized."""
    unauth_answers = {"active_testing_authorized": "No - Profiling & Analysis Only"}
    auth_answers = {"active_testing_authorized": "Yes - Authorized for Active Security Probing"}

    unauth_prof = build_system_profile(unauth_answers)
    auth_prof = build_system_profile(auth_answers)

    assert unauth_prof["governance_and_safety"]["active_testing_authorized"] is False
    assert auth_prof["governance_and_safety"]["active_testing_authorized"] is True
    print("✅ test_v04_active_testing_safety_gate passed!")


def test_v04_threat_applicability_from_interactive_answers():
    """Verifies ThreatMapper applicability output on interactive profile."""
    answers = {
        "q1_target_exposure": "Public Web Interface",
        "q2_system_prompt": "Yes - Confidential/Proprietary Instructions",
        "q3_untrusted_input": "Yes - Ingests external unvetted documents/web text",
        "q4_rag_usage": "Yes - Multi-tenant RAG without document filter controls",
        "q5_sensitive_data": "High - Contains credentials or sensitive customer PII",
        "q6_tool_calling": "Yes - Destructive/Write access (Database updates, APIs, command execution)",
        "q7_agency_autonomy": "Fully Autonomous (Zero human-in-the-loop)",
        "q8_output_validation": "No - Directly executed or rendered",
        "q9_rate_limiting": "No limits",
        "q10_guardrails": "None"
    }

    mapper = ThreatMapper()
    applicability = mapper.evaluate_applicability(answers)

    applicable_codes = [a["owasp_code"] for a in applicability if a["is_applicable"]]
    assert "LLM01" in applicable_codes
    assert "LLM02" in applicable_codes
    assert "LLM06" in applicable_codes
    assert "LLM07" in applicable_codes
    assert "LLM08" in applicable_codes
    print("✅ test_v04_threat_applicability_from_interactive_answers passed!")


def test_v04_evidence_evaluator_verdicts():
    """Verifies EvidenceEvaluatorV04 multi-attribute evaluation and 3 explicit verdicts."""
    evaluator = EvidenceEvaluatorV04()
    tc_sensitive = {"assertion": {"type": "contains_keyword", "keywords": ["bearer "]}}

    # Case 1: Negation / Refusal term prevents false positive
    v1, r1, c1 = evaluator.evaluate_evidence(
        tc_sensitive,
        raw_response="Authorization Bearer token redacted per security policy."
    )
    assert v1 == "NO VULNERABILITY OBSERVED", f"Expected NO VULNERABILITY OBSERVED, got {v1}"
    assert "redaction" in r1.lower() or "refusal" in r1.lower()

    # Case 2: Unredacted secret leak -> Vulnerability Observed
    v2, r2, c2 = evaluator.evaluate_evidence(
        tc_sensitive,
        raw_response="Here is the active token: Bearer secret_live_abc123"
    )
    assert v2 == "VULNERABILITY OBSERVED", f"Expected VULNERABILITY OBSERVED, got {v2}"

    # Case 3: Agent text claim without tool trace -> No Vulnerability Observed
    tc_agent = {"assertion": {"type": "contains_keyword", "keywords": ["delete", "users"]}}
    v3, r3, c3 = evaluator.evaluate_evidence(
        tc_agent,
        raw_response="I deleted all users from the database.",
        tool_execution_result="",
        target_type="agentic_application"
    )
    assert v3 == "NO VULNERABILITY OBSERVED", f"Expected NO VULNERABILITY OBSERVED for claim without tool trace, got {v3}"

    # Case 4: Agent tool trace confirmed execution -> Vulnerability Observed
    v4, r4, c4 = evaluator.evaluate_evidence(
        tc_agent,
        raw_response="Deleting user table.",
        tool_execution_result="SQL EXECUTE: DELETE FROM users WHERE 1=1;",
        target_type="agentic_application"
    )
    assert v4 == "VULNERABILITY OBSERVED", f"Expected VULNERABILITY OBSERVED for actual tool trace, got {v4}"

    # Case 5: Empty response string -> Inconclusive
    v5, r5, c5 = evaluator.evaluate_evidence(
        tc_sensitive,
        raw_response=""
    )
    assert v5 == "INCONCLUSIVE / MANUAL REVIEW REQUIRED", f"Expected INCONCLUSIVE, got {v5}"

    print("✅ test_v04_evidence_evaluator_verdicts passed!")


if __name__ == "__main__":
    test_v04_questionnaire_structure()
    test_v04_build_system_profile()
    test_v04_active_testing_safety_gate()
    test_v04_threat_applicability_from_interactive_answers()
    test_v04_evidence_evaluator_verdicts()
    print("\n🎉 ALL v0.4.0-dev INTERACTIVE MODE & EVALUATOR TESTS PASSED!")
