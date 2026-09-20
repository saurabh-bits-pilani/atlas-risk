import os
import pytest
from engines.report_exporter import export_assessment_pdf_and_html

TARGET_TYPES = ["website", "github", "questionnaire", "chatbot", "local_model", "openrouter"]

@pytest.mark.parametrize("t_type", TARGET_TYPES)
def test_universal_report_export(t_type):
    record = {
        "id": f"TEST-{t_type.upper()}-001",
        "name": f"Test Audit: {t_type}",
        "target_type": t_type,
        "target_input": f"https://example.com/{t_type}" if t_type in ["website", "github"] else f"model-{t_type}",
        "scan_profile": "owasp_core",
        "audit_profile_name": f"Standard {t_type.title()} Audit",
        "audit_profile_tier": "Full Adversarial Audit",
        "overall_safety_score": 75,
        "safety_grade": "C",
        "max_severity_found": "HIGH",
        "circuit_breaker_triggered": False,
        "launch_readiness": "CONDITIONAL_APPROVAL",
        "attack_success_rate": 0.25,
        "total_prompts_tested": 10,
        "total_prompts_planned": 10,
        "execution_duration_sec": 4.5,
        "status": "COMPLETE",
        "summary": f"Audit completed for {t_type} with 2 findings.",
        "counts": {"issues": 2, "no_issue": 8, "not_completed": 0, "not_applicable": 0},
        "findings": [
            {
                "domain": "Security Headers" if t_type == "website" else "Prompt Injection",
                "severity": "HIGH",
                "title": f"Finding 1 for {t_type}",
                "observed": "Security misconfiguration observed.",
                "why_it_matters": "Exposes attack surface.",
                "evidence": "Observed in response headers or token output.",
                "action": "Apply recommended configuration fix.",
                "how_to_verify": "Retest endpoint.",
            }
        ],
        "positive_observations": [
            "Baseline control 1 verified.",
            {"title": "Baseline control 2 verified", "domain": "General"}
        ],
        "unassessed_areas": ["Admin portal unassessed without credentials"],
        "next_steps": ["Review flagged findings", "Deploy hardening"]
    }

    pdf_path, html_path = export_assessment_pdf_and_html(record)

    assert os.path.exists(html_path)
    assert os.path.getsize(html_path) > 1000

    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000

    with open(html_path, "r", encoding="utf-8") as f:
        html_str = f.read()

    assert "Threat Category Defense Breakdown" in html_str
    assert "SAFETY SCORE" in html_str

    if t_type == "website":
        assert "OpenRouter / Cloud AI" not in html_str
        assert "Target Web Service / Domain" in html_str
    elif t_type == "github":
        assert "OpenRouter / Cloud AI" not in html_str
        assert "Repository Audited" in html_str
