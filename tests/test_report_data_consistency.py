import os
import re
import pytest
from engines.report_exporter import export_assessment_pdf_and_html, generate_html_report, _synthesize_category_scores
from engines.evidence_lineage import (
    ExecutionTrial,
    OutcomeClassification,
    UnassessedReason,
    
)


def test_universal_invariant_and_table_reconciliation_live():
    """Verify that category breakdown column sums strictly match top cards in live audit scenario."""
    cat_scores = {
        "repo_governance": {
            "id": "repo_governance",
            "name": "Repository Governance",
            "icon": "🐙",
            "total_planned": 5,
            "tested": 5,
            "passed": 5,
            "defended": 5,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 0,
            "pass_rate": 100.0,
            "status": "PASS"
        },
        "disclosure_policy": {
            "id": "disclosure_policy",
            "name": "Security & Advisory Policy",
            "icon": "🛡️",
            "total_planned": 5,
            "tested": 5,
            "passed": 4,
            "defended": 4,
            "failed": 1,
            "vulnerable": 1,
            "unassessed": 0,
            "pass_rate": 80.0,
            "status": "FAIL"
        },
        "secret_hygiene": {
            "id": "secret_hygiene",
            "name": "Secret & Canary Hygiene",
            "icon": "🔐",
            "total_planned": 5,
            "tested": 5,
            "passed": 4,
            "defended": 4,
            "failed": 1,
            "vulnerable": 1,
            "unassessed": 0,
            "pass_rate": 80.0,
            "status": "FAIL"
        },
        "prompt_defense": {
            "id": "prompt_defense",
            "name": "Prompt Delimiter Fencing",
            "icon": "💉",
            "total_planned": 5,
            "tested": 5,
            "passed": 5,
            "defended": 5,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 0,
            "pass_rate": 100.0,
            "status": "PASS"
        },
        "dependency_posture": {
            "id": "dependency_posture",
            "name": "Supply Chain & Lockfiles",
            "icon": "📦",
            "total_planned": 5,
            "tested": 5,
            "passed": 5,
            "defended": 5,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 0,
            "pass_rate": 100.0,
            "status": "PASS"
        }
    }

    record = {
        "id": "ASM-TEST-HUME-01",
        "name": "GitHub Review: HumeAI/hume-ai",
        "target_type": "github",
        "target_input": "https://github.com/HumeAI/hume-ai",
        "scan_profile": "full_atlas_depth",
        "audit_profile_name": "Full MITRE ATLAS Depth Audit",
        "audit_profile_tier": "Enterprise Rigor",
        "overall_safety_score": 92,
        "score_label": "Repository Posture Score (RPSS-P)",
        "safety_grade": "Grade A",
        "max_severity_found": "MEDIUM",
        "circuit_breaker_triggered": False,
        "launch_readiness": {
            "code": "APPROVED",
            "verdict": "SAFE FOR GUARDRAILED PILOT",
            "explanation": "Verified defenses across key repositories."
        },
        "attack_success_rate": 0.08,
        "assessment_completeness": 100.0,
        "category_scores": cat_scores,
        "total_prompts_tested": 25,
        "total_prompts_planned": 25,
        "execution_duration_sec": 6.2,
        "status": "COMPLETE",
        "summary": "Completed 25 checks.",
        "counts": {
            "unique_findings": 1,
            "issues": 1,
            "total_breaches": 2,
            "defended_trials": 23,
            "no_issue": 23,
            "unassessed": 0,
            "not_completed": 0,
            "evaluated_trials": 25,
            "total_prompts_tested": 25,
            "total_prompts_planned": 25,
            "not_applicable": 0
        },
        "unique_findings_count": 1,
        "breach_events_count": 2,
        "defended_events_count": 23,
        "unassessed_events_count": 0,
        "findings": [
            {
                "title": "Advisory / Disclosure Policy Inconsistency",
                "severity": "MEDIUM",
                "observed": "Security.md and Canary tokens flagged.",
                "domain": "Security Policy"
            }
        ],
        "positive_observations": [
            {"aspect": "Repo Governance", "observation": "Protected branches"}
        ],
        "unassessed_areas": []
    }

    html_content = generate_html_report(record)

    assert ">23</div>\n        <div class=\"count-lbl\">Defended Trials (D)</div>" in html_content
    assert ">0</div>\n        <div class=\"count-lbl\">Unassessed / Throttled (U)</div>" in html_content
    assert ">1</div>\n        <div class=\"count-lbl\">Unique Findings (M)</div>" in html_content
    assert "(2 Breaches)" in html_content

    assert "Evaluated" in html_content
    assert "Defended" in html_content
    assert "Breached" in html_content
    assert "Unassessed" in html_content

    pdf_path, html_path = export_assessment_pdf_and_html(record)
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000
    assert os.path.exists(html_path)
    assert os.path.getsize(html_path) > 1000


def test_unassessed_scenario_consistency():
    """Verify that when API is unreachable or requires authentication, N = D + B + U holds with U > 0."""
    cat_scores = {
        "repo_governance": {
            "id": "repo_governance",
            "name": "Repository Governance",
            "icon": "🐙",
            "total_planned": 5,
            "tested": 1,
            "passed": 0,
            "defended": 0,
            "failed": 1,
            "vulnerable": 1,
            "unassessed": 4,
            "pass_rate": 0.0,
            "status": "FAIL"
        },
        "disclosure_policy": {
            "id": "disclosure_policy",
            "name": "Security & Advisory Policy",
            "icon": "🛡️",
            "total_planned": 5,
            "tested": 0,
            "passed": 0,
            "defended": 0,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 5,
            "pass_rate": None,
            "status": "UNASSESSED"
        },
        "secret_hygiene": {
            "id": "secret_hygiene",
            "name": "Secret & Canary Hygiene",
            "icon": "🔐",
            "total_planned": 5,
            "tested": 0,
            "passed": 0,
            "defended": 0,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 5,
            "pass_rate": None,
            "status": "UNASSESSED"
        },
        "prompt_defense": {
            "id": "prompt_defense",
            "name": "Prompt Delimiter Fencing",
            "icon": "💉",
            "total_planned": 5,
            "tested": 0,
            "passed": 0,
            "defended": 0,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 5,
            "pass_rate": None,
            "status": "UNASSESSED"
        },
        "dependency_posture": {
            "id": "dependency_posture",
            "name": "Supply Chain & Lockfiles",
            "icon": "📦",
            "total_planned": 5,
            "tested": 0,
            "passed": 0,
            "defended": 0,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 5,
            "pass_rate": None,
            "status": "UNASSESSED"
        }
    }

    record = {
        "id": "ASM-TEST-UNASSESSED-02",
        "name": "GitHub Review: Private/internal-repo",
        "target_type": "github",
        "target_input": "https://github.com/Private/internal-repo",
        "scan_profile": "full_atlas_depth",
        "overall_safety_score": 0,
        "score_label": "Repository Posture Score (RPSS-P)",
        "safety_grade": "Grade F",
        "max_severity_found": "HIGH",
        "circuit_breaker_triggered": False,
        "launch_readiness": {
            "code": "ACTION_REQUIRED",
            "verdict": "ACTION REQUIRED (Unauthenticated Scope)",
            "explanation": "Authenticated probe failed; remaining checks unassessed."
        },
        "attack_success_rate": 1.0,
        "assessment_completeness": 4.0,
        "category_scores": cat_scores,
        "total_prompts_tested": 1,
        "total_prompts_planned": 25,
        "execution_duration_sec": 1.5,
        "status": "PARTIAL",
        "summary": "1 check evaluated, 24 unassessed.",
        "counts": {
            "unique_findings": 1,
            "issues": 1,
            "total_breaches": 1,
            "defended_trials": 0,
            "no_issue": 0,
            "unassessed": 24,
            "not_completed": 24,
            "evaluated_trials": 1,
            "total_prompts_tested": 1,
            "total_prompts_planned": 25,
            "not_applicable": 0
        },
        "unique_findings_count": 1,
        "breach_events_count": 1,
        "defended_events_count": 0,
        "unassessed_events_count": 24,
        "findings": [{"title": "Repo Unreachable", "severity": "HIGH", "domain": "Repository Governance"}],
        "positive_observations": [],
        "unassessed_areas": ["24 checks require authentication token"]
    }

    html_content = generate_html_report(record)

    assert ">0</div>\n        <div class=\"count-lbl\">Defended Trials (D)</div>" in html_content
    assert ">24</div>\n        <div class=\"count-lbl\">Unassessed / Throttled (U)</div>" in html_content
    assert ">1</div>\n        <div class=\"count-lbl\">Unique Findings (M)</div>" in html_content
    assert "(1 Breaches)" in html_content

    pdf_path, _ = export_assessment_pdf_and_html(record)
    assert os.path.exists(pdf_path)


def test_synthesize_category_scores_preserves_sums():
    """Verify that even when synthesizing category scores from raw totals, no trials are lost to integer division."""
    record = {
        "target_type": "openrouter",
        "breach_events_count": 7,
        "defended_events_count": 23,
        "unassessed_events_count": 4,
        "counts": {
            "total_breaches": 7,
            "defended_trials": 23,
            "unassessed": 4
        }
    }
    findings = [{"domain": "direct_jailbreak", "title": f"F{i}"} for i in range(7)]
    positives = [f"P{i}" for i in range(23)]

    cats = _synthesize_category_scores(record, findings, positives)
    assert len(cats) == 5

    sum_def = sum(c["defended"] for c in cats.values())
    sum_vuln = sum(c["vulnerable"] for c in cats.values())
    sum_unass = sum(c["unassessed"] for c in cats.values())

    assert sum_def == 23, f"Expected 23 defended, got {sum_def}"
    assert sum_vuln == 7, f"Expected 7 breached, got {sum_vuln}"
    assert sum_unass == 4, f"Expected 4 unassessed, got {sum_unass}"
    assert sum_def + sum_vuln + sum_unass == 34, "Total planned invariant preserved"


def test_unreachable_target_zero_breaches_and_na_defense_rates():
    """Verify that connection failure produces 0 breaches, 0 findings, N/A score, and N/A defense rates."""
    cat_scores = {
        f"cat_{i}": {
            "id": f"cat_{i}",
            "name": f"Category {i}",
            "icon": "🛡️",
            "total_planned": 5,
            "tested": 0,
            "passed": 0,
            "defended": 0,
            "failed": 0,
            "vulnerable": 0,
            "unassessed": 5,
            "pass_rate": None,
            "status": "UNASSESSED"
        }
        for i in range(1, 6)
    }

    record = {
        "id": "ASM-TEST-HUME-UNREACHABLE",
        "name": "Web App Audit: https://www.hume.ai/",
        "target_type": "website",
        "target_input": "https://www.hume.ai/",
        "scan_profile": "quick",
        "overall_safety_score": None,
        "score_label": "Application Security Posture Score (ASPS)",
        "safety_grade": "UNRATED",
        "max_severity_found": "NONE",
        "circuit_breaker_triggered": False,
        "launch_readiness": {
            "code": "UNRATED",
            "verdict": "AUDIT INCOMPLETE (Target Unreachable / Unassessed)",
            "explanation": "Target could not be reached or zero security checks were evaluated."
        },
        "attack_success_rate": None,
        "assessment_completeness": 0.0,
        "category_scores": cat_scores,
        "total_prompts_tested": 0,
        "total_prompts_planned": 25,
        "execution_duration_sec": 0.5,
        "status": "FAILED_CONNECTIVITY",
        "summary": "Target endpoint could not be reached. 25 checks unassessed.",
        "counts": {
            "unique_findings": 0,
            "issues": 0,
            "total_breaches": 0,
            "defended_trials": 0,
            "no_issue": 0,
            "unassessed": 25,
            "not_completed": 25,
            "evaluated_trials": 0,
            "total_prompts_tested": 0,
            "total_prompts_planned": 25,
            "not_applicable": 0
        },
        "unique_findings_count": 0,
        "breach_events_count": 0,
        "defended_events_count": 0,
        "unassessed_events_count": 25,
        "findings": [],
        "positive_observations": [],
        "candidate_clusters": [],
        "unassessed_areas": ["Connection failed to https://www.hume.ai/"]
    }

    html_content = generate_html_report(record)

    # Invariants verification
    assert ">0</div>\n        <div class=\"count-lbl\">Defended Trials (D)</div>" in html_content
    assert "(0 Breaches)" in html_content
    assert ">0</div>\n        <div class=\"count-lbl\">Unique Findings (M)</div>" in html_content
    assert ">25</div>\n        <div class=\"count-lbl\">Unassessed / Throttled (U)</div>" in html_content
    assert "N/A" in html_content  # Defense rate column displays N/A
    assert "UNRATED" in html_content
    assert "AUDIT INCOMPLETE" in html_content

    pdf_path, _ = export_assessment_pdf_and_html(record)
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000

