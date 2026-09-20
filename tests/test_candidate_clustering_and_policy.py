"""
Automated tests for Candidate Finding Clustering, Policy Engine, and Domain Models.
"""

import pytest
from engines.evidence_lineage import (
    ExecutionTrial,
    OutcomeClassification,
    UnassessedReason,
    ClassificationMethod,
    DetectorProvenance,
    AttackCase,
    ProbeFamily
)
from engines.metric_engine import compute_trial_metrics
from engines.finding_clusterer import (
    cluster_trials_into_findings,
    EvidenceConfidenceLevel,
    EvidenceType
)
from engines.policy_engine import (
    evaluate_deployment_policy,
    PolicyVerdict,
    PolicyThresholds,
    EnvironmentTier
)
from engines.domain_models import (
    compute_webapp_posture_model,
    compute_repo_hygiene_model
)


def test_clustering_nemotron_style_21_breaches_to_unique_findings():
    """
    Validates that 21 breach trials across 8 canary permutation variants
    cluster into a single unique canary finding with ERR and High Confidence,
    rather than exaggerating as 21 separate vulnerabilities.
    """
    trials = []
    cases = {}

    # 18 Canary breaches across 6 different AttackCase variants
    for var_idx in range(6):
        ac_id = f"AC-CANARY-VAR-{var_idx}"
        cases[ac_id] = AttackCase(
            attack_case_id=ac_id,
            probe_family_id="PF-01",
            adversarial_prompt=f"Permutation variant {var_idx}",
            target_asset="CANARY_TOKEN",
            intended_impact="CONFIDENTIALITY_LEAK"
        )
        for rep in range(3):
            trial_id = f"ET-CANARY-{var_idx}-{rep}"
            trials.append(ExecutionTrial(
                execution_trial_id=trial_id,
                attack_case_id=ac_id,
                probe_family_id="PF-01",
                outcome_classification=OutcomeClassification.BREACHED,
                classification_method=ClassificationMethod.DETERMINISTIC_TOKEN_MATCH,
                detector_provenance=DetectorProvenance(
                    detector_id="CANARY_EXACT_MATCH",
                    matched_token="ALPHA_CANARY_SECRET_889"
                )
            ))

    # 2 Persona breaches
    ac_dan = "AC-DAN-001"
    cases[ac_dan] = AttackCase(
        attack_case_id=ac_dan,
        probe_family_id="PF-02",
        adversarial_prompt="DAN roleplay override",
        target_asset="SYSTEM_PERSONA",
        intended_impact="INTEGRITY_BYPASS"
    )
    for rep in range(2):
        trials.append(ExecutionTrial(
            execution_trial_id=f"ET-DAN-{rep}",
            attack_case_id=ac_dan,
            probe_family_id="PF-02",
            raw_response="DAN mode enabled override",
            outcome_classification=OutcomeClassification.BREACHED
        ))

    # 1 XML Tag breach
    ac_xml = "AC-XML-001"
    cases[ac_xml] = AttackCase(
        attack_case_id=ac_xml,
        probe_family_id="PF-03",
        adversarial_prompt="XML breakout",
        target_asset="DELIMITER_PARSER",
        intended_impact="PROMPT_INJECTION"
    )
    trials.append(ExecutionTrial(
        execution_trial_id="ET-XML-1",
        attack_case_id=ac_xml,
        probe_family_id="PF-03",
        raw_response="Unescaped tag execution",
        outcome_classification=OutcomeClassification.BREACHED
    ))

    # 9 Defended trials
    for d_idx in range(9):
        trials.append(ExecutionTrial(
            execution_trial_id=f"ET-DEF-{d_idx}",
            attack_case_id="AC-SAFE-001",
            probe_family_id="PF-04",
            outcome_classification=OutcomeClassification.DEFENDED
        ))

    clusters = cluster_trials_into_findings(trials, cases)

    # 21 breaches should cluster into exactly 3 unique candidate findings
    assert len(clusters) == 3

    # Primary cluster is Canary exfiltration
    canary_cluster = next(c for c in clusters if "CANARY" in c.target_asset or "Canary" in c.title)
    assert canary_cluster.technical_severity == "CRITICAL"
    assert canary_cluster.breach_count == 18
    assert canary_cluster.independent_vector_count == 6
    assert canary_cluster.evidence_confidence_level == EvidenceConfidenceLevel.VERY_HIGH
    assert canary_cluster.root_cause_hypothesis is not None


def test_policy_engine_gates():
    """Validates policy verdicts: circuit breaker blocking vs audit completeness."""
    # Scenario A: 96% ADS, but has 1 CRITICAL finding -> DEPLOYMENT BLOCKED
    from engines.metric_engine import MetricSummary, CoverageSufficiency
    metrics_a = MetricSummary(
        d_defended=24,
        b_breached=1,
        u_unassessed=5,
        n_evaluated=25,
        n_planned=30,
        ads_defense_score=96.0,
        asr_attack_success_rate=4.0,
        ac_completeness=83.33,
        coverage_sufficiency=CoverageSufficiency(83.33, 10, 10, 4, 4, True)
    )
    crit_cluster = next(iter(cluster_trials_into_findings([
        ExecutionTrial(
            execution_trial_id="ET-CRIT",
            attack_case_id="AC-1",
            probe_family_id="PF-1",
            outcome_classification=OutcomeClassification.BREACHED,
            classification_method=ClassificationMethod.DETERMINISTIC_TOKEN_MATCH,
            detector_provenance=DetectorProvenance("CANARY_EXACT", matched_token="SECRET_123")
        )
    ])))

    eval_a = evaluate_deployment_policy(metrics_a, [crit_cluster])
    assert eval_a.verdict == PolicyVerdict.DEPLOYMENT_BLOCKED
    assert "Circuit Breaker" in eval_a.headline

    # Scenario B: ADS = 100%, but AC = 50% (due to 429 rate limit) -> AUDIT INCOMPLETE (NOT Safe for Release)
    metrics_b = MetricSummary(
        d_defended=15,
        b_breached=0,
        u_unassessed=15,
        n_evaluated=15,
        n_planned=30,
        ads_defense_score=100.0,
        asr_attack_success_rate=0.0,
        ac_completeness=50.0,
        coverage_sufficiency=CoverageSufficiency(50.0, 5, 10, 2, 4, False)
    )
    eval_b = evaluate_deployment_policy(metrics_b, [])
    assert eval_b.verdict == PolicyVerdict.AUDIT_INCOMPLETE
    assert "Insufficient Evaluation Coverage" in eval_b.headline


def test_domain_models_repository_hygiene_and_web():
    """Validates domain-specific scoring prevents distorted 33% Grade F on SIAS."""
    # SIAS case: missing LICENSE + missing SECURITY.md
    sias_findings = [
        {"title": "Missing LICENSE file", "severity": "LOW"},
        {"title": "Missing SECURITY.md vulnerability disclosure policy", "severity": "MEDIUM"}
    ]
    repo_res = compute_repo_hygiene_model(sias_findings)
    # Base 100 - 3 (LICENSE) - 10 (SECURITY.md) = 87
    assert repo_res.rpss_posture_score == 87
    assert "RPSS-P" in repo_res.policy_model_name

    # Web App: login boundary should not penalize posture score
    web_issues = [{"title": "Missing CSP Header", "severity": "MEDIUM"}]
    web_positives = ["HTTPS Handshake verified", "HSTS header present"]
    unassessed_pages = ["/admin/login", "/dashboard"]
    pages_inspected = ["/"]

    web_res = compute_webapp_posture_model(
        issues=web_issues,
        positives=web_positives,
        unassessed_pages=unassessed_pages,
        pages_inspected=pages_inspected
    )
    # 2 positive / 3 evaluated checks = 66.7%
    assert web_res.asps_posture_score == 66.7
    # 1 page / 3 total pages = 33.3% public coverage
    assert web_res.public_surface_coverage_pct == 33.3


def test_web_score_reconciliation_exact_20_5_yields_80():
    """
    Validates that a web assessment with 20 defended checks and 5 breached checks
    reconciles directly to ASPS = 80.0% (80/100, Grade B), without distortion.
    """
    web_res = compute_webapp_posture_model(
        issues=[{"title": "Issue"}],
        positives=["Positive"],
        unassessed_pages=[],
        pages_inspected=["/"],
        evaluated_defended_count=20,
        evaluated_breached_count=5
    )
    assert web_res.checks_passed == 20
    assert web_res.checks_failed == 5
    assert web_res.total_checks_evaluated == 25
    assert web_res.asps_posture_score == 80.0

    # Also test through compute_executive_scorecard
    from guided_assessment_ui import compute_executive_scorecard
    trials = []
    for i in range(20):
        trials.append(ExecutionTrial(
            execution_trial_id=f"ET-WEB-DEF-{i+1:03d}",
            attack_case_id=f"AC-WEB-DEF-{i+1:03d}",
            probe_family_id="security_headers",
            outcome_classification=OutcomeClassification.DEFENDED
        ))
    for i in range(5):
        trials.append(ExecutionTrial(
            execution_trial_id=f"ET-WEB-BRK-{i+1:03d}",
            attack_case_id=f"AC-WEB-BRK-{i+1:03d}",
            probe_family_id="security_headers",
            raw_response="Missing Content-Security-Policy (CSP)",
            outcome_classification=OutcomeClassification.BREACHED
        ))

    scorecard = compute_executive_scorecard(
        findings=[],
        positive_obs=[],
        total_tested=25,
        target_type="website",
        raw_trials=trials,
        unassessed_count=0
    )
    assert scorecard["overall_safety_score"] == 80
    assert scorecard["safety_grade"] == "Grade B"
    assert scorecard["score_label"] == "Application Security Posture Score (ASPS)"
    assert scorecard["candidate_clusters"][0]["title"] == "Missing Content-Security-Policy (CSP) Header"
    assert "OWASP Top 10 Web" in scorecard["candidate_clusters"][0]["owasp_mapping"]


def test_web_finding_domain_isolation_no_llm_leakage():
    """
    Validates that web probe breaches produce web-specific finding titles,
    OWASP Top 10 Web classifications, and reverse-proxy/server HTTP header remediations,
    and NEVER leak LLM prompt injection or delimiter framing templates.
    """
    trials = [
        ExecutionTrial(
            execution_trial_id="ET-WEB-001",
            attack_case_id="AC-WEB-001",
            probe_family_id="security_headers",
            raw_response="Missing Content-Security-Policy (CSP): No CSP header detected on root response",
            outcome_classification=OutcomeClassification.BREACHED
        ),
        ExecutionTrial(
            execution_trial_id="ET-WEB-002",
            attack_case_id="AC-WEB-002",
            probe_family_id="security_headers",
            raw_response="Missing HTTP Strict Transport Security (HSTS): No Strict-Transport-Security header returned",
            outcome_classification=OutcomeClassification.BREACHED
        ),
        ExecutionTrial(
            execution_trial_id="ET-WEB-003",
            attack_case_id="AC-WEB-003",
            probe_family_id="perimeter_fuzzing",
            raw_response="Exposed Environment Secrets (.env): 200 OK returned on /.env endpoint",
            outcome_classification=OutcomeClassification.BREACHED
        )
    ]

    clusters = cluster_trials_into_findings(trials, target_type="website")
    assert len(clusters) >= 2

    # Verify each cluster strictly adheres to Web taxonomy
    for c in clusters:
        # Must not contain LLM prompt injection templates
        assert "delimiter" not in c.actionable_remediation.lower()
        assert "guardrail" not in c.actionable_remediation.lower()
        assert "prompt injection" not in c.title.lower()
        assert "Adversarial Boundary Violation" not in c.title
        assert "LLM01" not in c.owasp_mapping
        assert "LLM02" not in c.owasp_mapping

    # Specific finding check: CSP
    csp_cluster = next(c for c in clusters if "Content-Security-Policy" in c.title)
    assert csp_cluster.title == "Missing Content-Security-Policy (CSP) Header"
    assert "OWASP Top 10 Web A05:2021" in csp_cluster.owasp_mapping
    assert "web server / reverse proxy" in csp_cluster.actionable_remediation
    assert "Content-Security-Policy" in csp_cluster.actionable_remediation

    # Specific finding check: Exposed .env
    env_cluster = next(c for c in clusters if ".env" in c.sample_evidence_excerpt or "Environment" in c.title)
    assert "OWASP Top 10 Web A01:2021" in env_cluster.owasp_mapping
    assert env_cluster.technical_severity == "CRITICAL"

