"""
ATLAS-Risk Domain-Specific Posture & Scoring Models (v1.0-FROZEN).

Provides domain-separated scoring engines:
1. LLM Models: Empirical Stochastic Resilience (ADS, ASR, AC).
2. Web Applications: Application Security Posture Score (ASPS) + Public Surface Coverage.
3. Source Repositories: Repository Posture Score — Policy-Based Model (RPSS-P).

Avoids the catastrophic distortion of applying a stochastic LLM ratio to static repository governance.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple
from engines.evidence_lineage import ExecutionTrial, ProbeFamily, OutcomeClassification
from engines.metric_engine import MetricSummary, compute_trial_metrics


class CheckCategory(str, Enum):
    SECURITY = "SECURITY"
    HYGIENE = "HYGIENE"
    INFORMATIONAL = "INFORMATIONAL"
    BENIGN_CONTROL = "BENIGN_CONTROL"
    QUALITY_USABILITY = "QUALITY_USABILITY"


class TargetCapability(str, Enum):
    WEB_SURFACE = "WEB_SURFACE"
    GIT_METADATA = "GIT_METADATA"
    AI_MODEL = "AI_MODEL"


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    category: CheckCategory
    required_capabilities: Tuple[TargetCapability, ...]
    score_eligible: bool       # True ONLY for security controls and scored hygiene
    weight: float              # 1.0 (standard), 2.0 (critical controls)
    prerequisites: Tuple[str, ...] = ()
    description: str = ""


# Documented Project Scoring Rubric
# Note: Partial credit values reflect the documented project scoring rubric, not an external standard.
PROJECT_SCORING_RUBRIC = {
    # Strict Binary Controls (Weight 1.0; Defended = 1.0, Deficiency = 0.0, Breach = 0.0)
    "WEB:MISSING_CSP": {"weight": 1.0, "defended": 1.0, "partial": 0.5, "absent": 0.0},
    "WEB:MISSING_HSTS": {"weight": 1.0, "defended": 1.0, "partial": 0.5, "absent": 0.0},
    "WEB:MISSING_CONTENT_TYPE_OPTIONS": {"weight": 1.0, "defended": 1.0, "partial": 0.0, "absent": 0.0},
    "WEB:MISSING_FRAME_PROTECTION": {"weight": 1.0, "defended": 1.0, "partial": 0.5, "absent": 0.0},
    # Contextual & Cookie Controls
    "WEB:INSECURE_COOKIES": {"weight": 1.0, "defended": 1.0, "partial": 0.5, "absent": 0.0},
    "WEB:MISSING_REFERRER_POLICY": {"weight": 1.0, "defended": 1.0, "partial": 0.5, "absent": 0.0},
    "WEB:EXPOSED_ENV_SECRETS": {"weight": 2.0, "defended": 2.0, "partial": 0.0, "absent": 0.0},
    "WEB:CLEARTEXT_DATA_TRANSMISSION": {"weight": 1.5, "defended": 1.5, "partial": 0.0, "absent": 0.0},
    # GitHub Scored Controls
    "GH:SECURITY_POLICY": {"weight": 1.0, "defended": 1.0, "partial": 0.0, "absent": 0.0},
}


def compute_security_posture_score(
    evaluated_trials: List[ExecutionTrial],
    total_eligible_checks: int = 0
) -> Tuple[Optional[float], str, str, float]:
    """
    Computes Bounded Ratio-Based Automated Security Posture Score (ASPS).
    
    Formula:
      E_sec = { t in evaluated_trials if t is score_eligible and outcome in (DEFENDED, BREACHED, DEFICIENCY) }
      If |E_sec| == 0:
          ASPS = None (Status: UNRATED, Verdict: AUDIT_INCOMPLETE)
      Else:
          ASPS = (sum(earned_credit) / sum(weight)) * 100
          
    Returns:
      (score_val, grade_str, status_str, coverage_pct)
    """
    eligible_trials = [
        t for t in evaluated_trials 
        if t.outcome_classification in (OutcomeClassification.DEFENDED, OutcomeClassification.BREACHED, OutcomeClassification.DEFICIENCY)
    ]
    
    denom_count = len(eligible_trials)
    planned = max(total_eligible_checks, denom_count)
    coverage_pct = round((denom_count / planned) * 100.0, 1) if planned > 0 else 0.0
    
    if denom_count == 0:
        return None, "UNRATED", "AUDIT_INCOMPLETE", coverage_pct

    total_weight = 0.0
    total_earned = 0.0

    for t in eligible_trials:
        # Determine weight & credit from rubric or default
        pf = t.probe_family_id or ""
        rubric_entry = PROJECT_SCORING_RUBRIC.get(pf, {"weight": 1.0, "defended": 1.0, "partial": 0.0, "absent": 0.0})
        w = rubric_entry.get("weight", 1.0)
        total_weight += w

        if t.outcome_classification == OutcomeClassification.DEFENDED:
            total_earned += rubric_entry.get("defended", w)
        elif t.outcome_classification == OutcomeClassification.DEFICIENCY:
            # Check if partial condition met in raw_response / metadata
            if t.metadata.get("partial_credit", False) or "partial" in (t.raw_response or "").lower():
                total_earned += rubric_entry.get("partial", 0.0)
            else:
                total_earned += rubric_entry.get("absent", 0.0)
        elif t.outcome_classification == OutcomeClassification.BREACHED:
            total_earned += 0.0

    if total_weight <= 0:
        return None, "UNRATED", "AUDIT_INCOMPLETE", coverage_pct

    asps = round((total_earned / total_weight) * 100.0, 1)
    
    if asps >= 85.0:
        grade = "Grade A"
    elif asps >= 70.0:
        grade = "Grade B"
    elif asps >= 55.0:
        grade = "Grade C"
    elif asps >= 40.0:
        grade = "Grade D"
    else:
        grade = "Grade F"
        
    status = "EVALUATED"
    return asps, grade, status, coverage_pct


@dataclass
class LLMResilienceModelResult:
    metric_summary: MetricSummary
    score_label: str = "ATLAS Defense Score (ADS)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score_label": self.score_label,
            "ads_defense_score": self.metric_summary.ads_defense_score,
            "asr_attack_success_rate": self.metric_summary.asr_attack_success_rate,
            "ac_completeness": self.metric_summary.ac_completeness,
            "n_evaluated": self.metric_summary.n_evaluated,
            "n_planned": self.metric_summary.n_planned,
            "coverage_sufficiency": self.metric_summary.coverage_sufficiency.to_dict()
        }


@dataclass
class WebAppPostureModelResult:
    asps_posture_score: float
    public_surface_coverage_pct: float
    accessible_pages_inspected: int
    unassessed_protected_pages: int
    checks_passed: int
    checks_failed: int
    total_checks_evaluated: int
    score_label: str = "Application Security Posture Score (ASPS)"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepoHygieneModelResult:
    rpss_posture_score: int
    policy_model_name: str = "Repository Posture Score — Policy-Based Model (RPSS-P v1.0)"
    base_points: int = 100
    deductions_applied: List[Dict[str, Any]] = field(default_factory=list)
    has_critical_credential_leak: bool = False
    disclaimer: str = (
        "Notice: Scored under policy-based heuristic model RPSS-P. "
        "Weights reflect governance and supply chain policy thresholds rather than empirical exploit frequency."
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_llm_resilience_model(
    trials: List[ExecutionTrial],
    planned_trials_count: Optional[int] = None,
    probe_families: Optional[Dict[str, ProbeFamily]] = None
) -> LLMResilienceModelResult:
    """Computes pure empirical resilience metrics for LLM targets."""
    summary = compute_trial_metrics(trials, planned_trials_count, probe_families)
    return LLMResilienceModelResult(metric_summary=summary)


def compute_webapp_posture_model(
    issues: List[Dict[str, Any]],
    positives: List[Any],
    unassessed_pages: List[Any],
    pages_inspected: List[Any],
    evaluated_defended_count: Optional[int] = None,
    evaluated_breached_count: Optional[int] = None,
) -> WebAppPostureModelResult:
    """
    Computes web application posture score.
    Protected login areas affect Public Surface Coverage, NEVER penalizing the posture score.
    If evaluated_defended_count and evaluated_breached_count are provided (from execution trials),
    the posture score directly reflects those evaluated checks:
      passed = evaluated_defended_count (D)
      failed = evaluated_breached_count (B)
      total_evaluated = D + B
      ASPS = (D / (D + B)) * 100
      
      For example, 20 defended + 5 breached:
      20 / 25 * 100 = 80.0%
    """
    if evaluated_defended_count is not None and evaluated_breached_count is not None:
        passed = evaluated_defended_count
        failed = evaluated_breached_count
    else:
        passed = len(positives)
        failed = len(issues)
    total_evaluated = passed + failed

    if total_evaluated > 0:
        asps = round((passed / total_evaluated) * 100.0, 1)
    else:
        asps = None

    inspected_count = len(pages_inspected)
    unassessed_count = len(unassessed_pages)
    total_pages = max(1, inspected_count + unassessed_count)
    psc = round((inspected_count / total_pages) * 100.0, 1)

    return WebAppPostureModelResult(
        asps_posture_score=asps,
        public_surface_coverage_pct=psc,
        accessible_pages_inspected=inspected_count,
        unassessed_protected_pages=unassessed_count,
        checks_passed=passed,
        checks_failed=failed,
        total_checks_evaluated=total_evaluated
    )


def compute_repo_hygiene_model(
    findings: List[Dict[str, Any]],
    policy_weights: Optional[Dict[str, int]] = None
) -> RepoHygieneModelResult:
    """
    Computes repository governance & posture score using policy deductions.
    Prevents a missing LICENSE from falsely grading a repo as Grade F (33/100).
    """
    default_weights = {
        "INFORMATIONAL": 3,
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 25,
        "CRITICAL": 50
    }
    weights = policy_weights or default_weights

    base = 100
    deductions: List[Dict[str, Any]] = []
    has_crit = False

    for f in findings:
        title = f.get("title", "Finding")
        sev = f.get("severity", "LOW").upper()

        # Specific governance adjustments
        if "LICENSE" in title.upper():
            points = 3
            sev = "INFORMATIONAL"
        elif "SECURITY.MD" in title.upper():
            points = 10
            sev = "MEDIUM"
        else:
            points = weights.get(sev, 5)

        if sev == "CRITICAL" or "KEY" in title.upper() or "SECRET" in title.upper():
            has_crit = True

        deductions.append({
            "finding_title": title,
            "severity": sev,
            "deduction_points": points
        })

    total_deductions = sum(d["deduction_points"] for d in deductions)
    final_score = max(0, base - total_deductions)

    return RepoHygieneModelResult(
        rpss_posture_score=final_score,
        base_points=base,
        deductions_applied=deductions,
        has_critical_credential_leak=has_crit
    )
