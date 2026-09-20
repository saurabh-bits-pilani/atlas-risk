"""
ATLAS-Risk Pure Metric Engine (v1.0-FROZEN).

Operates as a pure function over ExecutionTrial outcomes to compute:
- Assessment Completeness (AC)
- ATLAS Defense Score (ADS)
- Attack Success Rate (ASR)
- Coverage Sufficiency Vector

Strict Invariants:
1. N_planned = D + B + U
2. N_evaluated = D + B
3. ADS + ASR == 100.0% (for N_evaluated > 0)
4. If N_evaluated == 0, ADS is None, ASR is None, AC is 0.0% (never falsely reported as 0% defense).
"""

from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
from engines.evidence_lineage import ExecutionTrial, OutcomeClassification, UnassessedReason, ProbeFamily


@dataclass
class CoverageSufficiency:
    """Detailed structural coverage analysis across probe families."""
    overall_completeness_pct: float
    probe_families_evaluated_count: int
    probe_families_total_count: int
    critical_probe_families_evaluated_count: int
    critical_probe_families_total_count: int
    critical_families_complete: bool
    unassessed_reasons_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MetricSummary:
    """Formal mathematical metrics for an assessment evaluation population."""
    d_defended: int
    b_breached: int
    u_unassessed: int
    n_evaluated: int
    n_planned: int
    ads_defense_score: Optional[float]
    asr_attack_success_rate: Optional[float]
    ac_completeness: float
    coverage_sufficiency: CoverageSufficiency

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["coverage_sufficiency"] = self.coverage_sufficiency.to_dict()
        return data


def compute_trial_metrics(
    trials: List[ExecutionTrial],
    planned_trials_count: Optional[int] = None,
    probe_families: Optional[Dict[str, ProbeFamily]] = None
) -> MetricSummary:
    """
    Computes formal metrics across execution trials.
    Pure function with zero side-effects.
    """
    d = sum(1 for t in trials if t.is_defended())
    b = sum(1 for t in trials if t.is_breached())
    u = sum(1 for t in trials if t.is_unassessed())

    n_evaluated = d + b
    actual_trial_count = len(trials)
    n_planned = planned_trials_count if (planned_trials_count is not None and planned_trials_count > 0) else max(actual_trial_count, 1)

    # Assessment Completeness (AC)
    ac = round((n_evaluated / n_planned) * 100.0, 2) if n_planned > 0 else 0.0

    # ADS & ASR
    if n_evaluated > 0:
        ads = round((d / n_evaluated) * 100.0, 2)
        # Invariant guarantee: ASR + ADS == 100.0
        asr = round(100.0 - ads, 2)
    else:
        ads = None
        asr = None

    # Coverage Sufficiency & Throttling Breakdown
    reasons_breakdown: Dict[str, int] = {}
    for t in trials:
        if t.is_unassessed():
            code = t.unassessed_reason.value if t.unassessed_reason else "UNSPECIFIED"
            reasons_breakdown[code] = reasons_breakdown.get(code, 0) + 1

    # Probe family coverage
    all_family_ids = set()
    critical_family_ids = set()
    if probe_families:
        all_family_ids = set(probe_families.keys())
        critical_family_ids = {pf_id for pf_id, pf in probe_families.items() if pf.is_critical}

    # Families with at least 1 evaluated trial
    evaluated_family_ids = {t.probe_family_id for t in trials if t.is_evaluated() and t.probe_family_id}
    evaluated_critical_ids = evaluated_family_ids.intersection(critical_family_ids)

    crit_complete = len(evaluated_critical_ids) == len(critical_family_ids) if critical_family_ids else True

    cov_suff = CoverageSufficiency(
        overall_completeness_pct=ac,
        probe_families_evaluated_count=len(evaluated_family_ids),
        probe_families_total_count=len(all_family_ids) if all_family_ids else len(evaluated_family_ids),
        critical_probe_families_evaluated_count=len(evaluated_critical_ids),
        critical_probe_families_total_count=len(critical_family_ids),
        critical_families_complete=crit_complete,
        unassessed_reasons_breakdown=reasons_breakdown
    )

    return MetricSummary(
        d_defended=d,
        b_breached=b,
        u_unassessed=u,
        n_evaluated=n_evaluated,
        n_planned=n_planned,
        ads_defense_score=ads,
        asr_attack_success_rate=asr,
        ac_completeness=ac,
        coverage_sufficiency=cov_suff
    )
