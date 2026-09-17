"""
Evidence Data Model for ATLAS Risk POC.
Captures research evaluation telemetry, ground truth comparisons, and taxonomy mappings.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
from typing import Dict, Any, Optional, List


@dataclass
class EvidenceRecord:
    target_name: str
    test_id: str
    test_name: str
    timestamp: str
    questionnaire_answers: Dict[str, Any]
    owasp_mapping: Dict[str, Any]       # e.g. {"id": "LLM01:2025", "name": "Prompt Injection"}
    atlas_mapping: Dict[str, Any]       # e.g. {"id": "AML.T0051", "name": "LLM Prompt Injection"}
    expected_vulnerable: bool           # Ground truth expectation
    expected_applicable: bool           # Ground truth expectation
    actual_applicable: bool             # Evaluated by rule engine
    actual_vulnerable: bool             # Evaluated by test execution
    test_prompt: str
    raw_response: str
    assertion_passed: bool              # True if assertion rule triggered detected breach
    likelihood_score: float             # 0.0 to 1.0
    impact_score: float                 # 0.0 to 1.0
    exposure_score: float               # 0.0 to 1.0
    computed_risk_score: float          # Likelihood * Impact * Exposure
    severity_rating: str                # Low, Medium, High, Critical
    framework_versions: Dict[str, str]  # e.g. {"owasp": "2025", "atlas": "v4.0"}
    notes: Optional[str] = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class AssessmentSessionLog:
    session_id: str
    target_name: str
    assessment_type: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_records: List[EvidenceRecord] = field(default_factory=list)

    def add_record(self, record: EvidenceRecord):
        self.evidence_records.append(record)

    def calculate_ground_truth_metrics(self) -> Dict[str, float]:
        """
        Calculates Precision, Recall, F1 Score, and Accuracy comparing 
        actual_vulnerable against expected_vulnerable ground truth.
        """
        tp = sum(1 for r in self.evidence_records if r.actual_vulnerable and r.expected_vulnerable)
        fp = sum(1 for r in self.evidence_records if r.actual_vulnerable and not r.expected_vulnerable)
        fn = sum(1 for r in self.evidence_records if not r.actual_vulnerable and r.expected_vulnerable)
        tn = sum(1 for r in self.evidence_records if not r.actual_vulnerable and not r.expected_vulnerable)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        total = len(self.evidence_records)
        accuracy = (tp + tn) / total if total > 0 else 1.0

        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "total_tests": total
        }
