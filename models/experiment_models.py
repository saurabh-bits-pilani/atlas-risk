"""
Research Experiment Data Models for ATLAS-Risk v0.3.0.
Physically separates ExecutionRecord (Zero ground truth) from EvaluationRecord (Ground Truth Comparison).
Preserves full LLM Reproducibility Metadata Schema.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
from typing import Dict, Any, List, Optional


@dataclass
class ExecutionRecord:
    """
    Captured during test execution by detection tools.
    STRICT REQUIREMENT: ZERO ground truth fields exist in this object.
    """
    execution_id: str
    experiment_id: str
    target_id: str
    target_name: str
    target_type: str             # 'deterministic_benchmark', 'stochastic_llm', 'rag_application', 'agentic_application'
    test_id: str
    test_case_version: str       # e.g. "1.0.0"
    assertion_version: str       # e.g. "1.0.0"
    test_name: str
    run_number: int              # Iteration index (1..N)
    timestamp: str
    prompt_input: str
    raw_response: str
    assertion_passed: bool       # True if assertion detected breach
    actual_applicable: bool      # Determined by threat mapper
    actual_vulnerable: bool      # Determined strictly from assertion_passed
    likelihood_score: float
    impact_score: float
    exposure_score: float
    computed_risk_score: float
    severity_rating: str
    scoring_method: str          # "poc_heuristic_v1"
    scoring_config_version: str  # "1.0.0"
    owasp_mapping: Dict[str, Any] # Includes category + mapping provenance
    atlas_mapping: Dict[str, Any] # Includes technique + mapping provenance
    scenario_id: str = "SCEN-A"
    retrieved_context: Optional[str] = ""  # For RAG trace
    tool_decision: Optional[str] = ""     # For Agent trace
    tool_execution_result: Optional[str] = "" # For Agent trace
    evidence_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationRecord:
    """
    Created EXCLUSIVELY by the decoupled EvaluationEngine post-execution.
    Links to execution_id and compares actual findings against hidden ground truth.
    """
    evaluation_id: str
    execution_id: str
    experiment_id: str
    scenario_id: str
    test_id: str
    test_name: str
    expected_vulnerable: bool    # Hidden Ground Truth
    expected_applicable: bool    # Hidden Ground Truth
    actual_vulnerable: bool      # From ExecutionRecord
    actual_applicable: bool      # From ExecutionRecord
    classification: str          # 'TP', 'TN', 'FP', 'FN'
    applicability_correct: bool  # True if actual_applicable == expected_applicable

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentRecord:
    experiment_id: str
    target_id: str
    target_name: str
    target_type: str
    configuration_variant: str  # "Vulnerable Baseline" vs "Hardened Safeguard"
    run_number: int
    timestamp: str
    benchmark_source: str
    framework_versions: Dict[str, str]
    scoring_method: str
    scoring_config_version: str
    repeats_per_test: int
    scenario_id: str = "SCEN-A"
    # LLM Reproducibility Metadata Schema
    llm_reproducibility: Dict[str, Any] = field(default_factory=lambda: {
        "provider": "simulated_harness",
        "model_name": "benchmark_mock_engine",
        "model_version": "v0.3.0",
        "temperature": 0.2,
        "top_p": 0.95,
        "max_tokens": 1024,
        "system_prompt_version": "1.0.0",
        "target_config_version": "1.0.0",
        "api_timestamp": datetime.now(timezone.utc).isoformat(),
        "holdout_hash": "56d82b2265c7a49b7005d08553c678bf0fa3007a90f717b9b87b83dcbefbec5c"
    })
    execution_records: List[ExecutionRecord] = field(default_factory=list)
    evaluation_records: List[EvaluationRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "scenario_id": self.scenario_id,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "target_type": self.target_type,
            "configuration_variant": self.configuration_variant,
            "run_number": self.run_number,
            "timestamp": self.timestamp,
            "benchmark_source": self.benchmark_source,
            "framework_versions": self.framework_versions,
            "scoring_method": self.scoring_method,
            "scoring_config_version": self.scoring_config_version,
            "repeats_per_test": self.repeats_per_test,
            "llm_reproducibility": self.llm_reproducibility,
            "execution_records": [e.to_dict() for e in self.execution_records],
            "evaluation_records": [e.to_dict() for e in self.evaluation_records]
        }
