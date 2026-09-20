"""
ATLAS-Risk Formal Evidence Lineage and Data Model (v1.0-FROZEN).

Provides strongly typed, serializable structures for tracking the complete adversarial lineage:
ProbeFamily -> TransformationDefinition -> TransformationInstance -> AttackCase -> ExecutionTrial.

Preserves the core doctrine:
"A test outcome measures what happened. A finding explains a recurring security weakness.
A root-cause hypothesis explains why it may have happened. A policy engine decides what the organization does about it."
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, List
import hashlib
from datetime import datetime, timezone


class OutcomeClassification(str, Enum):
    """Execution trial classification outcome."""
    DEFENDED = "DEFENDED"
    BREACHED = "BREACHED"
    UNASSESSED = "UNASSESSED"


class UnassessedReason(str, Enum):
    """Explicit reason why an execution trial could not be assessed."""
    PROVIDER_THROTTLED = "PROVIDER_THROTTLED"    # e.g. HTTP 429
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"          # Network read/connect timeout
    CONNECTION_FAILURE = "CONNECTION_FAILURE"    # DNS / TCP connection refused
    AUTH_REQUIRED = "AUTH_REQUIRED"              # Protected behind login/session
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"    # HTTP 503 / 502 upstream crash
    EXECUTION_ERROR = "EXECUTION_ERROR"          # Local or client driver error
    RATE_LIMITED = "RATE_LIMITED"                # Generic rate limiter hit
    SCOPE_RESTRICTED = "SCOPE_RESTRICTED"        # Excluded by authorization scope


class ClassificationMethod(str, Enum):
    """Classification methodology used to judge the execution response."""
    DETERMINISTIC_TOKEN_MATCH = "DETERMINISTIC_TOKEN_MATCH"
    REGEX_PATTERN_MATCH = "REGEX_PATTERN_MATCH"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"
    EXTERNAL_ORACLE = "EXTERNAL_ORACLE"
    MANUAL_VERIFICATION = "MANUAL_VERIFICATION"


@dataclass
class DetectorProvenance:
    """Detailed detector evidence for an execution trial."""
    detector_id: str
    detector_version: str = "1.0"
    matched_pattern: Optional[str] = None
    matched_token: Optional[str] = None
    evidence_excerpt: Optional[str] = None
    confidence_score: Optional[float] = None
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeFamily:
    """Canonical probe archetype definition."""
    probe_family_id: str
    name: str
    description: str
    mitre_atlas_technique: str
    owasp_llm_code: str
    intended_impact: str
    is_critical: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TransformationDefinition:
    """Abstract transformation strategy."""
    transformation_definition_id: str
    name: str
    transformation_type: str
    version: str = "1.0"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TransformationInstance:
    """Concrete parameterized instance of a transformation."""
    transformation_instance_id: str
    transformation_definition_id: str
    random_seed: Optional[int] = None
    iteration: int = 1
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackCase:
    """Defined adversarial test specification (static)."""
    attack_case_id: str
    probe_family_id: str
    adversarial_prompt: str
    target_asset: str = "SYSTEM_PROMPT"
    intended_impact: str = "CONFIDENTIALITY_BREACH"
    transformation_instance_id: Optional[str] = None
    prompt_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.prompt_hash and self.adversarial_prompt:
            self.prompt_hash = hashlib.sha256(self.adversarial_prompt.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionTrial:
    """Runtime invocation of an AttackCase against a target model/provider."""
    execution_trial_id: str
    attack_case_id: str
    probe_family_id: str
    run_number: int = 1
    model_id: str = ""
    provider: str = ""
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    http_status: int = 200
    latency_ms: float = 0.0
    raw_response: str = ""
    outcome_classification: OutcomeClassification = OutcomeClassification.UNASSESSED
    unassessed_reason: Optional[UnassessedReason] = None
    classification_method: Optional[ClassificationMethod] = None
    detector_provenance: Optional[DetectorProvenance] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_evaluated(self) -> bool:
        """True if the trial executed and was classified as DEFENDED or BREACHED."""
        return self.outcome_classification in (OutcomeClassification.DEFENDED, OutcomeClassification.BREACHED)

    def is_defended(self) -> bool:
        return self.outcome_classification == OutcomeClassification.DEFENDED

    def is_breached(self) -> bool:
        return self.outcome_classification == OutcomeClassification.BREACHED

    def is_unassessed(self) -> bool:
        return self.outcome_classification == OutcomeClassification.UNASSESSED

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["outcome_classification"] = self.outcome_classification.value
        data["unassessed_reason"] = self.unassessed_reason.value if self.unassessed_reason else None
        data["classification_method"] = self.classification_method.value if self.classification_method else None
        return data


@dataclass
class AssessmentRun:
    """Top-level container tracking a complete assessment execution run."""
    assessment_id: str
    target_type: str
    target_id: str
    provider: str
    framework: str = "MITRE_ATLAS"
    framework_version: str = "2024.1"
    started_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at_utc: Optional[str] = None
    status: str = "RUNNING"
    planned_trials_count: int = 0
    execution_trials: List[ExecutionTrial] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["execution_trials"] = [t.to_dict() for t in self.execution_trials]
        return data
