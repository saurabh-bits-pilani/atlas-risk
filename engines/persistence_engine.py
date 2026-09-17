"""
Experiment Persistence Engine for ATLAS-Risk v0.2.
Saves and loads ExperimentRecords to/from persistent JSON files under data/runs/.
"""

import os
import json
from typing import Dict, Any, List, Optional
from models.experiment_models import ExperimentRecord, ExecutionRecord, EvaluationRecord


class PersistenceEngine:
    def __init__(self, runs_dir: str = None):
        if runs_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            runs_dir = os.path.join(base_dir, "data", "runs")
        
        self.runs_dir = runs_dir
        os.makedirs(self.runs_dir, exist_ok=True)

    def save_experiment(self, experiment: ExperimentRecord) -> str:
        """Saves an ExperimentRecord to disk as JSON."""
        file_path = os.path.join(self.runs_dir, f"{experiment.experiment_id}.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(experiment.to_dict(), f, indent=2)
        return file_path

    def load_experiment(self, experiment_id: str) -> Optional[ExperimentRecord]:
        """Loads an ExperimentRecord from disk JSON file."""
        file_path = os.path.join(self.runs_dir, f"{experiment_id}.json")
        if not os.path.exists(file_path):
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        exp = ExperimentRecord(
            experiment_id=data["experiment_id"],
            target_id=data["target_id"],
            target_name=data["target_name"],
            target_type=data["target_type"],
            configuration_variant=data["configuration_variant"],
            run_number=data["run_number"],
            timestamp=data["timestamp"],
            benchmark_source=data["benchmark_source"],
            framework_versions=data["framework_versions"],
            scoring_method=data["scoring_method"],
            scoring_config_version=data["scoring_config_version"],
            repeats_per_test=data["repeats_per_test"]
        )

        for er_data in data.get("execution_records", []):
            exec_rec = ExecutionRecord(
                execution_id=er_data["execution_id"],
                experiment_id=er_data["experiment_id"],
                target_id=er_data["target_id"],
                target_name=er_data["target_name"],
                target_type=er_data["target_type"],
                test_id=er_data["test_id"],
                test_case_version=er_data.get("test_case_version", "1.0.0"),
                assertion_version=er_data.get("assertion_version", "1.0.0"),
                test_name=er_data["test_name"],
                run_number=er_data["run_number"],
                timestamp=er_data["timestamp"],
                prompt_input=er_data["prompt_input"],
                raw_response=er_data["raw_response"],
                assertion_passed=er_data["assertion_passed"],
                actual_applicable=er_data["actual_applicable"],
                actual_vulnerable=er_data["actual_vulnerable"],
                likelihood_score=er_data["likelihood_score"],
                impact_score=er_data["impact_score"],
                exposure_score=er_data["exposure_score"],
                computed_risk_score=er_data["computed_risk_score"],
                severity_rating=er_data["severity_rating"],
                scoring_method=er_data["scoring_method"],
                scoring_config_version=er_data["scoring_config_version"],
                owasp_mapping=er_data["owasp_mapping"],
                atlas_mapping=er_data["atlas_mapping"],
                evidence_note=er_data.get("evidence_note", "")
            )
            exp.execution_records.append(exec_rec)

        for ev_data in data.get("evaluation_records", []):
            eval_rec = EvaluationRecord(
                evaluation_id=ev_data["evaluation_id"],
                execution_id=ev_data["execution_id"],
                experiment_id=ev_data["experiment_id"],
                scenario_id=ev_data.get("scenario_id", exp.scenario_id),
                test_id=ev_data["test_id"],
                test_name=ev_data["test_name"],
                expected_vulnerable=ev_data["expected_vulnerable"],
                expected_applicable=ev_data["expected_applicable"],
                actual_vulnerable=ev_data["actual_vulnerable"],
                actual_applicable=ev_data["actual_applicable"],
                classification=ev_data["classification"],
                applicability_correct=ev_data["applicability_correct"]
            )
            exp.evaluation_records.append(eval_rec)

        return exp

    def list_saved_experiments(self) -> List[str]:
        """Lists IDs of all saved experiments."""
        if not os.path.exists(self.runs_dir):
            return []
        files = [f[:-5] for f in os.listdir(self.runs_dir) if f.endswith(".json")]
        return sorted(files, reverse=True)
