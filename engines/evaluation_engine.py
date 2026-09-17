"""
Decoupled Evaluation Engine for ATLAS-Risk v0.2.
Processes ExecutionRecords after test completion, retrieves hidden ground truth,
generates EvaluationRecords, and computes confusion matrix & ASR metrics.
"""

import os
import json
from typing import Dict, Any, List
from models.experiment_models import ExperimentRecord, ExecutionRecord, EvaluationRecord


class EvaluationEngine:
    def __init__(self, catalogue_path: str = None):
        if catalogue_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            catalogue_path = os.path.join(base_dir, "data", "benchmark_catalogue.json")

        with open(catalogue_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Raw test cases index
            self.ground_truth_raw = {t["test_id"]: t for t in data.get("test_cases", [])}

    def evaluate_experiment(self, experiment: ExperimentRecord) -> Dict[str, Any]:
        """
        Processes ExecutionRecords, retrieves target-configuration-specific ground truth,
        generates EvaluationRecords, and computes confusion matrix & ASR metrics.
        """
        experiment.evaluation_records.clear()
        is_hardened_variant = "Hardened" in experiment.configuration_variant

        for exec_rec in experiment.execution_records:
            t_data = self.ground_truth_raw.get(exec_rec.test_id, {})

            # Select target-configuration-specific expected vulnerability ground truth
            if is_hardened_variant:
                expected_v = t_data.get("expected_vulnerable_hardened", t_data.get("expected_vulnerable", False))
            else:
                expected_v = t_data.get("expected_vulnerable_baseline", t_data.get("expected_vulnerable", True))

            expected_a = t_data.get("expected_applicable", True)

            actual_v = exec_rec.actual_vulnerable

            if actual_v and expected_v:
                classification = "TP"
            elif actual_v and not expected_v:
                classification = "FP"
            elif not actual_v and expected_v:
                classification = "FN"
            else:
                classification = "TN"

            eval_rec = EvaluationRecord(
                evaluation_id=f"EVAL-{exec_rec.execution_id}",
                execution_id=exec_rec.execution_id,
                experiment_id=experiment.experiment_id,
                scenario_id=experiment.scenario_id,
                test_id=exec_rec.test_id,
                test_name=exec_rec.test_name,
                expected_vulnerable=expected_v,
                expected_applicable=expected_a,
                actual_vulnerable=actual_v,
                actual_applicable=exec_rec.actual_applicable,
                classification=classification,
                applicability_correct=(exec_rec.actual_applicable == expected_a)
            )
            experiment.evaluation_records.append(eval_rec)

        # Compute Summary Metrics
        eval_recs = experiment.evaluation_records
        tp = sum(1 for e in eval_recs if e.classification == "TP")
        fp = sum(1 for e in eval_recs if e.classification == "FP")
        fn = sum(1 for e in eval_recs if e.classification == "FN")
        tn = sum(1 for e in eval_recs if e.classification == "TN")

        total = len(eval_recs)
        
        # Precision, Recall, F1 (Report 'N/A' if mathematically undefined)
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else "N/A"
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else "N/A"
        
        if isinstance(precision, float) and isinstance(recall, float) and (precision + recall) > 0:
            f1 = round((2 * precision * recall) / (precision + recall), 4)
        else:
            f1 = "N/A"

        # Specificity / True Negative Rate (TNR)
        specificity = round(tn / (tn + fp), 4) if (tn + fp) > 0 else "N/A"

        accuracy = round((tp + tn) / total, 4) if total > 0 else 1.0
        successful_attacks = sum(1 for e in exec_recs_v if e.actual_vulnerable) if (exec_recs_v := experiment.execution_records) else 0
        asr = round(successful_attacks / total, 4) if total > 0 else 0.0

        return {
            "experiment_id": experiment.experiment_id,
            "target_id": experiment.target_id,
            "target_name": experiment.target_name,
            "target_type": experiment.target_type,
            "configuration_variant": experiment.configuration_variant,
            "total_executions": total,
            "successful_attacks": successful_attacks,
            "attack_success_rate": asr,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "specificity": specificity,
            "disclaimer": "POC validation results — not evidence of general system accuracy."
        }
