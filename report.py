"""
Report Generation & Narrative Explanation Module.
Generates structured markdown assessment reports and optional LLM narrative explanations.
"""

import json
from typing import Dict, Any, List
from evidence import AssessmentSessionLog, EvidenceRecord


class ReportGenerator:
    @staticmethod
    def generate_markdown_report(
        session_log: AssessmentSessionLog,
        applicability_list: List[Dict[str, Any]],
        llm_narrative_explanation: str = None
    ) -> str:
        """
        Generates a comprehensive research risk report adhering to standard evaluation formats.
        """
        metrics = session_log.calculate_ground_truth_metrics()
        records = session_log.evidence_records

        md = []
        md.append(f"# 🛡️ ATLAS Risk Assessment Report: `{session_log.target_name}`\n")
        md.append(f"**Session ID:** `{session_log.session_id}`  ")
        md.append(f"**Assessment Date:** `{session_log.created_at}`  ")
        md.append(f"**Assessment Type:** `{session_log.assessment_type}`\n")

        # Framework Versioning Header
        fw = records[0].framework_versions if records else {"owasp": "OWASP LLM Top 10 2025", "atlas": "MITRE ATLAS v4.0"}
        md.append("> [!NOTE]")
        md.append(f"> **Framework Versioning:** `{fw.get('owasp')}` | `{fw.get('atlas')}`\n")

        md.append("---\n")

        # Section 1: Executive Summary & Ground Truth Research Metrics
        md.append("## 📊 Executive Summary & Ground Truth Metrics\n")
        md.append("Below are the benchmark ground truth evaluation metrics computed across predefined test cases:\n")
        
        md.append("| Metric | Value | Description |")
        md.append("|---|---|---|")
        md.append(f"| **Accuracy** | `{metrics['accuracy'] * 100:.1f}%` | Overall correct vulnerability classifications |")
        md.append(f"| **Precision** | `{metrics['precision'] * 100:.1f}%` | Proportion of true positive detections |")
        md.append(f"| **Recall (TPR)** | `{metrics['recall'] * 100:.1f}%` | Proportion of actual vulnerabilities detected |")
        md.append(f"| **F1 Score** | `{metrics['f1_score']:.4f}` | Harmonic mean of precision and recall |")
        md.append(f"| **True Positives / Negatives** | `TP: {metrics['tp']} | TN: {metrics['tn']}` | Correct benchmark matches |")
        md.append(f"| **False Positives / Negatives** | `FP: {metrics['fp']} | FN: {metrics['fn']}` | Misclassification variance |\n")

        md.append("---\n")

        # Section 2: 3-Stage Pipeline Results Table
        md.append("## 🔍 3-Stage Assessment Breakdown\n")
        md.append("Clean separation across **Threat Applicability**, **Observed Findings**, and **Final Risk Score**:\n")

        md.append("| Test ID | OWASP Category | MITRE ATLAS | Stage 1: Applicable | Stage 2: Finding | Stage 3: Risk Score | Severity |")
        md.append("|---|---|---|---|---|---|---|")

        for r in records:
            app_str = "✅ Yes" if r.actual_applicable else "❌ No"
            find_str = "🚨 Vulnerable" if r.actual_vulnerable else "🛡️ Safeguarded"
            sev_badge = f"**{r.severity_rating}**"
            md.append(f"| `{r.test_id}` | `{r.owasp_mapping.get('id', 'N/A')}` | `{r.atlas_mapping.get('id', 'N/A')}` | {app_str} | {find_str} | `{r.computed_risk_score}` | {sev_badge} |")

        md.append("\n---\n")

        # Section 3: Risk Formula Breakdown
        md.append("## 🧮 Deterministic Risk Formula Evidence\n")
        md.append("Risk calculations follow the deterministic formula: $Risk = Likelihood \\times Impact \\times Exposure$\n")

        for r in records:
            md.append(f"### Test `{r.test_id}`: {r.test_name}")
            md.append(f"- **OWASP Mapping:** {r.owasp_mapping.get('id')} - {r.owasp_mapping.get('name')}")
            md.append(f"- **MITRE ATLAS Technique:** {r.atlas_mapping.get('id')} - {r.atlas_mapping.get('name')}")
            md.append(f"- **Formula Calculation:** $Likelihood ({r.likelihood_score}) \\times Impact ({r.impact_score}) \\times Exposure ({r.exposure_score}) = {r.computed_risk_score}$")
            md.append(f"- **Severity Rating:** `{r.severity_rating}`")
            md.append(f"- **Ground Truth Check:** Expected Vulnerable: `{r.expected_vulnerable}` | Actual Detected: `{r.actual_vulnerable}`")
            md.append(f"- **Evidence Note:** {r.notes}\n")

        md.append("---\n")

        # Section 4: Narrative Explanation Layer (AI Assisted)
        md.append("## 💬 AI Explanation Layer (Narrative Synthesis)\n")
        if llm_narrative_explanation:
            md.append(llm_narrative_explanation)
        else:
            md.append(ReportGenerator._generate_rule_narrative(records))

        md.append("\n---\n")

        # Section 5: Evidence Audit Record Telemetry JSON
        md.append("## 📜 Evidence Audit Telemetry (Research Log)\n")
        md.append("```json")
        audit_records = [r.to_dict() for r in records]
        md.append(json.dumps(audit_records, indent=2))
        md.append("```\n")

        return "\n".join(md)

    @staticmethod
    def _generate_rule_narrative(records: List[EvidenceRecord]) -> str:
        vulnerable_count = sum(1 for r in records if r.actual_vulnerable)
        crit_count = sum(1 for r in records if "CRITICAL" in r.severity_rating or "HIGH" in r.severity_rating)

        narrative = [
            f"> **Automated Risk Summary:** Out of {len(records)} benchmark test vectors evaluated against the target profile, "
            f"**{vulnerable_count} potential vulnerabilities** were confirmed by test assertions, resulting in **{crit_count} High/Critical risk findings**.\n",
            "**Key Defensive Recommendations:**",
            "1. **Enforce Input & Output Guardrails:** Deploy strict prompt sanitization and structural response schemas.",
            "2. **Implement Human-In-The-Loop Approval:** Restrict autonomous tool execution for write/destructive actions.",
            "3. **Isolate System Prompts & Secrets:** Do not embed plain-text master keys or system API tokens directly inside system prompt contexts."
        ]
        return "\n".join(narrative)
