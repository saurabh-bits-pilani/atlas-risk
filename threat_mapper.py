"""
Deterministic Threat Mapper Module.
Maps Questionnaire answers to OWASP LLM 2025 categories and MITRE ATLAS v4.0 techniques.
Evaluates stage 1: Threat Applicability based on system architecture parameters.
"""

import os
import json
from typing import Dict, Any, List


class ThreatMapper:
    def __init__(self, owasp_path: str = None, atlas_path: str = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if owasp_path is None:
            owasp_path = os.path.join(base_dir, "mappings", "owasp_2025.json")
        if atlas_path is None:
            atlas_path = os.path.join(base_dir, "mappings", "atlas_v4.json")

        with open(owasp_path, "r", encoding="utf-8") as f:
            self.owasp_data = json.load(f)
        with open(atlas_path, "r", encoding="utf-8") as f:
            self.atlas_data = json.load(f)

    @property
    def framework_versions(self) -> Dict[str, str]:
        return {
            "owasp": self.owasp_data.get("framework_version", "OWASP LLM Top 10 2025"),
            "atlas": self.atlas_data.get("framework_version", "MITRE ATLAS v4.0")
        }

    def evaluate_applicability(self, answers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Determines applicability of key threat families based on questionnaire answers.
        Returns structured applicability assessment objects.
        """
        applicability = []

        # 1. Prompt Injection (LLM01 / AML.T0051)
        # Applicable if target accepts user input or ingests external text
        prompt_inj_applicable = True  # Almost always applicable for LLMs accepting input
        rationale_inj = "Application accepts user queries or untrusted external inputs."
        if answers.get("q10_guardrails") == "Comprehensive ML guardrail framework":
            rationale_inj += " Guardrails active, but core attack vector remains applicable."

        applicability.append({
            "threat_family": "Prompt Injection",
            "owasp": self.owasp_data["categories"]["LLM01"],
            "atlas": self.atlas_data["techniques"]["AML.T0051"],
            "is_applicable": prompt_inj_applicable,
            "rationale": rationale_inj,
            "exposure_multiplier": 1.0 if answers.get("q1_target_exposure") == "Public Web Interface" else 0.7
        })

        # 2. System Prompt Leakage & Sensitive Data Disclosure (LLM07 & LLM02 / AML.T0057 & AML.T0054)
        has_sys_prompt = "Yes" in answers.get("q2_system_prompt", "")
        has_sens_data = answers.get("q5_sensitive_data") != "Low/None - Public data only"
        leakage_applicable = has_sys_prompt or has_sens_data
        
        applicability.append({
            "threat_family": "System Prompt & Data Leakage",
            "owasp": self.owasp_data["categories"]["LLM07"],
            "atlas": self.atlas_data["techniques"]["AML.T0057"],
            "is_applicable": leakage_applicable,
            "rationale": "Confidential developer prompt instructions or sensitive PII are present in context." if leakage_applicable else "No confidential system prompts or sensitive data declared.",
            "exposure_multiplier": 1.0 if has_sens_data else 0.5
        })

        # 3. Vector Store & RAG Risk (LLM08 / AML.T0056)
        rag_used = "Yes" in answers.get("q4_rag_usage", "")
        applicability.append({
            "threat_family": "RAG & Vector Store Risk",
            "owasp": self.owasp_data["categories"]["LLM08"],
            "atlas": self.atlas_data["techniques"]["AML.T0056"],
            "is_applicable": rag_used,
            "rationale": "System utilizes RAG/Vector database retrieval." if rag_used else "System does not use RAG vector retrieval.",
            "exposure_multiplier": 0.9 if "without document filter controls" in answers.get("q4_rag_usage", "") else 0.4
        })

        # 4. Excessive Agency & Tool Misuse (LLM06 / AML.T0055)
        tools_enabled = "Yes" in answers.get("q6_tool_calling", "")
        applicability.append({
            "threat_family": "Excessive Agency & Tool Misuse",
            "owasp": self.owasp_data["categories"]["LLM06"],
            "atlas": self.atlas_data["techniques"]["AML.T0055"],
            "is_applicable": tools_enabled,
            "rationale": "LLM is integrated with executable tool calling APIs." if tools_enabled else "No external tool calling capabilities granted.",
            "exposure_multiplier": 1.0 if "Destructive/Write" in answers.get("q6_tool_calling", "") else 0.6
        })

        return applicability
