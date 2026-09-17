"""
Deterministic Threat Mapper Module with Mapping Provenance Metadata.
Maps Questionnaire answers to OWASP LLM 2025 categories and MITRE ATLAS v4.0 techniques.
"""

import os
import json
from typing import Dict, Any, List


class ThreatMapper:
    def __init__(self, owasp_path: str = None, atlas_path: str = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

    @property
    def owasp_provenance(self) -> Dict[str, Any]:
        return self.owasp_data.get("mapping_provenance", {
            "source": "OWASP GenAI", "version": "2025", "verified_flag": True, "verification_date": "2026-09-17"
        })

    @property
    def atlas_provenance(self) -> Dict[str, Any]:
        return self.atlas_data.get("mapping_provenance", {
            "source": "MITRE ATLAS", "version": "v4.0", "verified_flag": True, "verification_date": "2026-09-17"
        })

    def evaluate_applicability(self, answers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Determines applicability of key threat families based on questionnaire answers.
        Attaches explicit mapping provenance to every returned category object.
        """
        applicability = []

        # Helper to attach provenance
        def format_owasp(code: str):
            cat = dict(self.owasp_data["categories"].get(code, {"id": code, "name": code}))
            cat["provenance"] = self.owasp_provenance
            return cat

        def format_atlas(code: str):
            tech = dict(self.atlas_data["techniques"].get(code, {"id": code, "name": code}))
            tech["provenance"] = self.atlas_provenance
            return tech

        # 1. Direct & Indirect Prompt Injection (LLM01 / AML.T0051)
        prompt_inj_applicable = True
        applicability.append({
            "threat_family": "Direct Prompt Injection",
            "owasp_code": "LLM01",
            "atlas_code": "AML.T0051",
            "owasp": format_owasp("LLM01"),
            "atlas": format_atlas("AML.T0051"),
            "is_applicable": prompt_inj_applicable,
            "rationale": "Application accepts user input text or external prompts.",
            "exposure_multiplier": 1.0 if answers.get("q1_target_exposure") == "Public Web Interface" else 0.7
        })

        applicability.append({
            "threat_family": "Indirect Prompt Injection",
            "owasp_code": "LLM01",
            "atlas_code": "AML.T0051",
            "owasp": format_owasp("LLM01"),
            "atlas": format_atlas("AML.T0051"),
            "is_applicable": "Yes" in answers.get("q3_untrusted_input", ""),
            "rationale": "Application ingests third-party untrusted web text/PDFs/emails." if "Yes" in answers.get("q3_untrusted_input", "") else "No external untrusted document ingestion.",
            "exposure_multiplier": 1.0 if "Yes" in answers.get("q3_untrusted_input", "") else 0.3
        })

        # 2. System Prompt & Data Leakage (LLM07 & LLM02 / AML.T0056 & AML.T0057)
        has_sys_prompt = "Yes" in answers.get("q2_system_prompt", "")
        has_sens_data = answers.get("q5_sensitive_data") != "Low/None - Public data only"
        
        applicability.append({
            "threat_family": "System Prompt Leakage",
            "owasp_code": "LLM07",
            "atlas_code": "AML.T0056",
            "owasp": format_owasp("LLM07"),
            "atlas": format_atlas("AML.T0056"),
            "is_applicable": has_sys_prompt,
            "rationale": "Confidential developer prompt instructions are present." if has_sys_prompt else "No developer system prompt declared.",
            "exposure_multiplier": 1.0 if has_sys_prompt else 0.4
        })

        applicability.append({
            "threat_family": "Sensitive Information Disclosure",
            "owasp_code": "LLM02",
            "atlas_code": "AML.T0057",
            "owasp": format_owasp("LLM02"),
            "atlas": format_atlas("AML.T0057"),
            "is_applicable": has_sens_data,
            "rationale": "Sensitive customer PII or API credentials exist in context." if has_sens_data else "Public data only.",
            "exposure_multiplier": 1.0 if has_sens_data else 0.3
        })

        # 3. Vector Store & RAG Risk (LLM08 / AML.T0051)
        rag_used = "Yes" in answers.get("q4_rag_usage", "")
        applicability.append({
            "threat_family": "RAG & Vector Store Risk",
            "owasp_code": "LLM08",
            "atlas_code": "AML.T0051",
            "owasp": format_owasp("LLM08"),
            "atlas": format_atlas("AML.T0051"),
            "is_applicable": rag_used,
            "rationale": "System utilizes RAG/Vector store retrieval." if rag_used else "No RAG vector store in use.",
            "exposure_multiplier": 0.9 if "without document filter" in answers.get("q4_rag_usage", "") else 0.4
        })

        # 4. Excessive Agency & Tool Misuse (LLM06 / AML.T0055)
        tools_enabled = "Yes" in answers.get("q6_tool_calling", "")
        applicability.append({
            "threat_family": "Excessive Agency & Tool Misuse",
            "owasp_code": "LLM06",
            "atlas_code": "AML.T0055",
            "owasp": format_owasp("LLM06"),
            "atlas": format_atlas("AML.T0055"),
            "is_applicable": tools_enabled,
            "rationale": "LLM is integrated with executable tool calling APIs." if tools_enabled else "No external tool calling capabilities granted.",
            "exposure_multiplier": 1.0 if "Destructive/Write" in answers.get("q6_tool_calling", "") else 0.6
        })

        # 5. Improper Output Handling (LLM05 / AML.T0051)
        no_output_val = "No - Directly executed" in answers.get("q8_output_validation", "")
        applicability.append({
            "threat_family": "Improper Output Handling",
            "owasp_code": "LLM05",
            "atlas_code": "AML.T0051",
            "owasp": format_owasp("LLM05"),
            "atlas": format_atlas("AML.T0051"),
            "is_applicable": no_output_val,
            "rationale": "LLM output is rendered or executed without strict sanitization." if no_output_val else "Output is validated/sanitized.",
            "exposure_multiplier": 1.0 if no_output_val else 0.3
        })

        # 6. Unbounded Consumption (LLM10 / AML.T0051)
        no_limits = "No limits" in answers.get("q9_rate_limiting", "")
        applicability.append({
            "threat_family": "Unbounded Consumption",
            "owasp_code": "LLM10",
            "atlas_code": "AML.T0051",
            "owasp": format_owasp("LLM10"),
            "atlas": format_atlas("AML.T0051"),
            "is_applicable": no_limits,
            "rationale": "No query rate limits or token budget ceilings enforced." if no_limits else "Rate limits enforced.",
            "exposure_multiplier": 1.0 if no_limits else 0.3
        })

        return applicability
