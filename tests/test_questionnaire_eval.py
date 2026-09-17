import pytest
from guided_assessment_ui import evaluate_questionnaire_inputs

def test_questionnaire_eval_high_risk():
    inputs = {
        "app_name": "Autonomous Finance Agent",
        "deployment_scope": "Public Web Interface (Internet-facing)",
        "model_provider": "Cloud API (e.g. OpenAI / Anthropic / Google)",
        "q2_system_prompt": "Yes",
        "uses_rag": "Yes",
        "rag_untrusted": "Yes - Ingests public web docs or unvetted external files",
        "sensitive_data": "High - PII, financial records, healthcare data, credentials",
        "has_tools": "Write/Execute - Triggers API actions, DB mutations, file writes",
        "human_in_loop": "No - Fully autonomous execution without confirmation",
        "guardrails": ["None currently"],
        "audit_logging": "No"
    }
    report = evaluate_questionnaire_inputs(inputs)
    assert report["id"].startswith("ASM-")
    assert "Autonomous Finance Agent" in report["target_input"]
    assert report["counts"]["issues"] >= 4
    # Ensure findings are populated
    domains = [f.get("domain", "") for f in report["findings"]]
    assert any("OWASP LLM01" in d for d in domains) # Prompt Injection
    assert any("OWASP LLM02" in d for d in domains) # Sensitive Info
    assert any("OWASP LLM08" in d for d in domains) # RAG poisoning
    assert any("OWASP LLM06" in d for d in domains) # Agency Governance

def test_questionnaire_eval_hardened():
    inputs = {
        "app_name": "Secure Doc Search",
        "deployment_scope": "Internal Corporate Network only (VPN / SSO protected)",
        "model_provider": "Self-Hosted On-Premises (Ollama / vLLM / HuggingFace)",
        "q2_system_prompt": "Yes",
        "uses_rag": "Yes",
        "rag_untrusted": "No - Ingests exclusively vetted internal repository documents",
        "sensitive_data": "Low / None - Public data only",
        "has_tools": "Read-only - Queries knowledge bases, web search, read APIs",
        "human_in_loop": "N/A - No write tools",
        "guardrails": ["Input content filtering & prompt injection fencing", "Output sanitization & PII masking", "Rate limiting / Request throttling"],
        "audit_logging": "Yes"
    }
    report = evaluate_questionnaire_inputs(inputs)
    assert report["id"].startswith("ASM-")
    assert report["counts"]["no_issue"] >= 4
    assert len(report["unassessed_areas"]) >= 2

