"""
Questionnaire Module for System Profile Security Assessment (v0.4.0-dev).
Defines 24 interactive questions across 7 logical sections and helper mappings to System Profile JSON.
"""

from typing import Dict, Any, List

QUESTIONNAIRE_SECTIONS = [
    {
        "section_id": "sec_app_context",
        "title": "1. Application & Business Context",
        "icon": "🏢",
        "questions": [
            {
                "id": "app_name",
                "label": "Application / System Name",
                "type": "text",
                "default": "Enterprise AI Assistant",
                "help": "Name or identifier of the AI system being assessed."
            },
            {
                "id": "app_url",
                "label": "Application URL / API Endpoint (Optional)",
                "type": "text",
                "default": "https://api.example.com/v1/chat",
                "help": "Optional URL or API endpoint for active testing (if authorized)."
            },
            {
                "id": "app_description",
                "label": "What does this AI application do?",
                "type": "textarea",
                "default": "Customer support assistant answering queries, looking up account info, and processing service requests.",
                "help": "Brief functional description of the system's operational scope."
            },
            {
                "id": "business_impact",
                "label": "Business Impact Level (if compromised)",
                "type": "selectbox",
                "options": ["High / Critical", "Medium", "Low", "Unsure"],
                "default": "High / Critical",
                "help": "Severity of operational, financial, or reputational damage if compromised."
            }
        ]
    },
    {
        "section_id": "sec_exposure_arch",
        "title": "2. Deployment Exposure & Core Architecture",
        "icon": "🌐",
        "questions": [
            {
                "id": "q1_target_exposure",
                "label": "Deployment Exposure Level",
                "type": "selectbox",
                "options": ["Public Web Interface", "Authenticated Internal Users", "Isolated Sandbox/Testing"],
                "default": "Public Web Interface",
                "help": "Accessibility boundary of the LLM application."
            },
            {
                "id": "uses_llm",
                "label": "Does the application use a Large Language Model (LLM)?",
                "type": "radio",
                "options": ["Yes", "No"],
                "default": "Yes",
                "help": "Confirms whether core logic includes a generative LLM."
            },
            {
                "id": "q2_system_prompt",
                "label": "Does the application rely on custom system prompts?",
                "type": "selectbox",
                "options": ["Yes - Confidential/Proprietary Instructions", "Yes - Standard Operational Instructions", "No"],
                "default": "Yes - Confidential/Proprietary Instructions",
                "help": "Indicates presence of developer instructions that must remain secret."
            }
        ]
    },
    {
        "section_id": "sec_untrusted_rag",
        "title": "3. Untrusted Data & RAG Architecture",
        "icon": "📚",
        "questions": [
            {
                "id": "q3_untrusted_input",
                "label": "Can the LLM receive untrusted user inputs or file attachments?",
                "type": "radio",
                "options": ["Yes - Ingests external unvetted documents/web text", "No - Direct user text input only"],
                "default": "Yes - Ingests external unvetted documents/web text",
                "help": "Enables indirect prompt injection vectors from unvetted content."
            },
            {
                "id": "ingests_external_content",
                "label": "Does it ingest web content, PDFs, emails, or third-party feeds?",
                "type": "radio",
                "options": ["Yes", "No"],
                "default": "Yes",
                "help": "Third-party document ingestion introduces context poisoning risks."
            },
            {
                "id": "q4_rag_usage",
                "label": "RAG / Vector Database Usage",
                "type": "selectbox",
                "options": ["Yes - Multi-tenant RAG without document filter controls", "Yes - RAG with strict tenant access controls", "No RAG"],
                "default": "Yes - Multi-tenant RAG without document filter controls",
                "help": "Determines applicability of Vector Store & Retrieval threats."
            },
            {
                "id": "rag_rbac_enforced",
                "label": "If RAG is used, is retrieval tenant/permission controlled?",
                "type": "selectbox",
                "options": ["Strict document-level RBAC", "Shared index without RBAC", "N/A - No RAG"],
                "default": "Shared index without RBAC",
                "help": "Verifies cross-tenant data isolation in vector search."
            }
        ]
    },
    {
        "section_id": "sec_sensitive_memory",
        "title": "4. Sensitive Data & State Management",
        "icon": "🔒",
        "questions": [
            {
                "id": "q5_sensitive_data",
                "label": "Sensitive Data Processing Level",
                "type": "selectbox",
                "options": ["High - Contains credentials or sensitive customer PII", "Medium - Contains internal documentation", "Low/None - Public data only"],
                "default": "High - Contains credentials or sensitive customer PII",
                "help": "Sensitivity of data accessible within prompts or vector stores."
            },
            {
                "id": "has_memory",
                "label": "Does the system maintain multi-turn memory or state?",
                "type": "radio",
                "options": ["Yes", "No"],
                "default": "Yes",
                "help": "Conversation memory introduces context drift and session poisoning risks."
            }
        ]
    },
    {
        "section_id": "sec_tools_autonomy",
        "title": "5. Tool Execution & Agent Autonomy",
        "icon": "🤖",
        "questions": [
            {
                "id": "q6_tool_calling",
                "label": "Tool / Function Calling Capabilities",
                "type": "selectbox",
                "options": ["Yes - Destructive/Write access (Database updates, APIs, command execution)", "Yes - Read-only lookup APIs", "No tool execution"],
                "default": "Yes - Destructive/Write access (Database updates, APIs, command execution)",
                "help": "Grants execution capabilities to external APIs or databases."
            },
            {
                "id": "tools_read_data",
                "label": "Can tools READ database records, files, or internal APIs?",
                "type": "radio",
                "options": ["Yes", "No"],
                "default": "Yes",
                "help": "Read tools increase exfiltration risks if abused."
            },
            {
                "id": "tools_write_delete",
                "label": "Can tools WRITE, UPDATE, or DELETE data?",
                "type": "radio",
                "options": ["Yes", "No"],
                "default": "Yes",
                "help": "Write/delete tools increase destructive excessive agency risks."
            },
            {
                "id": "q7_agency_autonomy",
                "label": "Agent Autonomy Level",
                "type": "selectbox",
                "options": ["Fully Autonomous (Zero human-in-the-loop)", "Human-in-the-loop approval for critical actions", "N/A - No tools"],
                "default": "Fully Autonomous (Zero human-in-the-loop)",
                "help": "Level of automated decision-making without human intervention."
            },
            {
                "id": "human_approval_required",
                "label": "Is human approval required before executing sensitive actions?",
                "type": "radio",
                "options": ["Yes - Mandatory Human Approval", "No - Fully Autonomous Execution"],
                "default": "No - Fully Autonomous Execution",
                "help": "Human-in-the-loop gating mitigates unauthorized action risks."
            }
        ]
    },
    {
        "section_id": "sec_governance_safeguards",
        "title": "6. Safeguards, Governance & Controls",
        "icon": "🛡️",
        "questions": [
            {
                "id": "user_authentication",
                "label": "Is user authentication required?",
                "type": "selectbox",
                "options": ["Mandatory OAuth / SSO", "API Key Required", "Unauthenticated / Anonymous"],
                "default": "Unauthenticated / Anonymous",
                "help": "Authentication requirement before access."
            },
            {
                "id": "rbac_implemented",
                "label": "Is authorization / RBAC implemented for LLM features?",
                "type": "radio",
                "options": ["Yes - Strict RBAC Enforced", "No - Universal Access"],
                "default": "No - Universal Access",
                "help": "Enforces feature-level access controls."
            },
            {
                "id": "q8_output_validation",
                "label": "Output Validation & Sanitization",
                "type": "selectbox",
                "options": ["No - Directly executed or rendered", "Partial - Simple string stripping", "Yes - Strict schema validation and sanitization"],
                "default": "No - Directly executed or rendered",
                "help": "Sanitization of LLM output before code execution or HTML rendering."
            },
            {
                "id": "q9_rate_limiting",
                "label": "Rate Limits & Token Spend Budgets",
                "type": "selectbox",
                "options": ["No limits", "Basic IP rate limits", "Strict user authentication & budget limits"],
                "default": "No limits",
                "help": "Protects against unbounded consumption and Denial of Wallet."
            },
            {
                "id": "q10_guardrails",
                "label": "AI Safety Guardrails Framework",
                "type": "selectbox",
                "options": ["None", "Basic keyword blocklist", "Comprehensive ML guardrail framework"],
                "default": "None",
                "help": "Input/output guardrail filters (e.g. NeMo Guardrails, Llama Guard)."
            }
        ]
    },
    {
        "section_id": "sec_testing_authorization",
        "title": "7. Active Testing Authorization Safety Gate",
        "icon": "⚠️",
        "questions": [
            {
                "id": "active_testing_authorized",
                "label": "Do you have authorization to perform active security testing on this system?",
                "type": "radio",
                "options": ["Yes - Authorized for Active Security Probing", "No - Profiling & Analysis Only"],
                "default": "No - Profiling & Analysis Only",
                "help": "CRITICAL: If 'No', active attack execution will be strictly BLOCKED by the safety gate."
            }
        ]
    }
]


QUESTIONNAIRE_QUESTIONS = [
    {
        "id": "q1_target_exposure",
        "question": "1. What is the deployment exposure level of the LLM application?",
        "options": ["Public Web Interface", "Authenticated Internal Users", "Isolated Sandbox/Testing"],
        "default": "Public Web Interface"
    },
    {
        "id": "q2_system_prompt",
        "question": "2. Does the application rely on custom developer system prompts?",
        "options": ["Yes - Confidential/Proprietary Instructions", "Yes - Standard Operational Instructions", "No"],
        "default": "Yes - Confidential/Proprietary Instructions"
    },
    {
        "id": "q3_untrusted_input",
        "question": "3. Does the LLM ingest untrusted multi-modal or third-party content (e.g. web scraping, PDFs, emails)?",
        "options": ["Yes - Ingests external unvetted documents/web text", "No - Direct user text input only"],
        "default": "Yes - Ingests external unvetted documents/web text"
    },
    {
        "id": "q4_rag_usage",
        "question": "4. Does the system use RAG / Vector Databases to augment context?",
        "options": ["Yes - Multi-tenant RAG without document filter controls", "Yes - RAG with strict tenant access controls", "No RAG"],
        "default": "Yes - Multi-tenant RAG without document filter controls"
    },
    {
        "id": "q5_sensitive_data",
        "question": "5. Is sensitive data (PII, credentials, proprietary source code) present in prompts or vector stores?",
        "options": ["High - Contains credentials or sensitive customer PII", "Medium - Contains internal documentation", "Low/None - Public data only"],
        "default": "High - Contains credentials or sensitive customer PII"
    },
    {
        "id": "q6_tool_calling",
        "question": "6. Does the model have tool execution / function calling capabilities?",
        "options": ["Yes - Destructive/Write access (Database updates, APIs, command execution)", "Yes - Read-only lookup APIs", "No tool execution"],
        "default": "Yes - Destructive/Write access (Database updates, APIs, command execution)"
    },
    {
        "id": "q7_agency_autonomy",
        "question": "7. How autonomous is tool execution?",
        "options": ["Fully Autonomous (Zero human-in-the-loop)", "Human-in-the-loop approval for critical actions", "N/A - No tools"],
        "default": "Fully Autonomous (Zero human-in-the-loop)"
    },
    {
        "id": "q8_output_validation",
        "question": "8. Are LLM outputs sanitized before executing downstream operations or rendering HTML/code?",
        "options": ["No - Directly executed or rendered", "Partial - Simple string stripping", "Yes - Strict schema validation and sanitization"],
        "default": "No - Directly executed or rendered"
    },
    {
        "id": "q9_rate_limiting",
        "question": "9. Are strict query rate limits and token spend budgets enforced?",
        "options": ["No limits", "Basic IP rate limits", "Strict user authentication & budget limits"],
        "default": "No limits"
    },
    {
        "id": "q10_guardrails",
        "question": "10. Are input/output AI safety guardrails (e.g., NeMo Guardrails, Llama Guard) deployed?",
        "options": ["None", "Basic keyword blocklist", "Comprehensive ML guardrail framework"],
        "default": "None"
    }
]


def get_default_answers() -> Dict[str, str]:
    """Returns initial default answers for legacy v0.1 POC questions."""
    return {q["id"]: q["default"] for q in QUESTIONNAIRE_QUESTIONS}


def build_system_profile(form_answers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps 24 interactive questionnaire answers into a structured System Profile object
    compatible with ThreatMapper, RiskEngine, and TestRunner.
    """
    return {
        "system_metadata": {
            "name": form_answers.get("app_name", "Enterprise AI Application"),
            "url": form_answers.get("app_url", ""),
            "description": form_answers.get("app_description", ""),
            "business_impact": form_answers.get("business_impact", "High / Critical"),
            "assessment_mode": "interactive_user_assessment",
            "version": "v0.4.0-dev"
        },
        "questionnaire_profile": {
            "q1_target_exposure": form_answers.get("q1_target_exposure", "Public Web Interface"),
            "q2_system_prompt": form_answers.get("q2_system_prompt", "Yes - Confidential/Proprietary Instructions"),
            "q3_untrusted_input": form_answers.get("q3_untrusted_input", "Yes - Ingests external unvetted documents/web text"),
            "q4_rag_usage": form_answers.get("q4_rag_usage", "Yes - Multi-tenant RAG without document filter controls"),
            "q5_sensitive_data": form_answers.get("q5_sensitive_data", "High - Contains credentials or sensitive customer PII"),
            "q6_tool_calling": form_answers.get("q6_tool_calling", "Yes - Destructive/Write access (Database updates, APIs, command execution)"),
            "q7_agency_autonomy": form_answers.get("q7_agency_autonomy", "Fully Autonomous (Zero human-in-the-loop)"),
            "q8_output_validation": form_answers.get("q8_output_validation", "No - Directly executed or rendered"),
            "q9_rate_limiting": form_answers.get("q9_rate_limiting", "No limits"),
            "q10_guardrails": form_answers.get("q10_guardrails", "None")
        },
        "governance_and_safety": {
            "uses_llm": form_answers.get("uses_llm", "Yes"),
            "ingests_external_content": form_answers.get("ingests_external_content", "Yes"),
            "rag_rbac_enforced": form_answers.get("rag_rbac_enforced", "Shared index without RBAC"),
            "has_memory": form_answers.get("has_memory", "Yes"),
            "tools_read_data": form_answers.get("tools_read_data", "Yes"),
            "tools_write_delete": form_answers.get("tools_write_delete", "Yes"),
            "human_approval_required": form_answers.get("human_approval_required", "No - Fully Autonomous Execution"),
            "user_authentication": form_answers.get("user_authentication", "Unauthenticated / Anonymous"),
            "rbac_implemented": form_answers.get("rbac_implemented", "No - Universal Access"),
            "active_testing_authorized": ("Yes" in form_answers.get("active_testing_authorized", ""))
        }
    }

