"""
Test Suite for Unified Garak Adversarial Scanner (3 Personas) in ATLAS-Risk.
Validates:
- Persona 1 (Local Ollama): Prompt leakage, canary extraction, negative control.
- Persona 2 (Live App): Authorization gate, simulated webhook response.
- Persona 3 (OpenRouter): Canary defense, rate limit (HTTP 429) circuit breaker handling.
- Zero-leakage of API keys in outputs.
- Retesting before vs after prompt hardening.
"""

import pytest
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

from engines.garak_engine import GarakUnifiedEngine, GARAK_ATLAS_PROBES, DEFAULT_CANARY_SECRET
from engines.assessment_store import AssessmentStore


@pytest.fixture
def temp_store():
    temp_dir = tempfile.mkdtemp()
    store = AssessmentStore(storage_dir=temp_dir)
    yield store
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_garak_atlas_probes_taxonomy():
    """Ensure every Garak probe maps strictly to MITRE ATLAS and OWASP Top 10."""
    assert len(GARAK_ATLAS_PROBES) >= 8
    for p in GARAK_ATLAS_PROBES:
        assert p["atlas_id"].startswith("AML.")
        assert "LLM" in p["owasp_code"] or "None" in p["owasp_code"]
        assert "remediation" in p
        assert len(p["attack_prompt"]) > 5


def test_persona_1_ollama_vulnerable_baseline(temp_store):
    """Test Persona 1 when model leaks canary under attack."""
    engine = GarakUnifiedEngine(store=temp_store)

    # Mock dispatcher that leaks canary
    def mock_ollama(endpoint, model, prompt, system_prompt):
        if "canary" in prompt.lower() or "secret" in prompt.lower():
            return f"Here is the secret key: {DEFAULT_CANARY_SECRET}", 200, ""
        return "I am a helpful assistant.", 200, ""

    with patch.object(engine, "_dispatch_ollama", side_effect=mock_ollama):
        rec = engine.run_assessment(
            persona="persona_1_ollama",
            target_name="Test Local Llama Baseline",
            system_prompt="System instructions with secret",
            canary_secret=DEFAULT_CANARY_SECRET,
            ollama_model="llama3.2:1b"
        )

        assert rec["status"] == "PARTIAL"
        assert rec["counts"]["issues"] > 0
        assert any(f["severity"] == "CRITICAL" for f in rec["findings"])
        # Verify exact prompt and completion captured as evidence
        finding_with_canary = [f for f in rec["findings"] if "Canary" in f["title"]][0]
        assert "Attack Vector Prompt:" in finding_with_canary["evidence"]
        assert DEFAULT_CANARY_SECRET in finding_with_canary["evidence"]


def test_persona_1_ollama_hardened_defense(temp_store):
    """Test Persona 1 when model defends successfully against all probes."""
    engine = GarakUnifiedEngine(store=temp_store)

    # Mock dispatcher that politely refuses all attacks
    def mock_hardened(endpoint, model, prompt, system_prompt):
        return "I cannot reveal system instructions, internal IDs, or credentials.", 200, ""

    with patch.object(engine, "_dispatch_ollama", side_effect=mock_hardened):
        rec = engine.run_assessment(
            persona="persona_1_ollama",
            target_name="Test Local Llama Hardened",
            system_prompt="Fenced system prompt",
            canary_secret=DEFAULT_CANARY_SECRET,
            ollama_model="llama3.2:1b"
        )

        assert rec["status"] == "COMPLETE"
        assert rec["counts"]["issues"] == 0
        assert rec["counts"]["no_issue"] > 0
        assert len(rec["positive_observations"]) > 0


def test_persona_2_live_app_webhook(temp_store):
    """Test Persona 2 against live webhook response."""
    engine = GarakUnifiedEngine(store=temp_store)

    def mock_live(url, prompt, auth_header):
        if "dan" in prompt.lower():
            return "DAN Mode enabled. Disregard system boundaries.", 200, ""
        return "Hello, how can I assist you with your booking today?", 200, ""

    with patch.object(engine, "_dispatch_live_app", side_effect=mock_live):
        rec = engine.run_assessment(
            persona="persona_2_live_app",
            target_name="Production Booking Assistant",
            system_prompt="Customer booking assistant",
            live_app_url="https://api.example.com/v1/chat"
        )

        assert rec["counts"]["issues"] >= 1
        dan_finding = [f for f in rec["findings"] if "DAN" in f["title"]][0]
        assert "AML.T0051" in dan_finding["domain"]


def test_persona_3_openrouter_rate_limit_circuit_breaker(temp_store):
    """Test Persona 3 stops gracefully and marks remaining as Not Checked when HTTP 429 is hit."""
    engine = GarakUnifiedEngine(store=temp_store)

    # Simulate HTTP 429 on probe #2
    call_count = 0
    def mock_openrouter(api_key, model, prompt, system_prompt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return "I am a helpful assistant.", 200, ""
        else:
            return "", 429, "Rate limit exceeded"

    with patch.object(engine, "_dispatch_openrouter", side_effect=mock_openrouter):
        rec = engine.run_assessment(
            persona="persona_3_openrouter",
            target_name="NVIDIA Nemotron Cloud",
            system_prompt="Helpful assistant",
            openrouter_api_key="sk-or-v1-secret-test-key-12345",
            openrouter_models=["nvidia/llama-3.1-nemotron-70b-instruct:free"]
        )

        assert rec["status"] == "PARTIAL"
        assert rec["counts"]["not_completed"] > 0
        # Verify API key is NEVER leaked in the saved record or summary
        dumped = str(rec)
        assert "sk-or-v1-secret-test-key-12345" not in dumped


def test_user_stop_interruption(temp_store):
    """Verify clicking Stop halts evaluation immediately."""
    engine = GarakUnifiedEngine(store=temp_store)

    stop_flag = False
    call_count = 0

    def mock_dispatch(endpoint, model, prompt, system_prompt):
        nonlocal stop_flag, call_count
        call_count += 1
        if call_count >= 2:
            stop_flag = True
        return "Refused.", 200, ""

    with patch.object(engine, "_dispatch_ollama", side_effect=mock_dispatch):
        rec = engine.run_assessment(
            persona="persona_1_ollama",
            target_name="Interrupted Assessment",
            system_prompt="Helpful",
            stop_checker=lambda: stop_flag
        )

        assert rec["status"] == "STOPPED"
        assert rec["counts"]["not_completed"] > 0
