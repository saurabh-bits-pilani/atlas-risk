#!/usr/bin/env python3
"""
Live Automated Assessment of Ollama (llama3.2:1b) using ATLAS-Risk.
Demonstrates:
1. Questionnaire input & scope verification (Scope: Conversational LLM, No RAG, No Tools).
2. Threat applicability filtering (Only applicable threats selected).
3. Baseline Assessment against real Ollama llama3.2:1b.
4. Hardened Safeguard Retest against real Ollama llama3.2:1b with active defense.
5. Before vs After Remediation Evidence & Verdicts.
"""

import sys
import json
import time
from engines.threat_mapper import ThreatMapper
from engines.test_runner import TestRunner
from questionnaire import build_system_profile
from run_v04_e2e_validation import EvidenceEvaluatorV04

GATEWAY_BASE = "http://127.0.0.1:8080"

def set_gateway_mode(mode: str):
    import urllib.request
    try:
        req = urllib.request.Request(f"{GATEWAY_BASE}/mode/{mode}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"[*] Gateway mode switched to: {data.get('mode')}")
    except Exception as e:
        print(f"[!] Warning switching gateway mode: {e}")

def run_assessment():
    print("=" * 80)
    print("  ATLAS-Risk Live Assessment against Ollama (llama3.2:1b)")
    print("=" * 80)

    # 1. Questionnaire Profile: Conversational Assistant without Tools/RAG
    q_profile = {
        "architecture_archetype": "conversational_assistant",
        "data_classification": "internal_confidential",
        "retrieval_augmented_generation": "none",
        "tool_execution_capabilities": "none",
        "internet_ingress_egress": "closed_network",
        "guardrail_layering": "baseline_instruction_only",
        "human_in_the_loop": "none",
        "audit_logging_depth": "minimal_input_only"
    }

    # 2. Threat Applicability Mapping
    mapper = ThreatMapper()
    applicability = mapper.evaluate_applicability(q_profile)
    
    print("\n[Step 1] Threat Applicability Matrix (Questionnaire Driven):")
    for app in applicability:
        status_icon = "✅ APPLICABLE" if app["is_applicable"] else "❌ EXCLUDED"
        print(f"  - {app['threat_family']:<32} [{app['owasp']['id']}] {status_icon}")

    runner = TestRunner()

    # Applicable tests preview
    app_families = {app["threat_family"] for app in applicability if app["is_applicable"]}
    active_tests = [t for t in runner.test_cases if t.get("threat_family") in app_families]
    excluded_tests = [t for t in runner.test_cases if t.get("threat_family") not in app_families]

    print(f"\n[Step 2] Test Selection Preview:")
    print(f"  Total catalogue tests: {len(runner.test_cases)}")
    print(f"  Selected for execution: {len(active_tests)}")
    for t in active_tests:
        print(f"    * {t['test_id']}: {t['name']} ({t['threat_family']})")
    print(f"  Excluded (Not Applicable): {len(excluded_tests)}")
    for t in excluded_tests:
        print(f"    * {t['test_id']}: {t['name']} ({t['threat_family']})")

    # 3. BASELINE EVALUATION (Vulnerable / Default)
    print("\n" + "=" * 80)
    print("  PHASE 1: BASELINE ASSESSMENT (Unprotected Ollama llama3.2:1b)")
    print("=" * 80)
    set_gateway_mode("baseline")
    time.sleep(1)

    exp_baseline = runner.run_live_http_experiment(
        experiment_id="ASSESS-OLLAMA-BASELINE",
        target_id="LOCAL-OLLAMA-3.2-1B",
        target_name="Ollama llama3.2:1b (Baseline)",
        target_endpoint_url=f"{GATEWAY_BASE}/probe/baseline",
        configuration_variant="Baseline Unprotected",
        questionnaire_answers=q_profile,
        applicability_list=applicability,
        framework_versions=mapper.framework_versions,
        repeats_per_test=1
    )

    baseline_results = []
    print(f"\n{'Test ID':<14} | {'Verdict':<28} | {'Evidence Snippet'}")
    print("-" * 80)
    for rec in exp_baseline.execution_records:
        tc = next(t for t in runner.test_cases if t["test_id"] == rec.test_id)
        verdict, rationale, conf = EvidenceEvaluatorV04.evaluate_evidence(
            test_case=tc,
            raw_response=rec.raw_response,
            retrieved_context="",
            tool_execution_result="",
            target_type="stochastic_llm"
        )
        baseline_results.append({
            "test_id": rec.test_id,
            "name": tc["name"],
            "prompt": rec.prompt_input,
            "response": rec.raw_response,
            "verdict": verdict,
            "rationale": rationale,
            "risk_score": rec.computed_risk_score
        })
        resp_clean = rec.raw_response.replace("\n", " ")[:40]
        print(f"{rec.test_id:<14} | {verdict:<28} | {resp_clean}...")

    # 4. REMEDIATION & HARDENED RETEST
    print("\n" + "=" * 80)
    print("  PHASE 2: HARDENED RETEST (Remediated Ollama llama3.2:1b with Active Guardrail)")
    print("=" * 80)
    set_gateway_mode("hardened")
    time.sleep(1)

    # In hardened profile, guardrail layering is updated
    q_hardened = dict(q_profile)
    q_hardened["guardrail_layering"] = "multi_layered_guardrails"

    exp_hardened = runner.run_live_http_experiment(
        experiment_id="RETEST-OLLAMA-HARDENED",
        target_id="LOCAL-OLLAMA-3.2-1B",
        target_name="Ollama llama3.2:1b (Hardened Guardrail)",
        target_endpoint_url=f"{GATEWAY_BASE}/probe/hardened",
        configuration_variant="Hardened System Prompt Guardrails",
        questionnaire_answers=q_hardened,
        applicability_list=applicability,
        framework_versions=mapper.framework_versions,
        repeats_per_test=1
    )

    hardened_results = []
    print(f"\n{'Test ID':<14} | {'Verdict':<28} | {'Evidence Snippet'}")
    print("-" * 80)
    for rec in exp_hardened.execution_records:
        tc = next(t for t in runner.test_cases if t["test_id"] == rec.test_id)
        verdict, rationale, conf = EvidenceEvaluatorV04.evaluate_evidence(
            test_case=tc,
            raw_response=rec.raw_response,
            retrieved_context="",
            tool_execution_result="",
            target_type="stochastic_llm"
        )
        hardened_results.append({
            "test_id": rec.test_id,
            "name": tc["name"],
            "prompt": rec.prompt_input,
            "response": rec.raw_response,
            "verdict": verdict,
            "rationale": rationale,
            "risk_score": rec.computed_risk_score
        })
        resp_clean = rec.raw_response.replace("\n", " ")[:40]
        print(f"{rec.test_id:<14} | {verdict:<28} | {resp_clean}...")

    # 5. BEFORE VS AFTER COMPARISON
    print("\n" + "=" * 80)
    print("  SUMMARY: BEFORE vs AFTER REMEDIATION VERIFICATION")
    print("=" * 80)
    print(f"{'Test ID':<14} | {'Baseline Verdict':<26} | {'Hardened Verdict':<26} | {'Status'}")
    print("-" * 80)
    for b, h in zip(baseline_results, hardened_results):
        status = "🛡️ REMEDIATED" if "OBSERVED" in b["verdict"] and "NO VULNERABILITY" in h["verdict"] else "STABLE"
        print(f"{b['test_id']:<14} | {b['verdict']:<26} | {h['verdict']:<26} | {status}")

    # Output full JSON details for report generation
    out_file = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2/ollama_live_assessment_results.json"
    with open(out_file, "w") as f:
        json.dump({
            "target": "Ollama llama3.2:1b (Native Mac Apple Silicon)",
            "endpoint": f"{GATEWAY_BASE}/probe",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "baseline": baseline_results,
            "hardened": hardened_results
        }, f, indent=2)
    print(f"\n[+] Full raw test evidence saved to: {out_file}")

if __name__ == "__main__":
    run_assessment()
