# 🛡️ ATLAS-Risk POC: LLM Threat Mapping & Security Evaluator

A minimal, research-oriented Proof-of-Concept (POC) designed to evaluate LLM application security risks using deterministic rules, explicit framework versioning, benchmark ground-truth assertions, and structured telemetry logs.

---

## 📌 Research Workflow

```text
Questionnaire (10 System Security Profile Questions)
        ↓
Threat Applicability Engine (Stage 1: Rule-Based OWASP 2025 & MITRE ATLAS v4.0 Mapping)
        ↓
Predefined DonkAI Benchmark Test Harness (Stage 2: Static Vectors & Assertions)
        ↓
Evidence Telemetry Recorder (Ground Truth Metrics: Accuracy, Precision, Recall, F1)
        ↓
Deterministic Risk Engine (Stage 3: Risk = Likelihood × Impact × Exposure)
        ↓
Structured Executive Risk Report & Audit Telemetry JSON Export
```

---

## 🎯 Key Architectural Refinements

1. **Framework Versioning:** Explicitly versioned data in `mappings/owasp_2025.json` (`OWASP LLM Top 10 2025`) and `mappings/atlas_v4.json` (`MITRE ATLAS v4.0`).
2. **Three-Output Pipeline:** Explicit separation between:
   - **Stage 1:** *Threat Applicability*
   - **Stage 2:** *Observed Test Finding*
   - **Stage 3:** *Final Risk Score & Severity Rating*
3. **Structured Telemetry:** `EvidenceRecord` dataclass capturing prompt inputs, raw target outputs, assertion results, ground-truth flags, and taxonomy mappings.
4. **Deterministic Decision Core:** 100% rule-based mapping and mathematical risk scoring ($Risk = Likelihood \times Impact \times Exposure$). AI APIs are restricted exclusively to the optional natural language explanation layer.
5. **Ground Truth Benchmark Metrics:** Calculates True Positives, False Positives, False Negatives, Precision, Recall, Accuracy, and F1 Score against baseline target definitions (`tests/test_cases.json`).

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Automated Unit Tests
```bash
pytest tests/test_poc_core.py -v
```

### 3. Launch Streamlit Web UI
```bash
streamlit run app.py
```

---

## 📁 Repository Structure

```text
atlas-risk-poc/
├── app.py                  # Main Streamlit web UI entry point
├── questionnaire.py        # 10 system security profile questions & inputs
├── threat_mapper.py        # Stage 1 deterministic threat applicability & mapping engine
├── test_runner.py          # Stage 2 controlled test runner executing predefined benchmarks
├── risk_engine.py          # Stage 3 deterministic risk engine (Risk = L x I x E)
├── evidence.py             # Telemetry data model & ground-truth metrics evaluator
├── report.py               # Stage 4 report generator & narrative explanation bridge
├── mappings/
│   ├── owasp_2025.json     # OWASP LLM Top 10 (2025) versioned taxonomy
│   └── atlas_v4.json       # MITRE ATLAS v4.0 versioned taxonomy
├── tests/
│   ├── test_cases.json     # Predefined DonkAI test cases with ground-truth labels
│   └── test_poc_core.py    # Pytest unit test suite
├── requirements.txt        # Dependencies
└── README.md               # Project documentation
```
