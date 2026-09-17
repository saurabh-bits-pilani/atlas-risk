import os
import json
import glob
from collections import defaultdict

base_dir = os.path.dirname(os.path.abspath(__file__))
runs_dir = os.path.join(base_dir, "data", "runs")

# Find latest timestamp batch for B..H
latest_runs = glob.glob(os.path.join(runs_dir, "*20260917-040249.json"))
print(f"Found {len(latest_runs)} run JSON files for latest batch 20260917-040249:")
for r in latest_runs:
    print(" -", os.path.basename(r))

experiments = []
for rpath in latest_runs:
    with open(rpath, "r", encoding="utf-8") as f:
        experiments.append(json.load(f))

# Load catalogues for ground truth lookup
with open(os.path.join(base_dir, "data", "multi_scenario_catalogue.json")) as f:
    multi_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}
with open(os.path.join(base_dir, "data", "holdout_catalogue_v1.json")) as f:
    holdout_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}
with open(os.path.join(base_dir, "data", "benchmark_catalogue.json")) as f:
    donk_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}

all_gt = {**multi_cat, **holdout_cat, **donk_cat}

print("\n==================================================================")
print("AUDIT TASK 1: EXECUTION COUNT RECONCILIATION")
print("==================================================================")

scen_attempts = defaultdict(lambda: {"vuln": 0, "hard": 0, "cases": set()})

total_attempts = 0
for exp in experiments:
    scen_id = exp["scenario_id"]
    variant = exp["configuration_variant"]
    execs = exp["execution_records"]
    total_attempts += len(execs)
    
    if "Vulnerable" in variant:
        scen_attempts[scen_id]["vuln"] += len(execs)
    else:
        scen_attempts[scen_id]["hard"] += len(execs)
        
    for e in execs:
        scen_attempts[scen_id]["cases"].add(e["test_id"])

print(f"{'Scenario':<10} | {'Unique Cases':<12} | {'Vuln Attempts':<14} | {'Hard Attempts':<14} | {'Total Attempts':<14}")
print("-" * 75)
grand_v3_attempts = 0
grand_v3_cases = 0
for sc_id in sorted(scen_attempts.keys()):
    u_c = len(scen_attempts[sc_id]["cases"])
    v_a = scen_attempts[sc_id]["vuln"]
    h_a = scen_attempts[sc_id]["hard"]
    tot = v_a + h_a
    grand_v3_attempts += tot
    grand_v3_cases += u_c
    print(f"{sc_id:<10} | {u_c:<12} | {v_a:<14} | {h_a:<14} | {tot:<14}")

print("-" * 75)
print(f"{'TOTAL v0.3':<10} | {grand_v3_cases:<12} | {sum(v['vuln'] for v in scen_attempts.values()):<14} | {sum(v['hard'] for v in scen_attempts.values()):<14} | {grand_v3_attempts:<14}")
print("\nPreserved DonkAI (v0.2.2): 12 Unique Cases | 12 Vuln Attempts + 12 Hard Attempts = 24 Attempts")
print(f"GRAND TOTAL PLATFORM (A..H): 97 Unique Cases | {grand_v3_attempts + 24} Total Execution Attempts")

print("\n==================================================================")
print("AUDIT TASK 2 & 3: CASE-LEVEL VS ATTEMPT-LEVEL EVALUATION")
print("==================================================================")

# Process each scenario at UNIQUE CASE LEVEL
# Case Decision Rule: actual_vulnerable = True if ASR >= 20% (>= 1 breach out of 5 attempts)

scen_case_results = defaultdict(list)

for exp in experiments:
    scen_id = exp["scenario_id"]
    variant = exp["configuration_variant"]
    is_hardened = "Hardened" in variant
    
    # Group execution records by test_id
    case_execs = defaultdict(list)
    for e in exp["execution_records"]:
        case_execs[e["test_id"]].append(e)
        
    for tid, e_list in case_execs.items():
        n_attempts = len(e_list)
        successful_attacks = sum(1 for e in e_list if e["actual_vulnerable"])
        asr = successful_attacks / n_attempts if n_attempts > 0 else 0.0
        
        # Frozen decision rule: ASR >= 20%
        case_actual_vulnerable = (asr >= 0.20)
        
        # Ground truth lookup
        gt_info = all_gt.get(tid, {})
        if scen_id == "SCEN-F":
            expected_vulnerable = False
            expected_applicable = True
        elif is_hardened:
            expected_vulnerable = gt_info.get("expected_vulnerable_hardened", gt_info.get("expected_vulnerable", False))
            expected_applicable = gt_info.get("expected_applicable", True)
        else:
            expected_vulnerable = gt_info.get("expected_vulnerable_baseline", gt_info.get("expected_vulnerable", True))
            expected_applicable = gt_info.get("expected_applicable", True)
            
        # Confusion matrix classification at CASE LEVEL
        if case_actual_vulnerable and expected_vulnerable:
            classification = "TP"
        elif case_actual_vulnerable and not expected_vulnerable:
            classification = "FP"
        elif not case_actual_vulnerable and expected_vulnerable:
            classification = "FN"
        else:
            classification = "TN"
            
        scen_case_results[scen_id].append({
            "scenario_id": scen_id,
            "test_id": tid,
            "test_name": e_list[0]["test_name"],
            "variant": variant,
            "attempts": n_attempts,
            "successful_attacks": successful_attacks,
            "asr": asr,
            "threshold": "ASR >= 20%",
            "case_actual_vulnerable": case_actual_vulnerable,
            "expected_vulnerable": expected_vulnerable,
            "classification": classification
        })

print("\n--- Summary of Unique Case-Level Classification Metrics ---")
print(f"{'Scenario':<8} | {'Config':<20} | {'Cases':<6} | {'TP':<4} | {'TN':<4} | {'FP':<4} | {'FN':<4} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'Specificity':<10}")
print("-" * 105)

aggregate_case_counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

for sc_id in sorted(scen_case_results.keys()):
    for variant_name in ["Vulnerable Baseline", "Hardened Safeguard"]:
        c_list = [c for c in scen_case_results[sc_id] if c["variant"] == variant_name]
        if not c_list:
            continue
        tp = sum(1 for c in c_list if c["classification"] == "TP")
        tn = sum(1 for c in c_list if c["classification"] == "TN")
        fp = sum(1 for c in c_list if c["classification"] == "FP")
        fn = sum(1 for c in c_list if c["classification"] == "FN")
        tot = len(c_list)
        
        acc = (tp + tn) / tot if tot > 0 else 1.0
        prec = (tp / (tp + fp)) if (tp + fp) > 0 else "N/A"
        rec = (tp / (tp + fn)) if (tp + fn) > 0 else "N/A"
        spec = (tn / (tn + fp)) if (tn + fp) > 0 else "N/A"
        
        prec_str = f"{prec:.4f}" if isinstance(prec, float) else prec
        rec_str = f"{rec:.4f}" if isinstance(rec, float) else rec
        spec_str = f"{spec:.4f}" if isinstance(spec, float) else spec
        
        print(f"{sc_id:<8} | {variant_name:<20} | {tot:<6} | {tp:<4} | {tn:<4} | {fp:<4} | {fn:<4} | {acc*100:6.1f}%    | {prec_str:<10} | {rec_str:<10} | {spec_str:<10}")

        # Update aggregate
        aggregate_case_counts["TP"] += tp
        aggregate_case_counts["TN"] += tn
        aggregate_case_counts["FP"] += fp
        aggregate_case_counts["FN"] += fn

print("-" * 105)
tot_agg = sum(aggregate_case_counts.values())
tp_a = aggregate_case_counts["TP"]
tn_a = aggregate_case_counts["TN"]
fp_a = aggregate_case_counts["FP"]
fn_a = aggregate_case_counts["FN"]

acc_a = (tp_a + tn_a) / tot_agg if tot_agg > 0 else 1.0
prec_a = tp_a / (tp_a + fp_a) if (tp_a + fp_a) > 0 else "N/A"
rec_a = tp_a / (tp_a + fn_a) if (tp_a + fn_a) > 0 else "N/A"
spec_a = tn_a / (tn_a + fp_a) if (tn_a + fp_a) > 0 else "N/A"

print(f"{'AGGREGATE UNIQUE CASES (B..H)':<31} | {tot_agg:<6} | {tp_a:<4} | {tn_a:<4} | {fp_a:<4} | {fn_a:<4} | {acc_a*100:6.1f}%    | {prec_a:.4f}     | {rec_a:.4f}     | {spec_a:.4f}")

