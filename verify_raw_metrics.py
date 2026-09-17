import os, json, glob
from collections import defaultdict

base_dir = os.path.dirname(os.path.abspath(__file__))
runs_dir = os.path.join(base_dir, "data", "runs")
latest_runs = glob.glob(os.path.join(runs_dir, "*20260917-040249.json"))

# Load all raw execution records directly from disk
experiments = [json.load(open(r)) for r in latest_runs]

# Load catalog ground truths
with open(os.path.join(base_dir, "data", "multi_scenario_catalogue.json")) as f:
    multi_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}
with open(os.path.join(base_dir, "data", "holdout_catalogue_v1.json")) as f:
    holdout_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}

all_gt = {**multi_cat, **holdout_cat}

tp, tn, fp, fn = 0, 0, 0, 0
case_evaluations = 0

for exp in experiments:
    scen_id = exp["scenario_id"]
    variant = exp["configuration_variant"]
    is_hardened = "Hardened" in variant
    
    # Group execution records by test_id
    case_execs = defaultdict(list)
    for e in exp["execution_records"]:
        case_execs[e["test_id"]].append(e)
        
    for tid, e_list in case_execs.items():
        case_evaluations += 1
        n_attempts = len(e_list)
        succ = sum(1 for e in e_list if e["actual_vulnerable"])
        asr = succ / n_attempts if n_attempts > 0 else 0.0
        
        # Frozen decision rule: ASR >= 20%
        c_vuln = (asr >= 0.20)
        
        gt_info = all_gt.get(tid, {})
        if scen_id == "SCEN-F":
            gt_v = False
        elif is_hardened:
            gt_v = gt_info.get("expected_vulnerable_hardened", gt_info.get("expected_vulnerable", False))
        else:
            gt_v = gt_info.get("expected_vulnerable_baseline", gt_info.get("expected_vulnerable", True))
            
        if c_vuln and gt_v:
            tp += 1
        elif c_vuln and not gt_v:
            fp += 1
        elif not c_vuln and gt_v:
            fn += 1
        else:
            tn += 1

total = tp + tn + fp + fn
accuracy = (tp + tn) / total
precision = tp / (tp + fp)
recall = tp / (tp + fn)
specificity = tn / (tn + fp)
f1 = (2 * precision * recall) / (precision + recall)

print("==================================================================")
print("INDEPENDENT METRIC VERIFICATION FROM RAW RECORD FILES")
print("==================================================================")
print(f"Total Unique Case-Target Evaluations: {total}")
print(f"TP = {tp}")
print(f"TN = {tn}")
print(f"FP = {fp}")
print(f"FN = {fn}")
print("-" * 50)
print(f"Accuracy    = {accuracy*100:.2f}%  (Exact: {accuracy:.6f})")
print(f"Precision   = {precision*100:.2f}%  (Exact: {precision:.6f})")
print(f"Recall      = {recall*100:.2f}%  (Exact: {recall:.6f})")
print(f"Specificity = {specificity*100:.2f}%  (Exact: {specificity:.6f})")
print(f"F1 Score    = {f1*100:.2f}%  (Exact: {f1:.6f})")
print("-" * 50)

# Verify against expected values:
assert tp == 42, f"Expected TP=42, got {tp}"
assert tn == 113, f"Expected TN=113, got {tn}"
assert fp == 1, f"Expected FP=1, got {fp}"
assert fn == 4, f"Expected FN=4, got {fn}"
assert abs(accuracy - 0.96875) < 0.0001, f"Accuracy mismatch: {accuracy}"
assert abs(precision - (42/43)) < 0.0001, f"Precision mismatch: {precision}"
assert abs(recall - (42/46)) < 0.0001, f"Recall mismatch: {recall}"
assert abs(specificity - (113/114)) < 0.0001, f"Specificity mismatch: {specificity}"

print("✅ VERIFICATION SUCCESSFUL: All raw records independently recalculate to exact reported metrics!")
