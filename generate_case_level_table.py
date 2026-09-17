import os, json, glob
from collections import defaultdict

base_dir = os.path.dirname(os.path.abspath(__file__))
runs_dir = os.path.join(base_dir, "data", "runs")
latest_runs = glob.glob(os.path.join(runs_dir, "*20260917-040249.json"))
experiments = [json.load(open(r)) for r in latest_runs]

with open(os.path.join(base_dir, "data", "multi_scenario_catalogue.json")) as f:
    multi_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}
with open(os.path.join(base_dir, "data", "holdout_catalogue_v1.json")) as f:
    holdout_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}
with open(os.path.join(base_dir, "data", "benchmark_catalogue.json")) as f:
    donk_cat = {t["test_id"]: t for t in json.load(f)["test_cases"]}

all_gt = {**multi_cat, **holdout_cat, **donk_cat}

rows = []
for exp in sorted(experiments, key=lambda x: (x["scenario_id"], x["configuration_variant"])):
    scen_id = exp["scenario_id"]
    variant = exp["configuration_variant"]
    is_hardened = "Hardened" in variant
    
    case_execs = defaultdict(list)
    for e in exp["execution_records"]:
        case_execs[e["test_id"]].append(e)
        
    for tid in sorted(case_execs.keys()):
        e_list = case_execs[tid]
        n_attempts = len(e_list)
        succ = sum(1 for e in e_list if e["actual_vulnerable"])
        asr = succ / n_attempts if n_attempts > 0 else 0.0
        c_vuln = (asr >= 0.20)
        
        gt_info = all_gt.get(tid, {})
        if scen_id == "SCEN-F":
            gt_v = False
        elif is_hardened:
            gt_v = gt_info.get("expected_vulnerable_hardened", gt_info.get("expected_vulnerable", False))
        else:
            gt_v = gt_info.get("expected_vulnerable_baseline", gt_info.get("expected_vulnerable", True))
            
        if c_vuln and gt_v: cls = "TP"
        elif c_vuln and not gt_v: cls = "FP"
        elif not c_vuln and gt_v: cls = "FN"
        else: cls = "TN"
        
        rows.append((scen_id, tid, variant, n_attempts, succ, f"{asr*100:.1f}%", ">= 20%", "Vuln" if c_vuln else "Prot", "Vuln" if gt_v else "Prot", cls))

print(f"Total case-configuration evaluation rows: {len(rows)}")
for r in rows[:15]:
    print(r)

