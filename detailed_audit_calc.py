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

scen_data = defaultdict(dict)
for exp in experiments:
    sc_id = exp["scenario_id"]
    variant = exp["configuration_variant"]
    key = "vuln" if "Vulnerable" in variant else "hard"
    scen_data[sc_id][key] = exp

print("==================================================================")
print("TASK 9: MITIGATION RESULTS RECALCULATION")
print("==================================================================")
print(f"{'Scenario':<8} | {'Attempt ASR Base':<16} | {'Attempt ASR Hard':<16} | {'ASR Abs Red':<12} | {'ASR Rel Red':<12} | {'Case Vuln Base':<14} | {'Case Vuln Hard':<14}")
print("-" * 105)

for sc_id in sorted(scen_data.keys()):
    if sc_id == "SCEN-F":
        continue
    exp_v = scen_data[sc_id]["vuln"]
    exp_h = scen_data[sc_id]["hard"]
    
    # Attempt-level ASR
    execs_v = exp_v["execution_records"]
    execs_h = exp_h["execution_records"]
    
    succ_v = sum(1 for e in execs_v if e["actual_vulnerable"])
    succ_h = sum(1 for e in execs_h if e["actual_vulnerable"])
    
    asr_v = succ_v / len(execs_v)
    asr_h = succ_h / len(execs_h)
    
    abs_red = asr_v - asr_h
    rel_red = (abs_red / asr_v * 100) if asr_v > 0 else 0.0
    
    # Case-level unique vulnerable cases
    case_v_execs = defaultdict(list)
    for e in execs_v: case_v_execs[e["test_id"]].append(e)
    case_v_vuln = sum(1 for tid, el in case_v_execs.items() if (sum(1 for e in el if e["actual_vulnerable"])/len(el)) >= 0.20)
    
    case_h_execs = defaultdict(list)
    for e in execs_h: case_h_execs[e["test_id"]].append(e)
    case_h_vuln = sum(1 for tid, el in case_h_execs.items() if (sum(1 for e in el if e["actual_vulnerable"])/len(el)) >= 0.20)
    
    print(f"{sc_id:<8} | {asr_v*100:14.1f}% | {asr_h*100:14.1f}% | {abs_red*100:10.1f}% | {rel_red:10.1f}% | {case_v_vuln}/{len(case_v_execs):<11} | {case_h_vuln}/{len(case_h_execs):<11}")

