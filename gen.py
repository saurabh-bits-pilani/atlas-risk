import json

with open('data/multi_scenario_catalogue.json') as f:
    bg = json.load(f)['test_cases']
with open('data/holdout_catalogue_v1.json') as f:
    h = json.load(f)['test_cases']

for t in h:
    t['scenario_id'] = 'SCEN-H'
    t['source'] = 'data/holdout_catalogue_v1.json'

for t in bg:
    t['source'] = 'data/multi_scenario_catalogue.json'

all_85 = bg + h

lines = []
lines.append('| Scenario | Test ID | Threat Family | Architecture | Expected Applicability | Ground Truth | Configuration | Repeats | Source | Version |')
lines.append('| :--- | :--- | :--- | :--- | :---: | :--- | :--- | :---: | :--- | :---: |')

for t in all_85:
    scen = t.get('scenario_id', 'SCEN-B')
    tid = t.get('test_id', '')
    tf = t.get('threat_family', 'N/A')
    arch = t.get('target_architecture', 'N/A')
    app = 'Applicable' if t.get('expected_applicable', True) else 'Not Applicable'
    
    vb = t.get('expected_vulnerable_baseline', True)
    vh = t.get('expected_vulnerable_hardened', False)
    gt = 'Expected Non-Vulnerable' if scen == 'SCEN-F' else f"Base: {'Vuln' if vb else 'Prot'} / Hard: {'Vuln' if vh else 'Prot'}"
    config = 'Hardened Only' if scen == 'SCEN-F' else 'Vulnerable + Hardened'
    repeats = 1 if scen == 'SCEN-G' else 5
    src = t.get('source', '').split('/')[-1]
    ver = t.get('test_case_version', '1.0.0')
    
    lines.append(f"| **{scen}** | `{tid}` | {tf} | {arch} | {app} | {gt} | {config} | {repeats} | `{src}` | `{ver}` |")

with open('matrix_table_out.md', 'w') as f:
    f.write('\n'.join(lines))

print(f"Generated matrix_table_out.md with {len(all_85)} test cases.")
