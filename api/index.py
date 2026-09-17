import os
import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        files_dict = {}
        file_paths = [
            "app.py",
            "app_v01.py",
            "questionnaire.py",
            "questionnaire_ui.py",
            "evidence.py",
            "threat_mapper.py",
            "risk_engine.py",
            "test_runner.py",
            "report.py",
            "models/experiment_models.py",
            "engines/threat_mapper.py",
            "engines/test_runner.py",
            "engines/risk_engine.py",
            "engines/evaluation_engine.py",
            "engines/evidence_evaluator_v04.py",
            "engines/baseline_comparator.py",
            "engines/persistence_engine.py",
            "engines/multi_scenario_runner.py",
            "reports/report_v02.py",
            "reports/report_v03.py",
            "data/benchmark_catalogue.json",
            "data/test_cases.json",
            "mappings/owasp_2025.json",
            "mappings/atlas_v4.json"
        ]

        for rel_path in file_paths:
            full_p = os.path.join(base_dir, rel_path)
            if os.path.exists(full_p):
                with open(full_p, "r", encoding="utf-8") as f:
                    files_dict[rel_path] = f.read()

        stlite_files_json = json.dumps(files_dict)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ ATLAS-Risk v0.4.0-dev — Enterprise AI Risk Assessment</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@stlite/mountable@0.50.0/build/stlite.css" />
    <style>
        html, body {{ margin: 0; padding: 0; width: 100%; height: 100%; background-color: #0e1117; overflow: hidden; }}
        #root {{ width: 100%; height: 100%; }}
    </style>
</head>
<body>
    <div id="root"></div>
    <script src="https://cdn.jsdelivr.net/npm/@stlite/mountable@0.50.0/build/stlite.js"></script>
    <script>
        stlite.mount({{
            entrypoint: "app.py",
            files: {stlite_files_json}
        }}, document.getElementById("root"));
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        return


app = handler
