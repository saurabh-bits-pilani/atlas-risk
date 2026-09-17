import os
import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ ATLAS-Risk v0.4.0-dev — Enterprise AI Security Platform</title>
    <style>
        :root {
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #ffffff;
            --accent: #58a6ff;
            --green: #238636;
            --green-hover: #2ea043;
            --badge-bg: #1f6feb22;
            --badge-text: #58a6ff;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }

        .header {
            background-color: var(--card-bg);
            border-bottom: 1px solid var(--border);
            padding: 24px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            margin: 0;
            font-size: 24px;
            color: var(--heading);
        }

        .status-badge {
            background: #23863622;
            color: #3fb950;
            border: 1px solid #23863688;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }

        .container {
            max-width: 1000px;
            margin: 40px auto;
            padding: 0 20px;
        }

        .hero-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 30px;
        }

        .hero-card h2 {
            margin-top: 0;
            color: var(--heading);
            font-size: 28px;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 24px 0;
        }

        .metric-card {
            background: #0d1117;
            border: 1px solid var(--border);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }

        .metric-value {
            font-size: 28px;
            font-weight: bold;
            color: var(--accent);
        }

        .metric-label {
            font-size: 13px;
            color: #8b949e;
            margin-top: 4px;
        }

        .actions {
            display: flex;
            gap: 16px;
            margin-top: 24px;
            flex-wrap: wrap;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            text-decoration: none;
            transition: background-color 0.2s;
        }

        .btn-primary {
            background-color: var(--green);
            color: #ffffff;
        }

        .btn-primary:hover {
            background-color: var(--green-hover);
        }

        .btn-secondary {
            background-color: #21262d;
            color: var(--heading);
            border: 1px solid var(--border);
        }

        .btn-secondary:hover {
            background-color: #30363d;
        }

        .info-section {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .info-section h3 {
            margin-top: 0;
            color: var(--heading);
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
        }

        ul {
            padding-left: 20px;
        }

        li {
            margin-bottom: 10px;
        }

        code {
            font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
            background: #21262d;
            color: #79c0ff;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 85%;
        }

        .footer {
            text-align: center;
            color: #8b949e;
            font-size: 13px;
            margin-top: 40px;
            padding-bottom: 40px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ATLAS-Risk Security Platform</h1>
        <span class="status-badge">v0.4.0-dev BETA READY</span>
    </div>

    <div class="container">
        <div class="hero-card">
            <h2>New AI System Assessment & Threat Applicability Engine</h2>
            <p>ATLAS-Risk provides dynamic, framework-mapped application security assessments for enterprise AI applications, RAG architectures, and autonomous agentic workflows.</p>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">24</div>
                    <div class="metric-label">Assessment Questions</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">8</div>
                    <div class="metric-label">Applicable Threat Families</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">3</div>
                    <div class="metric-label">Multi-Attribute Verdicts</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">20/20</div>
                    <div class="metric-label">Acceptance Suite Passed</div>
                </div>
            </div>

            <div class="actions">
                <a href="https://atlas-risk.streamlit.app" target="_blank" class="btn btn-primary">🚀 Launch Streamlit Web App</a>
                <a href="https://github.com/saurabh-bits-pilani/atlas-risk" target="_blank" class="btn btn-secondary">📦 GitHub Repository</a>
            </div>
        </div>

        <div class="info-section">
            <h3>🔑 Core Architectural Modules</h3>
            <ul>
                <li><strong>Interactive System Profile Questionnaire:</strong> 24-question architectural profiling across 7 core security domains.</li>
                <li><strong>Dynamic Threat Applicability Engine:</strong> Stage-1 rule-based mapping to OWASP LLM Top 10 (2025) and MITRE ATLAS (v4.0).</li>
                <li><strong>Active Testing Safety Gate:</strong> Blocks unauthorized penetration testing and requires mandatory 4-point scope verification.</li>
                <li><strong>Multi-Attribute Evidence Evaluator (v0.4):</strong> Evaluates raw responses, negation terms, RAG context, and agent tool execution traces.</li>
                <li><strong>3 Explicit Verdict Statuses:</strong> <code>🔴 VULNERABILITY OBSERVED</code> | <code>🟢 NO VULNERABILITY OBSERVED</code> | <code>⚠️ INCONCLUSIVE / MANUAL REVIEW</code>.</li>
                <li><strong>Post-Remediation Workflow:</strong> <code>SIMULATED MITIGATION RETEST</code> and <code>LIVE RETEST</code> verification.</li>
            </ul>
        </div>

        <div class="info-section">
            <h3>💻 Local Terminal Execution</h3>
            <p>To run the full interactive application locally on your machine:</p>
            <pre><code>cd "/Users/saurabhiim/Documents/01_YEAR_2026_ACTIVE/Antigravity/atlas-risk.taegisai.space"
streamlit run app.py</code></pre>
        </div>

        <div class="footer">
            ATLAS-Risk v0.4.0-dev | Research Freeze v0.3.0 Preserved | Developed for Academic & Enterprise Security Assessment
        </div>
    </div>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
        return


app = handler
