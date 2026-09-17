"""
Unified PDF and HTML Report Exporter for ATLAS-Risk.
Generates:
1. Print-ready, publication-quality A4 PDF using Playwright Chromium.
2. Standalone, responsive HTML report.
Guarantees:
- Escapes all untrusted content (no execution of website or model text as markup).
- Wraps long URLs and code snippets cleanly.
- Renders page numbers, headers, and footers.
- Parity: PDF, HTML, and on-screen results stem from the exact same saved assessment record.
"""

import os
import html
import re
from typing import Dict, Any, Tuple
from playwright.sync_api import sync_playwright

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(WORKSPACE_DIR, "data", "exports")
os.makedirs(EXPORTS_DIR, exist_ok=True)


def sanitize(text: Any) -> str:
    if text is None:
        return ""
    return html.escape(str(text))


def generate_html_report(record: Dict[str, Any]) -> str:
    """Generates a standalone, secure, responsive HTML report."""
    rec_id = sanitize(record.get("id", "ASM-REPORT"))
    name = sanitize(record.get("name", "Assessment Report"))
    target = sanitize(record.get("target_input", record.get("target_url", "Target")))
    created_at = sanitize(record.get("created_at", ""))
    status = sanitize(record.get("status", "COMPLETE"))
    summary = sanitize(record.get("summary", "No summary provided."))
    counts = record.get("counts", {})

    status_badge_class = "badge-complete" if status == "COMPLETE" else ("badge-partial" if status == "PARTIAL" else "badge-stopped")

    findings = record.get("findings", [])
    positives = record.get("positive_observations", [])
    unassessed = record.get("unassessed_areas", [])
    next_steps = record.get("next_steps", record.get("next_steps_required_access", []))

    findings_html = []
    if not findings:
        findings_html.append("<div class='empty-note'>No issues observed within the tested scope.</div>")
    else:
        for idx, f in enumerate(findings, 1):
            sev = sanitize(f.get("severity", "MEDIUM")).upper()
            sev_class = "sev-high" if "HIGH" in sev or "CRIT" in sev else ("sev-med" if "MED" in sev else "sev-low")
            findings_html.append(f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="finding-title">{sanitize(f.get('title', f.get('issue', 'Issue')))}</span>
                    <span class="badge {sev_class}-badge">{sev}</span>
                </div>
                <div class="finding-body">
                    <p><strong>What we observed:</strong> {sanitize(f.get('observed', f.get('evidence', '')))}</p>
                    <p><strong>Why it matters:</strong> {sanitize(f.get('why_it_matters', 'Affects system resilience and user privacy.'))}</p>
                    <div class="finding-action">
                        <strong>Recommended action:</strong>
                        <code>{sanitize(f.get('action', f.get('fix', '')))}</code>
                    </div>
                    {f'<p class="verify-note"><strong>How to verify:</strong> {sanitize(f.get("how_to_verify"))}</p>' if f.get("how_to_verify") else ''}
                </div>
            </div>
            """)

    positives_html = []
    for p in positives:
        positives_html.append(f"""
        <li>
            <strong>[{sanitize(p.get('area', 'Observation'))}]</strong> {sanitize(p.get('observation', ''))}
            <br><span class="evidence-subtext">Evidence: <code>{sanitize(p.get('evidence', ''))}</code></span>
        </li>
        """)

    unassessed_html = []
    for u in unassessed:
        unassessed_html.append(f"""
        <div class="unassessed-card">
            <strong>Area:</strong> <code>{sanitize(u.get('area', 'Protected Area'))}</code>
            <p><strong>Reason:</strong> {sanitize(u.get('reason', 'Access barrier or authentication required.'))}</p>
            <p><strong>Required Access:</strong> <em>{sanitize(u.get('required_access', 'Provide credentials or API access.'))}</em></p>
        </div>
        """)

    next_steps_html = "".join([f"<li>{sanitize(step)}</li>" for step in next_steps])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ATLAS-Risk Report - {name}</title>
<style>
    @page {{
        size: A4 portrait;
        margin: 15mm 15mm 18mm 15mm;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #1e293b;
        background: #ffffff;
        font-size: 10pt;
        line-height: 1.5;
        margin: 0;
        padding: 0;
    }}
    .report-header {{
        border-bottom: 2px solid #0f172a;
        padding-bottom: 12px;
        margin-bottom: 18px;
    }}
    .report-title {{
        font-size: 18pt;
        font-weight: 800;
        color: #0f172a;
        margin: 0 0 4px 0;
    }}
    .report-meta {{
        font-size: 8.5pt;
        color: #64748b;
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin-top: 6px;
    }}
    .badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 7.5pt;
        font-weight: 700;
        text-transform: uppercase;
    }}
    .badge-complete {{ background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }}
    .badge-partial {{ background: #fef9c3; color: #854d0e; border: 1px solid #fef08a; }}
    .badge-stopped {{ background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }}
    
    .counts-grid {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 10px;
        margin: 14px 0 20px 0;
    }}
    .count-card {{
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 10px 12px;
        text-align: center;
    }}
    .count-val {{ font-size: 18pt; font-weight: 800; color: #0f172a; margin-bottom: 2px; }}
    .count-lbl {{ font-size: 7.5pt; text-transform: uppercase; color: #64748b; font-weight: 600; }}

    .summary-box {{
        background: #f1f5f9;
        border-left: 4px solid #3b82f6;
        padding: 12px 16px;
        border-radius: 4px;
        margin-bottom: 20px;
        font-size: 9.5pt;
    }}

    h2 {{
        font-size: 12pt;
        font-weight: 700;
        color: #0f172a;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 4px;
        margin-top: 22px;
        margin-bottom: 10px;
        page-break-after: avoid;
    }}

    .finding-card {{
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        margin-bottom: 12px;
        overflow: hidden;
        page-break-inside: avoid;
    }}
    .finding-card.sev-high {{ border-left: 4px solid #ef4444; }}
    .finding-card.sev-med {{ border-left: 4px solid #f59e0b; }}
    .finding-card.sev-low {{ border-left: 4px solid #3b82f6; }}

    .finding-header {{
        background: #f8fafc;
        padding: 8px 12px;
        border-bottom: 1px solid #e2e8f0;
        display: flex;
        align-items: center;
        gap: 8px;
    }}
    .finding-num {{ font-weight: 800; color: #64748b; font-size: 8.5pt; }}
    .finding-title {{ font-weight: 700; color: #0f172a; font-size: 9.5pt; flex-grow: 1; }}
    .sev-high-badge {{ background: #fee2e2; color: #991b1b; }}
    .sev-med-badge {{ background: #fef3c7; color: #92400e; }}
    .sev-low-badge {{ background: #e0f2fe; color: #075985; }}

    .finding-body {{ padding: 10px 12px; font-size: 9pt; }}
    .finding-body p {{ margin: 4px 0 6px 0; }}
    .finding-action {{
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 6px 8px;
        margin-top: 8px;
    }}
    code {{
        font-family: "SFMono-Regular", Consolas, Menlo, monospace;
        font-size: 8pt;
        background: #f1f5f9;
        padding: 2px 4px;
        border-radius: 3px;
        word-break: break-all;
    }}
    .verify-note {{ font-size: 8pt; color: #475569; margin-top: 4px; }}

    .unassessed-card {{
        background: #fffbeb;
        border: 1px solid #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 8px 12px;
        border-radius: 4px;
        margin-bottom: 8px;
        font-size: 8.5pt;
        page-break-inside: avoid;
    }}
    .unassessed-card p {{ margin: 3px 0; }}
    .evidence-subtext {{ font-size: 8pt; color: #64748b; }}
    .empty-note {{ color: #16a34a; font-style: italic; padding: 6px 0; }}
    ul {{ margin: 6px 0 12px 18px; padding: 0; font-size: 9pt; }}
    li {{ margin-bottom: 6px; }}
</style>
</head>
<body>

<div class="report-header">
    <div class="report-title">ATLAS-Risk Assessment Report</div>
    <div class="report-meta">
        <span><strong>Target:</strong> <code>{target}</code></span>
        <span><strong>Report ID:</strong> {rec_id}</span>
        <span><strong>Date:</strong> {created_at[:19].replace('T', ' ')} UTC</span>
        <span><strong>Status:</strong> <span class="badge {status_badge_class}">{status}</span></span>
    </div>
</div>

<div class="counts-grid">
    <div class="count-card">
        <div class="count-val" style="color: #ef4444;">{counts.get('issues', 0)}</div>
        <div class="count-lbl">Issues Observed</div>
    </div>
    <div class="count-card">
        <div class="count-val" style="color: #10b981;">{counts.get('no_issue', 0)}</div>
        <div class="count-lbl">No Issues Observed</div>
    </div>
    <div class="count-card">
        <div class="count-val" style="color: #f59e0b;">{counts.get('not_completed', 0)}</div>
        <div class="count-lbl">Unassessed / Blocked</div>
    </div>
    <div class="count-card">
        <div class="count-val" style="color: #64748b;">{counts.get('not_applicable', 0)}</div>
        <div class="count-lbl">Not Applicable</div>
    </div>
</div>

<div class="summary-box">
    <strong>Executive Summary:</strong> {summary}
</div>

<h2>1. Observed Issues & Recommended Fixes</h2>
{"".join(findings_html)}

<h2>2. Verified Positive Observations</h2>
<ul>
{"".join(positives_html)}
</ul>

<h2>3. What We Could Not Assess & Required Access</h2>
<p style="font-size: 8.5pt; color: #64748b; margin-bottom: 8px;">
    These sections were outside the bounded public scope or required authentication. A protected resource is <strong>not a vulnerability</strong>; it represents an access boundary.
</p>
{"".join(unassessed_html)}

<h2>4. Recommended Next Steps</h2>
<ul>
{next_steps_html}
</ul>

</body>
</html>
"""
    return html_content


def export_assessment_pdf_and_html(record: Dict[str, Any]) -> Tuple[str, str]:
    """
    Renders both HTML and PDF files for an assessment record.
    Returns (pdf_path, html_path).
    """
    rec_id = record.get("id", "ASM-EXPORT")
    html_content = generate_html_report(record)

    html_file = os.path.join(EXPORTS_DIR, f"{rec_id}.html")
    pdf_file = os.path.join(EXPORTS_DIR, f"{rec_id}.pdf")

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Generate PDF with Playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page()
        page.set_content(html_content, wait_until="networkidle")

        footer_tpl = """
        <div style="font-size: 7.5pt; color: #94a3b8; width: 100%; display: flex; justify-content: space-between; padding: 0 15mm;">
            <span>ATLAS-Risk Bounded Assessment Report</span>
            <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        </div>
        """

        page.pdf(
            path=pdf_file,
            format="A4",
            print_background=True,
            margin={"top": "14mm", "bottom": "16mm", "left": "14mm", "right": "14mm"},
            display_header_footer=True,
            header_template="<div></div>",
            footer_template=footer_tpl
        )
        browser.close()

    return pdf_file, html_file
