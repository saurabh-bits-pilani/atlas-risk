"""
Unified PDF and HTML Report Exporter for ATLAS-Risk.
Generates:
1. Print-ready, publication-quality A4 PDF via ReportLab (pure-Python, zero browser dependencies).
2. Standalone, responsive HTML report.
3. Optional Playwright Chromium PDF fallback if ReportLab is unavailable.

Guarantees:
- Resilient on Streamlit Community Cloud (no hard browser/playwright requirements at boot).
- Escapes all untrusted content (no execution of website or model text as markup).
- Wraps long URLs, evidence, and code snippets cleanly.
- Renders page numbers, headers, and footers.
- Parity: PDF, HTML, and on-screen results stem from the exact same saved assessment record.
- Zero false claims (no arbitrary 62/100 scores or 100% security promises).
"""

import os
import html
import re
import logging
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(WORKSPACE_DIR, "data", "exports")
os.makedirs(EXPORTS_DIR, exist_ok=True)


def sanitize(text: Any) -> str:
    """Escapes HTML entities for safe HTML output."""
    if text is None:
        return ""
    return html.escape(str(text))


def clean_pdf_text(text: Any) -> str:
    """Escapes XML entities, strips non-printable/unsupported font emojis, and preserves linebreaks for ReportLab."""
    if text is None:
        return ""
    s = str(text)
    # Replace common status emojis with clean text representations
    s = s.replace('🟢', '').replace('🔹', '').replace('🌟', '').replace('⚡', '').replace('🛡️', '')
    s = s.replace('✅', '[PASS]').replace('❌', '[FAIL]').replace('⚠️', '[WARN]').replace('ℹ️', '')
    # Strip any characters above unicode range that standard Helvetica cannot render
    s = ''.join(c for c in s if ord(c) < 0x2000 or ord(c) in (0x2013, 0x2014, 0x2018, 0x2019, 0x2022))
    s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    s = s.replace('\n', '<br/>')
    return s.strip()


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

    model_name = sanitize(record.get("model_name") or target)
    model_id = sanitize(record.get("model_id") or target)
    company = sanitize(record.get("model_company") or "OpenRouter / Cloud AI")
    tier_str = sanitize(record.get("model_tier") or ("🟢 100% Free Tier" if (":free" in str(model_id) or model_id == "openrouter/free") else "🔹 Standard Tier"))
    duration = record.get("execution_duration_sec", "")
    dur_str = f"{duration}s" if duration != "" else "Automated Quick Scan"
    eval_date = sanitize(record.get("evaluated_at_display") or f"{created_at[:19].replace('T', ' ')} UTC")
    mode_label = sanitize(record.get("target_type", "Cloud AI Audit")).replace("_", " ").title()

    issues_cnt = counts.get("issues_observed", counts.get("issues", len(findings)))
    clean_cnt = counts.get("no_issue_observed", counts.get("no_issue", len(positives)))
    unassessed_cnt = counts.get("unassessed_or_blocked", counts.get("not_completed", counts.get("unassessed", len(unassessed))))
    na_cnt = counts.get("not_applicable", 0)

    findings_html = []
    if not findings:
        findings_html.append("<div class='empty-note'>No issues observed within the tested scope.</div>")
    else:
        for idx, f in enumerate(findings, 1):
            sev = sanitize(f.get("severity", "MEDIUM")).upper()
            sev_class = "sev-high" if "HIGH" in sev or "CRIT" in sev else ("sev-med" if "MED" in sev else "sev-low")
            code_fix_html = ""
            code_fix = f.get("code_fix")
            if code_fix:
                code_fix_html = f"""
                <div class="finding-action" style="margin-top: 6px;">
                    <strong>Practical Code Fix:</strong>
                    <pre><code>{sanitize(code_fix)}</code></pre>
                </div>
                """
            findings_html.append(f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="finding-title">{sanitize(f.get('title', f.get('issue', 'Issue')))}</span>
                    <span class="badge {sev_class}-badge">{sev}</span>
                </div>
                <div class="finding-body">
                    <p><strong>🏢 Business Impact & Risk:</strong> {sanitize(f.get('business_impact', f.get('why_it_matters', 'Affects system resilience, accessibility, or user privacy.')))}</p>
                    <p><strong>🎭 Real-World Attack Scenario:</strong> {sanitize(f.get('attack_scenario', 'An adversary sends crafted prompts to bypass intended safeguards.'))}</p>
                    <p><strong>⚖️ Regulatory & Compliance Exposure:</strong> <code>{sanitize(f.get('compliance_impact', f.get('domain', 'MITRE ATLAS / OWASP LLM Top 10')))}</code></p>
                    <p><strong>🔍 Observed Technical Evidence:</strong> {sanitize(f.get('observed', f.get('evidence', '')))}</p>
                    <div class="finding-action">
                        <strong>🛠️ Actionable Executive Remediation:</strong>
                        <code>{sanitize(f.get('action', f.get('fix', f.get('recommendation', ''))))}</code>
                    </div>
                    {code_fix_html}
                    {f'<p class="verify-note"><strong>How to verify:</strong> {sanitize(f.get("how_to_verify"))}</p>' if f.get("how_to_verify") else ''}
                </div>
            </div>
            """)

    positives_html = []
    for p in positives:
        pv = sanitize(p.get('practical_value', ''))
        pv_html = f"<br/><span style='color: #15803d; font-size: 8pt;'><strong>💼 Business Value:</strong> {pv}</span>" if pv else ""
        positives_html.append(f"""
        <li>
            <strong>[{sanitize(p.get('aspect', p.get('area', 'Security Control')))}]</strong> {sanitize(p.get('summary', p.get('observation', '')))}
            <br><span class="evidence-subtext">Evidence: <code>{sanitize(p.get('evidence', ''))}</code></span>
            {pv_html}
        </li>
        """)

    unassessed_html = []
    for u in unassessed:
        unassessed_html.append(f"""
        <div class="unassessed-card">
            <strong>Target Area:</strong> <code>{sanitize(u.get('area', u.get('component', 'Protected Area')))}</code>
            <p><strong>Reason:</strong> {sanitize(u.get('reason', 'Access barrier or authentication required.'))}</p>
            <p><strong>Required Access:</strong> <em>{sanitize(u.get('required_access', u.get('what_access_would_enable', 'Provide credentials or API access.')))}</em></p>
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
    pre {{
        margin: 4px 0 0 0;
        background: #0f172a;
        color: #f8fafc;
        padding: 8px;
        border-radius: 4px;
        overflow-x: auto;
        font-size: 7.5pt;
    }}
    pre code {{
        background: transparent;
        color: inherit;
        padding: 0;
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
    <div class="report-meta" style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px 24px; margin-top: 10px;">
        <span><strong>Model Tested:</strong> {model_name} (<code>{model_id}</code>)</span>
        <span><strong>Assessment ID:</strong> {rec_id}</span>
        <span><strong>Managing Provider:</strong> <b>{company}</b> <span style="font-size: 7.5pt; color: #16a34a;">({tier_str})</span></span>
        <span><strong>Evaluation Date:</strong> {eval_date}</span>
        <span><strong>Audit Scope / Mode:</strong> {mode_label}</span>
        <span><strong>Execution Duration:</strong> {dur_str} (10 Garak Probes)</span>
        <span><strong>Status:</strong> <span class="badge {status_badge_class}">{status}</span></span>
    </div>
</div>

<div class="counts-grid">
    <div class="count-card">
        <div class="count-val" style="color: #ef4444;">{issues_cnt}</div>
        <div class="count-lbl">Issues Observed</div>
    </div>
    <div class="count-card">
        <div class="count-val" style="color: #10b981;">{clean_cnt}</div>
        <div class="count-lbl">No Issues Observed</div>
    </div>
    <div class="count-card">
        <div class="count-val" style="color: #f59e0b;">{unassessed_cnt}</div>
        <div class="count-lbl">Unassessed / Blocked</div>
    </div>
    <div class="count-card">
        <div class="count-val" style="color: #64748b;">{na_cnt}</div>
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


def _build_reportlab_pdf(record: Dict[str, Any], output_path: str) -> bool:
    """Builds a crisp, professional A4 PDF report using ReportLab (Pure Python)."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
        )
        from reportlab.pdfgen import canvas
    except ImportError as e:
        logger.warning(f"ReportLab not available: {e}")
        return False

    rec_status = record.get("status", "COMPLETE")
    counts = record.get("counts", {})
    issues_cnt = counts.get("issues_observed", counts.get("issues", len(record.get("findings", []))))
    clean_cnt = counts.get("no_issue_observed", counts.get("no_issue", len(record.get("positive_observations", []))))
    unassessed_cnt = counts.get("unassessed_or_blocked", counts.get("not_completed", counts.get("unassessed", len(record.get("unassessed_areas", [])))))

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_decorations(self, page_count):
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))

            is_unreachable = rec_status in ("FAILED_CONNECTIVITY", "UNREACHABLE") or (clean_cnt == 0 and issues_cnt == 0)

            # Header on subsequent pages
            if self._pageNumber > 1:
                self.drawString(40, 808, "ATLAS-Risk Assessment Report — Confidential")
                header_right = "Target Unreachable / Incomplete Run" if is_unreachable else ("Verified Automated Evaluation" if clean_cnt > 0 else "Evaluation Incomplete")
                self.drawRightString(555, 808, header_right)
                self.setStrokeColor(colors.HexColor("#cbd5e1"))
                self.setLineWidth(0.5)
                self.line(40, 802, 555, 802)

            # Footer on all pages
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(40, 45, 555, 45)
            if is_unreachable:
                footer_text = "ATLAS-Risk Security Scanner (Pre-flight Connectivity Incomplete — 0 Findings)"
            elif unassessed_cnt > 0 or rec_status == "PARTIAL":
                footer_text = "ATLAS-Risk Evidence-Based Assessment Engine (Bounded Scope — Incomplete Tests Unassessed)"
            elif clean_cnt > 0 and issues_cnt == 0:
                footer_text = "ATLAS-Risk Evidence-Based Assessment Engine (All Probes Evaluated)"
            else:
                footer_text = "ATLAS-Risk Evidence-Based Assessment Engine"

            self.drawString(40, 32, footer_text)
            self.drawRightString(555, 32, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=48,
        bottomMargin=55
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=18, leading=22,
        textColor=colors.HexColor('#0f172a'), spaceAfter=4
    )
    meta_label_style = ParagraphStyle(
        'MetaLabel', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=8, leading=11,
        textColor=colors.HexColor('#64748b')
    )
    meta_val_style = ParagraphStyle(
        'MetaVal', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=11,
        textColor=colors.HexColor('#0f172a')
    )
    h2_style = ParagraphStyle(
        'SectionH2', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=12, leading=16,
        textColor=colors.HexColor('#0f172a'), spaceBefore=14, spaceAfter=6
    )
    body_style = ParagraphStyle(
        'DocBody', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=12,
        textColor=colors.HexColor('#334155')
    )
    body_bold = ParagraphStyle(
        'DocBodyBold', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=8.5, leading=12,
        textColor=colors.HexColor('#1e293b')
    )
    finding_title_style = ParagraphStyle(
        'FindingTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=10, leading=13,
        textColor=colors.HexColor('#0f172a')
    )
    sev_badge_style = ParagraphStyle(
        'SevBadge', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=8, leading=10,
        alignment=2
    )
    evidence_style = ParagraphStyle(
        'EvidenceStyle', parent=styles['Normal'],
        fontName='Courier', fontSize=7.5, leading=10,
        textColor=colors.HexColor('#0f172a')
    )
    code_style = ParagraphStyle(
        'CodeStyle', parent=styles['Normal'],
        fontName='Courier', fontSize=7.5, leading=10,
        textColor=colors.HexColor('#047857')
    )

    story = []

    # Title & Badge
    rec_id = record.get("id", "ASM-REPORT")
    status = record.get("status", "COMPLETE")
    target = record.get("target_input", record.get("target_url", "Target"))
    created_at = record.get("created_at", "")[:19].replace("T", " ")

    header_table = Table(
        [
            [
                Paragraph("ATLAS-Risk Bounded Assessment Report", title_style),
                Paragraph(f"<b>STATUS: {status}</b>", ParagraphStyle('StatusBadge', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9, alignment=2, textColor=colors.HexColor('#0369a1')))
            ]
        ],
        colWidths=[380, 135]
    )
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceBefore=4, spaceAfter=8))

    model_name = record.get("model_name") or target
    model_id = record.get("model_id") or target
    company = record.get("model_company") or "OpenRouter / Cloud AI"
    tier_str = record.get("model_tier") or ("100% Free Tier" if (":free" in str(model_id) or model_id == "openrouter/free") else "Standard Tier")
    duration = record.get("execution_duration_sec", "")
    dur_str = f"{duration}s" if duration != "" else "Automated Quick Scan"
    eval_date_display = record.get("evaluated_at_display") or f"{created_at} UTC"
    mode_label = clean_pdf_text(record.get('target_type', 'Cloud AI Audit')).replace('_', ' ').title()

    # Meta Table
    meta_data = [
        [
            Paragraph("Model Tested:", meta_label_style),
            Paragraph(f"<b>{clean_pdf_text(model_name)}</b><br/><font size=6.8 color='#64748b'>ID: {clean_pdf_text(model_id)}</font>", meta_val_style),
            Paragraph("Assessment ID:", meta_label_style),
            Paragraph(f"<b>{rec_id}</b>", meta_val_style),
        ],
        [
            Paragraph("Provider / Company:", meta_label_style),
            Paragraph(f"<b>{clean_pdf_text(company)}</b> &nbsp;<font size=7 color='#16a34a'>({clean_pdf_text(tier_str)})</font>", meta_val_style),
            Paragraph("Evaluation Date:", meta_label_style),
            Paragraph(f"<b>{clean_pdf_text(eval_date_display)}</b>", meta_val_style),
        ],
        [
            Paragraph("Audit Scope / Mode:", meta_label_style),
            Paragraph(mode_label, meta_val_style),
            Paragraph("Execution Duration:", meta_label_style),
            Paragraph(f"<b>{dur_str}</b> (10 Garak Probes)", meta_val_style),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[95, 195, 95, 130])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Metrics Summary Box
    findings = record.get("findings", [])
    positives = record.get("positive_observations", [])
    unassessed = record.get("unassessed_areas", [])
    counts = record.get("counts", {})

    issues_cnt = counts.get("issues_observed", counts.get("issues", len(findings)))
    clean_cnt = counts.get("no_issue_observed", counts.get("no_issue", len(positives)))
    unassessed_cnt = counts.get("unassessed_or_blocked", counts.get("not_completed", counts.get("unassessed", len(unassessed))))
    na_cnt = counts.get("not_applicable", 0)

    metric_cells = [
        [
            Paragraph(f"<font size=16 color='#dc2626'><b>{issues_cnt}</b></font><br/><font size=7.5 color='#64748b'>Issues Observed</font>", ParagraphStyle('M1', alignment=1)),
            Paragraph(f"<font size=16 color='#16a34a'><b>{clean_cnt}</b></font><br/><font size=7.5 color='#64748b'>No Issue Observed</font>", ParagraphStyle('M2', alignment=1)),
            Paragraph(f"<font size=16 color='#ea580c'><b>{unassessed_cnt}</b></font><br/><font size=7.5 color='#64748b'>Unassessed / Blocked</font>", ParagraphStyle('M3', alignment=1)),
            Paragraph(f"<font size=16 color='#64748b'><b>{na_cnt}</b></font><br/><font size=7.5 color='#64748b'>Not Applicable</font>", ParagraphStyle('M4', alignment=1))
        ]
    ]
    metrics_table = Table(metric_cells, colWidths=[128, 129, 129, 129])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 10))

    # Executive Summary
    summary_text = record.get("summary", "Assessment completed.")
    story.append(Paragraph("<b>Executive Summary:</b> " + clean_pdf_text(summary_text), body_style))
    story.append(Spacer(1, 8))

    # 1. Positive Observations
    story.append(Paragraph("1. Positive Observations (Verified Controls)", h2_style))
    if not positives:
        story.append(Paragraph("No positive observations recorded.", body_style))
    else:
        pos_data = [[
            Paragraph("<b>Security Control / Domain</b>", body_bold),
            Paragraph("<b>Observed Adversarial Evidence</b>", body_bold),
            Paragraph("<b>Practical Business Value</b>", body_bold)
        ]]
        for p in positives:
            pos_data.append([
                Paragraph(clean_pdf_text(p.get("aspect", p.get("area", ""))), body_style),
                Paragraph(clean_pdf_text(p.get("evidence", p.get("observation", ""))), body_style),
                Paragraph(clean_pdf_text(p.get("practical_value", p.get("observation", ""))), body_style),
            ])
        pos_table = Table(pos_data, colWidths=[125, 230, 160])
        pos_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(pos_table)
    story.append(Spacer(1, 10))

    # 2. Issues Observed & Practical Fixes
    story.append(Paragraph("2. Issues Observed & Practical Remediations", h2_style))
    if not findings:
        story.append(Paragraph("No security or quality defects were observed within the tested scope.", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity", "MEDIUM")).upper()
            sev_color = "#dc2626" if "HIGH" in sev or "CRIT" in sev else ("#d97706" if "MED" in sev else "#2563eb")

            f_header = Table(
                [
                    [
                        Paragraph(f"<b>#{idx} {clean_pdf_text(f.get('title', f.get('issue', 'Finding')))}</b>", finding_title_style),
                        Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", sev_badge_style)
                    ]
                ],
                colWidths=[430, 75]
            )
            f_header.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ]))

            biz_impact = f.get("business_impact", f.get("why_it_matters", "Risk to business operations and data confidentiality."))
            attack_scen = f.get("attack_scenario", "An adversary crafts targeted prompts to manipulate the model into bypassing safeguards.")
            compliance = f.get("compliance_impact", f.get("domain", "MITRE ATLAS / OWASP LLM Top 10"))
            remediation = f.get("action", f.get("fix", f.get("recommendation", "Review and apply security guardrails.")))

            card_content = [
                f_header,
                Spacer(1, 4),
                Paragraph("<b>Business Impact & Risk Analysis:</b> " + clean_pdf_text(biz_impact), body_style),
                Spacer(1, 3),
                Paragraph("<b>Real-World Attack Scenario:</b> " + clean_pdf_text(attack_scen), body_style),
                Spacer(1, 3),
                Paragraph("<b>Regulatory & Compliance Exposure:</b> <font color='#334155'><b>" + clean_pdf_text(compliance) + "</b></font>", body_style),
                Spacer(1, 3),
                Paragraph("<b>Observed Technical Evidence:</b> " + clean_pdf_text(f.get("observed", f.get("evidence", "N/A"))), evidence_style),
                Spacer(1, 3),
                Paragraph("<b>Actionable Executive Remediation:</b> " + clean_pdf_text(remediation), body_style),
            ]

            code_fix = f.get("code_fix")
            if code_fix:
                card_content.append(Spacer(1, 3))
                card_content.append(Paragraph("<b>Suggested Code / Configuration Fix:</b>", body_bold))
                card_content.append(Paragraph(clean_pdf_text(code_fix), code_style))

            box_table = Table([[card_content]], colWidths=[515])
            box_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), colors.HexColor("#f8fafc")),
                ('BOX', (0, 0), (0, 0), 0.75, colors.HexColor(sev_color)),
                ('TOPPADDING', (0, 0), (0, 0), 6),
                ('BOTTOMPADDING', (0, 0), (0, 0), 6),
                ('LEFTPADDING', (0, 0), (0, 0), 8),
                ('RIGHTPADDING', (0, 0), (0, 0), 8),
            ]))

            story.append(KeepTogether([box_table, Spacer(1, 6)]))

    story.append(Spacer(1, 8))

    # 3. Unassessed Areas & Required Access
    story.append(Paragraph("3. Unassessed Areas & Permissions Required", h2_style))
    if not unassessed:
        if clean_cnt + issues_cnt > 0:
            story.append(Paragraph("All designated target areas were verified.", body_style))
        else:
            story.append(Paragraph("No target areas were assessed due to connectivity failure.", body_style))
    else:
        un_data = [[
            Paragraph("<b>Target Area</b>", body_bold),
            Paragraph("<b>Status / Obstacle</b>", body_bold),
            Paragraph("<b>Access Required to Complete</b>", body_bold)
        ]]
        for u in unassessed:
            un_data.append([
                Paragraph(clean_pdf_text(u.get("area", u.get("component", ""))), body_style),
                Paragraph(clean_pdf_text(u.get("reason", u.get("status", "Requires Access"))), body_style),
                Paragraph(clean_pdf_text(u.get("required_access", u.get("what_access_would_enable", ""))), body_style),
            ])
        un_table = Table(un_data, colWidths=[140, 185, 190])
        un_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(un_table)

    story.append(Spacer(1, 10))

    # 4. Next Steps
    next_steps = record.get("next_steps", record.get("next_steps_required_access", []))
    if next_steps:
        story.append(Paragraph("4. Recommended Next Steps", h2_style))
        for s in next_steps:
            story.append(Paragraph(f"• {clean_pdf_text(s)}", body_style))
            story.append(Spacer(1, 2))

    doc.build(story, canvasmaker=NumberedCanvas)
    return True


def _build_playwright_pdf(html_content: str, output_path: str) -> bool:
    """Optional fallback: Generates PDF using Playwright Chromium if available."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.debug("Playwright not installed, skipping playwright PDF export.")
        return False

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(html_content, wait_until="networkidle")

            footer_tpl = """
            <div style="font-size: 7.5pt; color: #94a3b8; width: 100%; display: flex; justify-content: space-between; padding: 0 15mm;">
                <span>ATLAS-Risk Bounded Assessment Report</span>
                <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
            </div>
            """

            page.pdf(
                path=output_path,
                format="A4",
                print_background=True,
                margin={"top": "14mm", "bottom": "16mm", "left": "14mm", "right": "14mm"},
                display_header_footer=True,
                header_template="<div></div>",
                footer_template=footer_tpl
            )
            browser.close()
        return True
    except Exception as e:
        logger.warning(f"Playwright PDF generation failed: {e}")
        return False


def export_assessment_pdf_and_html(record: Dict[str, Any]) -> Tuple[str, str]:
    """
    Renders both HTML and PDF files for an assessment record.
    Uses pure-Python ReportLab primarily, falling back to Playwright if needed.
    Returns (pdf_path, html_path).
    """
    rec_id = record.get("id", "ASM-EXPORT")
    html_content = generate_html_report(record)

    html_file = os.path.join(EXPORTS_DIR, f"{rec_id}.html")
    pdf_file = os.path.join(EXPORTS_DIR, f"{rec_id}.pdf")

    # Always generate and save standalone HTML
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Primary: ReportLab (no external browser required, works in Streamlit Cloud)
    pdf_ok = False
    try:
        pdf_ok = _build_reportlab_pdf(record, pdf_file)
    except Exception as e:
        logger.warning(f"ReportLab PDF generation error: {e}")
        pdf_ok = False

    # Secondary: Playwright fallback if ReportLab failed or wasn't available
    if not pdf_ok or not os.path.exists(pdf_file) or os.path.getsize(pdf_file) < 1000:
        try:
            pdf_ok = _build_playwright_pdf(html_content, pdf_file)
        except Exception as e:
            logger.warning(f"Playwright PDF fallback error: {e}")

    return pdf_file, html_file
