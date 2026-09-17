import os
import re
import base64
import markdown
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2"
MD_PATH = os.path.join(ARTIFACTS_DIR, "LOCAL_AI_TESTING_ACCEPTANCE_REPORT.md")
PDF_OUT_1 = os.path.join(ARTIFACTS_DIR, "ATLAS_RISK_LOCAL_AI_ACCEPTANCE_REPORT.pdf")
PDF_OUT_2 = "/Users/saurabhiim/Documents/01_YEAR_2026_ACTIVE/Antigravity/atlas-risk.taegisai.space/ATLAS_RISK_LOCAL_AI_ACCEPTANCE_REPORT.pdf"

with open(MD_PATH, "r", encoding="utf-8") as f:
    raw_md = f.read()

# Replace carousel blocks with image grids
def carousel_replacer(match):
    content = match.group(1)
    slides = content.split("<!-- slide -->")
    html_out = ['<div class="image-gallery">']
    for slide in slides:
        img_match = re.search(r'!\[(.*?)\]\((.*?)\)', slide.strip())
        if img_match:
            alt = img_match.group(1)
            img_path = img_match.group(2)
            if os.path.exists(img_path):
                with open(img_path, "rb") as img_f:
                    b64 = base64.b64encode(img_f.read()).decode()
                html_out.append(f'''
                <div class="gallery-item">
                    <img src="data:image/png;base64,{b64}" alt="{alt}" />
                    <div class="gallery-caption">{alt}</div>
                </div>
                ''')
    html_out.append('</div>')
    return "\n".join(html_out)

processed_md = re.sub(r'````carousel\n(.*?)\n````', carousel_replacer, raw_md, flags=re.DOTALL)

# Handle alert callouts (> [!IMPORTANT])
def alert_replacer(match):
    alert_type = match.group(1).upper()
    body = match.group(2).strip()
    color_class = "alert-important" if alert_type == "IMPORTANT" else "alert-info"
    return f'<div class="alert-box {color_class}"><strong>{alert_type}:</strong> {body}</div>'

processed_md = re.sub(r'>\s*\[!(IMPORTANT|NOTE|WARNING|TIP|CAUTION)\]\s*\n((?:>\s*.*\n?)+)', 
                      lambda m: alert_replacer(re.match(r'>\s*\[!(.*?)\]\s*\n(.*)', m.group(0), flags=re.DOTALL)), 
                      processed_md)

# Clean remaining '>' in alerts
processed_md = re.sub(r'<div class="alert-box (.*?)"><strong>(.*?)</strong> (.*?)</div>',
                      lambda m: f'<div class="alert-box {m.group(1)}"><strong>{m.group(2)}</strong> {m.group(3).replace(">", "").strip()}</div>',
                      processed_md)

html_body = markdown.markdown(processed_md, extensions=['tables', 'fenced_code', 'nl2br'])

# Badge styling for status
html_body = html_body.replace('PASSED', '<span class="badge badge-pass">PASSED</span>')
html_body = html_body.replace('CONDITIONAL PASS (RECHECK COMPLETE)', '<span class="badge badge-cond">CONDITIONAL PASS (RECHECK COMPLETE)</span>')
html_body = html_body.replace('VULNERABILITY OBSERVED', '<span class="badge badge-vuln">VULNERABILITY OBSERVED</span>')
html_body = html_body.replace('INCONCLUSIVE / INCOMPLETE RESPONSE', '<span class="badge badge-inconcl">INCONCLUSIVE / INCOMPLETE RESPONSE</span>')
html_body = html_body.replace('INCONCLUSIVE / TEST FAILED', '<span class="badge badge-inconcl">INCONCLUSIVE / TEST FAILED</span>')
html_body = html_body.replace('NO VULNERABILITY OBSERVED', '<span class="badge badge-pass">NO VULNERABILITY OBSERVED</span>')
html_body = html_body.replace('NOT VERIFIED (LIMITATION)', '<span class="badge badge-warn">NOT VERIFIED (LIMITATION)</span>')

full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ATLAS-Risk Local AI Security Assessment Report</title>
<style>
    @page {{
        size: A4;
        margin: 18mm 15mm 20mm 15mm;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #1f2937;
        line-height: 1.5;
        font-size: 11pt;
        margin: 0;
        padding: 0;
    }}
    h1 {{
        font-size: 20pt;
        font-weight: 700;
        color: #111827;
        border-bottom: 2px solid #e5e7eb;
        padding-bottom: 8px;
        margin-top: 0;
        margin-bottom: 12px;
    }}
    h2 {{
        font-size: 14pt;
        font-weight: 600;
        color: #1e3a8a;
        margin-top: 24px;
        margin-bottom: 10px;
        border-bottom: 1px solid #f3f4f6;
        padding-bottom: 4px;
        page-break-after: avoid;
    }}
    h3 {{
        font-size: 12pt;
        font-weight: 600;
        color: #374151;
        margin-top: 16px;
        margin-bottom: 8px;
        page-break-after: avoid;
    }}
    h4 {{
        font-size: 11pt;
        font-weight: 600;
        color: #4b5563;
        margin-top: 12px;
        margin-bottom: 6px;
        page-break-after: avoid;
    }}
    p {{
        margin-top: 4px;
        margin-bottom: 8px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 14px 0;
        font-size: 9.5pt;
        page-break-inside: avoid;
    }}
    th, td {{
        border: 1px solid #d1d5db;
        padding: 6px 10px;
        text-align: left;
        vertical-align: top;
    }}
    th {{
        background-color: #f8fafc;
        font-weight: 600;
        color: #1e293b;
    }}
    tr:nth-child(even) {{
        background-color: #fcfcfd;
    }}
    code {{
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 9pt;
        background-color: #f3f4f6;
        padding: 2px 4px;
        border-radius: 4px;
        color: #be123c;
    }}
    pre {{
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 10px 12px;
        font-size: 8.5pt;
        overflow-x: auto;
        page-break-inside: avoid;
    }}
    pre code {{
        background-color: transparent;
        padding: 0;
        color: #1e293b;
    }}
    .badge {{
        display: inline-block;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 8.5pt;
        font-weight: 700;
        letter-spacing: 0.02em;
    }}
    .badge-pass {{
        background-color: #dcfce7;
        color: #15803d;
        border: 1px solid #bbf7d0;
    }}
    .badge-cond {{
        background-color: #fef9c3;
        color: #854d0e;
        border: 1px solid #fef08a;
    }}
    .badge-vuln {{
        background-color: #fee2e2;
        color: #b91c1c;
        border: 1px solid #fecaca;
    }}
    .badge-inconcl {{
        background-color: #f3e8ff;
        color: #7e22ce;
        border: 1px solid #e9d5ff;
    }}
    .badge-warn {{
        background-color: #ffedd5;
        color: #c2410c;
        border: 1px solid #fed7aa;
    }}
    .alert-box {{
        padding: 10px 14px;
        border-radius: 6px;
        margin: 14px 0;
        font-size: 10pt;
        page-break-inside: avoid;
    }}
    .alert-important {{
        background-color: #eff6ff;
        border-left: 4px solid #2563eb;
        color: #1e40af;
    }}
    .alert-info {{
        background-color: #f0fdf4;
        border-left: 4px solid #16a34a;
        color: #166534;
    }}
    .image-gallery {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
        margin: 16px 0;
        page-break-inside: avoid;
    }}
    .gallery-item {{
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        overflow: hidden;
        background: #fff;
        page-break-inside: avoid;
    }}
    .gallery-item img {{
        width: 100%;
        height: auto;
        display: block;
    }}
    .gallery-caption {{
        padding: 6px 8px;
        font-size: 8pt;
        font-weight: 600;
        background: #f9fafb;
        color: #4b5563;
        border-top: 1px solid #e5e7eb;
        text-align: center;
    }}
    hr {{
        border: none;
        border-top: 1px solid #e5e7eb;
        margin: 18px 0;
    }}
</style>
</head>
<body>
{html_body}
</body>
</html>
"""

with open("report_styled.html", "w", encoding="utf-8") as f:
    f.write(full_html)

print("[*] HTML generated. Launching Playwright to generate PDF...")

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome")
    page = browser.new_page()
    page.set_content(full_html, wait_until="networkidle")
    
    footer_tpl = """
    <div style="font-size: 8pt; color: #9ca3af; width: 100%; display: flex; justify-content: space-between; padding: 0 15mm;">
        <span>ATLAS-Risk Local AI Security Assessment — Commit 64b7438</span>
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
    </div>
    """
    
    page.pdf(
        path=PDF_OUT_1,
        format="A4",
        print_background=True,
        margin={"top": "16mm", "bottom": "18mm", "left": "14mm", "right": "14mm"},
        display_header_footer=True,
        header_template="<div></div>",
        footer_template=footer_tpl
    )
    
    # Also copy to workspace
    with open(PDF_OUT_1, "rb") as src_f, open(PDF_OUT_2, "wb") as dst_f:
        dst_f.write(src_f.read())
        
    browser.close()

print(f"[+] PDF successfully created at:")
print(f"    - {PDF_OUT_1}")
print(f"    - {PDF_OUT_2}")
