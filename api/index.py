from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ATLAS-Risk v0.4.0-dev — Enterprise AI Risk Assessment</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; line-height: 1.6; background-color: #0e1117; color: #ffffff; }
                .container { max-width: 800px; margin: 0 auto; background: #161b22; padding: 30px; border-radius: 12px; border: 1px solid #30363d; }
                h1 { color: #58a6ff; }
                .badge { display: inline-block; background: #238636; color: #fff; padding: 4px 12px; border-radius: 16px; font-weight: bold; font-size: 0.9em; }
                .btn { display: inline-block; background: #238636; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; margin-top: 20px; }
                .btn:hover { background: #2ea043; }
                code { background: #21262d; padding: 2px 6px; border-radius: 4px; color: #79c0ff; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ ATLAS-Risk v0.4.0-dev</h1>
                <p><span class="badge">BETA RELEASE</span></p>
                <p>Welcome to the <strong>ATLAS-Risk Security Assessment Platform</strong> repository deployment.</p>
                <hr style="border-color: #30363d;">
                <h3>📌 Deployment Options & Access Points</h3>
                <ul>
                    <li><strong>Interactive Streamlit App:</strong> Deploy natively on <a href="https://share.streamlit.io" style="color: #58a6ff;">Streamlit Community Cloud</a> (Repository: <code>saurabh-bits-pilani/atlas-risk</code>).</li>
                    <li><strong>GitHub Repository:</strong> <a href="https://github.com/saurabh-bits-pilani/atlas-risk" style="color: #58a6ff;">github.com/saurabh-bits-pilani/atlas-risk</a></li>
                    <li><strong>Local Run:</strong> <code>streamlit run app.py</code></li>
                </ul>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))
        return

app = handler
