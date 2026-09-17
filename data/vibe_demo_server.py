"""
Lightweight Vibe-Coded Demo Web Server for ATLAS-Risk 'Assess My App' Validation.
Provides:
1. /public_app: Fully public app with accessible landing, features, and pricing.
2. /hybrid_app: Public landing and pricing, but with /dashboard (HTTP 401) and /admin (HTTP 403).
"""

import http.server
import socketserver
import threading
import time

PORT = 8088

HTML_PUBLIC_LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeFlow AI - Effortless Workflow Automation</title>
</head>
<body style="font-family: sans-serif; padding: 20px;">
    <h1>Welcome to VibeFlow AI</h1>
    <p>Automate your business workflows in natural language.</p>
    <img src="/static/hero.png" alt="VibeFlow Dashboard Preview" width="300" />
    <br><br>
    <button>Start Free Trial</button>
    <a href="/public_app/pricing">View Pricing ($19/mo)</a>
    <a href="/public_app/features">Features</a>
</body>
</html>"""

HTML_PUBLIC_PRICING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pricing Plans - VibeFlow AI</title>
</head>
<body style="font-family: sans-serif; padding: 20px;">
    <h1>Simple, Transparent Pricing</h1>
    <div>
        <h3>Starter Plan: Free tier</h3>
        <h3>Pro Plan: $19 / month</h3>
        <h3>Enterprise Plan: Custom billing</h3>
    </div>
    <a href="/public_app">Back to Home</a>
</body>
</html>"""

HTML_PUBLIC_FEATURES = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Features - VibeFlow AI</title>
</head>
<body style="font-family: sans-serif; padding: 20px;">
    <h1>Features & Integrations</h1>
    <p>Connects with Slack, Notion, and GitHub seamlessly.</p>
    <a href="/public_app">Back to Home</a>
</body>
</html>"""

# Hybrid App Templates
HTML_HYBRID_LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevVibe Studio - Collaborative AI Workspace</title>
</head>
<body style="font-family: sans-serif; padding: 20px;">
    <h1>DevVibe Studio</h1>
    <p>Build, test, and ship full-stack apps with conversational prompts.</p>
    <img src="/static/dev.png" alt="DevVibe Studio UI" width="300" />
    <br><br>
    <button>Sign In</button>
    <a href="/hybrid_app/pricing">Pricing ($29/mo)</a>
    <a href="/hybrid_app/dashboard">Customer Dashboard (Private)</a>
</body>
</html>"""

HTML_HYBRID_PRICING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pricing - DevVibe Studio</title>
</head>
<body style="font-family: sans-serif; padding: 20px;">
    <h1>DevVibe Pricing</h1>
    <p>Solo Developer: $29/mo | Team: $99/mo</p>
    <a href="/hybrid_app">Home</a>
</body>
</html>"""


class VibeDemoHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Silence standard HTTP access logging

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        # Target 1: Public App
        if path == "/public_app" or path == "/public_app/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.end_headers()
            self.wfile.write(HTML_PUBLIC_LANDING.encode("utf-8"))

        elif path == "/public_app/pricing":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(HTML_PUBLIC_PRICING.encode("utf-8"))

        elif path == "/public_app/features":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PUBLIC_FEATURES.encode("utf-8"))

        # Target 2: Hybrid App (with Protected Section)
        elif path == "/hybrid_app" or path == "/hybrid_app/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(HTML_HYBRID_LANDING.encode("utf-8"))

        elif path == "/hybrid_app/pricing":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_HYBRID_PRICING.encode("utf-8"))

        elif path == "/hybrid_app/dashboard":
            # Protected Area: Requires Authentication
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("WWW-Authenticate", 'Bearer realm="DevVibe Dashboard"')
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized. Please authenticate with a valid session token or Bearer key."}')

        elif path == "/hybrid_app/admin":
            # Protected Area: Forbidden
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"error": "Forbidden: Administrative credentials required."}')

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")


def run_server():
    server = socketserver.TCPServer(("127.0.0.1", PORT), VibeDemoHandler)
    server.allow_reuse_address = True
    print(f"[*] VibeDemoServer running on http://127.0.0.1:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
