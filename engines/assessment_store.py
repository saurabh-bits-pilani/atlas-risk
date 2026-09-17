"""
Assessment Store for ATLAS-Risk.
Provides immutable persistent JSON storage for completed and partial assessments.
Ensures that:
- Every assessment is saved with its own unique immutable ID.
- Target or model changes create a new assessment record.
- Historical assessments remain viewable and exportable across application restarts.
"""

import os
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSESSMENTS_DIR = os.path.join(WORKSPACE_DIR, "data", "assessments")


class AssessmentStore:
    def __init__(self, storage_dir: str = ASSESSMENTS_DIR):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def generate_assessment_id(self) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        short_id = uuid.uuid4().hex[:6].upper()
        return f"ASM-{date_str}-{short_id}"

    def save_assessment(self, record: Dict[str, Any]) -> str:
        if "id" not in record or not record["id"]:
            record["id"] = self.generate_assessment_id()
        if "created_at" not in record:
            record["created_at"] = datetime.now(timezone.utc).isoformat()

        file_path = os.path.join(self.storage_dir, f"{record['id']}.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        return file_path

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        file_path = os.path.join(self.storage_dir, f"{assessment_id}.json")
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def list_assessments(self) -> List[Dict[str, Any]]:
        records = []
        if not os.path.exists(self.storage_dir):
            return []

        for filename in os.listdir(self.storage_dir):
            if filename.endswith(".json"):
                full_p = os.path.join(self.storage_dir, filename)
                try:
                    with open(full_p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        records.append({
                            "id": data.get("id", filename.replace(".json", "")),
                            "name": data.get("name", "Unnamed Assessment"),
                            "target_type": data.get("target_type", "website"),
                            "target_input": data.get("target_input", ""),
                            "created_at": data.get("created_at", ""),
                            "status": data.get("status", "COMPLETE"),
                            "summary": data.get("summary", ""),
                            "counts": data.get("counts", {"issues": 0, "no_issue": 0, "not_completed": 0, "not_applicable": 0})
                        })
                except Exception:
                    continue

        records.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return records

    def get_sample_report(self) -> Dict[str, Any]:
        """Returns a verified sample partial assessment for onboarding/demo."""
        sample_id = "SAMPLE-HYBRID-001"
        existing = self.get_assessment(sample_id)
        if existing:
            return existing

        sample_record = {
            "id": sample_id,
            "name": "DevVibe Studio - Sample Partial Review",
            "target_type": "website",
            "target_input": "http://127.0.0.1:8088/hybrid_app",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "PARTIAL",
            "summary": "Bounded review inspected 2 accessible pages. Found 3 security/privacy header issues with practical code fixes. 1 section (/dashboard) requires authentication and could not be assessed.",
            "counts": {
                "issues": 3,
                "no_issue": 8,
                "not_completed": 1,
                "not_applicable": 2
            },
            "findings": [
                {
                    "domain": "Security / Privacy",
                    "severity": "MEDIUM",
                    "title": "Missing `X-Frame-Options` Header",
                    "observed": "Response header `X-Frame-Options` was not returned.",
                    "why_it_matters": "Leaves the website susceptible to clickjacking attacks where malicious sites frame the page.",
                    "evidence": "Inspected root HTTP response headers on http://127.0.0.1:8088/hybrid_app",
                    "action": "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to your reverse proxy or headers config.",
                    "how_to_verify": "Run `curl -I <your-url>` and confirm `X-Frame-Options` is returned."
                },
                {
                    "domain": "Security / Privacy",
                    "severity": "LOW",
                    "title": "Missing `Referrer-Policy` Header",
                    "observed": "Response header `Referrer-Policy` was not returned.",
                    "why_it_matters": "Browsers may send full referrer URLs containing sensitive query parameters to external destinations.",
                    "evidence": "Inspected root HTTP response headers",
                    "action": "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
                    "how_to_verify": "Verify via browser network tab or curl response header."
                },
                {
                    "domain": "Security / Privacy",
                    "severity": "MEDIUM",
                    "title": "Missing Content-Security-Policy (CSP)",
                    "observed": "No `Content-Security-Policy` header found on root response.",
                    "why_it_matters": "Without CSP, the browser has no baseline restrictions against loading unauthorized scripts or resources.",
                    "evidence": "Root response headers on http://127.0.0.1:8088/hybrid_app",
                    "action": "Define a CSP header: `Content-Security-Policy: default-src 'self'; script-src 'self';`.",
                    "how_to_verify": "Check that browser console enforces the declared CSP policy."
                }
            ],
            "positive_observations": [
                {"area": "Usability", "observation": "Document has a clear browser title.", "evidence": "<title>DevVibe Studio - Collaborative AI Workspace</title>"},
                {"area": "Usability", "observation": "Interactive entry points and buttons are discoverable.", "evidence": "1 buttons, 0 forms"},
                {"area": "Accessibility", "observation": "HTML language attribute is declared (`lang=\"en\"`).", "evidence": "<html lang=\"en\">"},
                {"area": "Accessibility", "observation": "Mobile viewport meta tag is present.", "evidence": "<meta name=\"viewport\" ...>"},
                {"area": "Accessibility", "observation": "Discovered images include descriptive alt text.", "evidence": "Verified 1 image with valid alt text"},
                {"area": "Performance", "observation": "Fast initial response latency.", "evidence": "TTFB: 0.8ms, Total Load: 1.1ms"},
                {"area": "Security / Privacy", "observation": "MIME-sniffing protection is active.", "evidence": "X-Content-Type-Options: nosniff"},
                {"area": "Published Pricing", "observation": "Public pricing structure is clearly published.", "evidence": "Detected: Pricing ($29/mo)"}
            ],
            "unassessed_areas": [
                {
                    "area": "http://127.0.0.1:8088/hybrid_app/dashboard",
                    "reason": "HTTP 401 Protected Resource (Unauthorized). Authentication credentials required.",
                    "required_access": "Provide test account credentials (username/password) or session bearer token."
                },
                {
                    "area": "Internal Backend Database & Code Logic",
                    "reason": "Public review does not inspect server-side databases or private repositories.",
                    "required_access": "Connect repository (GitHub/GitLab) or authorize white-box assessment."
                },
                {
                    "area": "Active AI Model Red-Teaming (ATLAS Probes)",
                    "reason": "Adversarial prompt injection testing requires explicit scoped authorization.",
                    "required_access": "Select 'AI Chatbot or Local Model' in Step 1 and authorize active testing."
                }
            ],
            "next_steps": [
                "Deploy X-Frame-Options and Content-Security-Policy headers in hosting configuration.",
                "To assess /dashboard: provide test credentials or session token.",
                "For active AI red-teaming: launch a dedicated AI model assessment with explicit authorization."
            ]
        }
        self.save_assessment(sample_record)
        return sample_record
