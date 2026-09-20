"""
Public App Inspector Engine for ATLAS-Risk.
Performs bounded, non-intrusive evaluation of publicly observable web applications.
Adheres strictly to the Product Principles:
- Assess what is publicly observable.
- Separate general observations (usability, a11y, perf, security headers, pricing) from ATLAS active security probes.
- Never treat a login screen or 401/403 as a vulnerability or reason to fail the assessment.
- Provide actionable, practical code fixes for every issue observed.
- Clearly present what could not be assessed and the exact access required to unlock next checks.
"""

import time
import re
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone


class SimpleHTMLAnalyzer(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title: Optional[str] = None
        self._in_title = False
        self.html_lang: Optional[str] = None
        self.has_meta_viewport = False
        self.h1_tags: List[str] = []
        self._in_h1 = False
        self._current_h1_text = []
        self.images: List[Dict[str, Any]] = []
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.buttons: List[str] = []
        self._in_button = False
        self._current_button_text = []
        self.pricing_signals: List[str] = []
        self.text_content: List[str] = []
        self._in_script: bool = False

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower in ("script", "style", "noscript", "svg"):
            self._in_script = True
            return

        if tag_lower == "html":
            self.html_lang = attr_dict.get("lang")
        elif tag_lower == "title":
            self._in_title = True
        elif tag_lower == "meta":
            if attr_dict.get("name", "").lower() == "viewport":
                self.has_meta_viewport = True
        elif tag_lower == "h1":
            self._in_h1 = True
            self._current_h1_text = []
        elif tag_lower == "img":
            self.images.append({
                "src": attr_dict.get("src", ""),
                "alt": attr_dict.get("alt"),
                "has_alt": "alt" in attr_dict
            })
        elif tag_lower == "a":
            href = attr_dict.get("href")
            if href:
                self.links.append(href)
        elif tag_lower == "form":
            self.forms.append({
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper()
            })
        elif tag_lower == "button":
            self._in_button = True
            self._current_button_text = []

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in ("script", "style", "noscript", "svg"):
            self._in_script = False
            return

        if tag_lower == "title":
            self._in_title = False
        elif tag_lower == "h1":
            self._in_h1 = False
            text = "".join(self._current_h1_text).strip()
            if text:
                self.h1_tags.append(text[:200])
        elif tag_lower == "button":
            self._in_button = False
            text = "".join(self._current_button_text).strip()
            if text:
                self.buttons.append(text[:100])

    def handle_data(self, data):
        if self._in_script:
            return
        clean_text = data.strip()
        if clean_text:
            self.text_content.append(clean_text[:300])
            if self._in_title and self.title is None:
                self.title = clean_text[:200]
            elif self._in_h1:
                self._current_h1_text.append(data[:200])
            elif self._in_button:
                self._current_button_text.append(data[:100])

            # Detect pricing keywords in visible text (strictly bounded)
            if len(clean_text) <= 120:
                pricing_keywords = ["pricing", "free tier", "$", "month", "/mo", "/year", "pro plan", "enterprise plan"]
                if any(k in clean_text.lower() for k in pricing_keywords):
                    self.pricing_signals.append(clean_text[:100])


class PublicAppInspector:
    def __init__(self, max_pages: int = 4, timeout_sec: float = 6.0):
        self.max_pages = max_pages
        self.timeout_sec = timeout_sec

    def inspect_url(self, root_url: str) -> Dict[str, Any]:
        """
        Executes a bounded, non-intrusive evaluation of the provided web app URL.
        """
        if not root_url.startswith(("http://", "https://")):
            root_url = "https://" + root_url

        parsed_root = urllib.parse.urlparse(root_url)
        origin = f"{parsed_root.scheme}://{parsed_root.netloc}"

        timestamp_iso = datetime.now(timezone.utc).isoformat()

        results = {
            "target_url": root_url,
            "origin": origin,
            "inspected_at": timestamp_iso,
            "pages_inspected": [],
            "unassessed_areas": [],
            "categories": {
                "usability": {"passed": [], "issues": []},
                "accessibility": {"passed": [], "issues": []},
                "performance": {"measurements": [], "issues": []},
                "security_privacy": {"passed": [], "issues": []},
                "pricing": {"status": "NOT_ASSESSED", "evidence": []}
            },
            "what_we_verified": [],
            "positive_observations": [],
            "issues_observed": [],
            "what_could_not_be_assessed": [],
            "next_steps_required_access": []
        }

        urls_to_visit = [root_url]
        visited_urls: Set[str] = set()

        while urls_to_visit and len(visited_urls) < self.max_pages:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
            visited_urls.add(current_url)

            page_result = self._inspect_single_page(current_url, origin)
            if page_result.get("is_accessible"):
                results["pages_inspected"].append(page_result)
                # Discover new same-origin links
                for lk in page_result.get("discovered_links", []):
                    if lk not in visited_urls and lk not in urls_to_visit and len(visited_urls) + len(urls_to_visit) < self.max_pages:
                        urls_to_visit.append(lk)
            else:
                results["unassessed_areas"].append(page_result)

        # Check for common sensitive files (passive probe, non-intrusive)
        self._check_sensitive_paths(origin, results)

        # Aggregate findings across all inspected pages
        self._aggregate_findings(results)

        return results

    def _inspect_single_page(self, url: str, origin: str) -> Dict[str, Any]:
        """
        Inspects a single page. Handles 401, 403, and login redirects gracefully without failing.
        """
        page_info = {
            "url": url,
            "is_accessible": False,
            "http_status": None,
            "ttfb_ms": None,
            "total_latency_ms": None,
            "content_length_bytes": None,
            "headers": {},
            "discovered_links": [],
            "auth_required": False,
            "unassessed_reason": None
        }

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ATLAS-Risk-Public-Inspector/1.0 (+https://atlas-risk.taegisai.space; non-intrusive audit)"
            }
        )

        t_start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as response:
                ttfb = (time.perf_counter() - t_start) * 1000
                html_bytes = response.read()
                total_latency = (time.perf_counter() - t_start) * 1000

                page_info["is_accessible"] = True
                page_info["http_status"] = response.status
                page_info["ttfb_ms"] = round(ttfb, 1)
                page_info["total_latency_ms"] = round(total_latency, 1)
                page_info["content_length_bytes"] = len(html_bytes)
                page_info["headers"] = dict(response.headers)

                final_url = response.geturl()
                if "login" in final_url.lower() and "login" not in url.lower():
                    page_info["is_accessible"] = False
                    page_info["auth_required"] = True
                    page_info["unassessed_reason"] = f"Redirected to authentication portal at {final_url}"
                    return page_info

                # Parse HTML content
                try:
                    encoding = response.headers.get_content_charset() or "utf-8"
                    html_text = html_bytes.decode(encoding, errors="replace")
                except Exception:
                    html_text = html_bytes.decode("utf-8", errors="replace")

                analyzer = SimpleHTMLAnalyzer()
                analyzer.feed(html_text)

                page_info["parsed"] = {
                    "title": analyzer.title,
                    "html_lang": analyzer.html_lang,
                    "has_meta_viewport": analyzer.has_meta_viewport,
                    "h1_tags": analyzer.h1_tags,
                    "images_count": len(analyzer.images),
                    "images_missing_alt": [img["src"] for img in analyzer.images if not img["has_alt"] or not img["alt"]],
                    "forms_count": len(analyzer.forms),
                    "buttons_count": len(analyzer.buttons),
                    "pricing_signals": analyzer.pricing_signals[:5]
                }

                # Normalize discovered same-origin links
                discovered = []
                for link in analyzer.links:
                    full_link = urllib.parse.urljoin(url, link)
                    parsed_link = urllib.parse.urlparse(full_link)
                    if f"{parsed_link.scheme}://{parsed_link.netloc}" == origin:
                        # strip fragment and query
                        clean_link = urllib.parse.urlunparse((parsed_link.scheme, parsed_link.netloc, parsed_link.path, "", "", ""))
                        if clean_link != url and clean_link not in discovered:
                            discovered.append(clean_link)
                page_info["discovered_links"] = discovered

        except urllib.error.HTTPError as e:
            page_info["http_status"] = e.code
            page_info["headers"] = dict(e.headers)
            if e.code in (401, 403):
                page_info["auth_required"] = True
                page_info["unassessed_reason"] = f"HTTP {e.code} Protected Resource ({e.reason}). Authentication credentials or session token required."
            else:
                page_info["unassessed_reason"] = f"HTTP {e.code} ({e.reason})"
        except urllib.error.URLError as e:
            page_info["unassessed_reason"] = f"Network Connection Failure: {e.reason}"
        except Exception as e:
            page_info["unassessed_reason"] = f"Inspection Error: {str(e)}"

        return page_info

    def _check_sensitive_paths(self, origin: str, results: Dict[str, Any]):
        """
        Non-intrusive probe for common misconfigurations (.env, .git/HEAD).
        A 401, 403, or 404 is a PASS (protected/absent). Only 200 with sensitive content is flagged.
        """
        paths_to_test = [
            ("/.env", "Environment Variables File", "DB_PASSWORD|SECRET|API_KEY"),
            ("/.git/HEAD", "Git Repository Metadata", "ref: refs/")
        ]

        for path, label, signature in paths_to_test:
            probe_url = origin + path
            try:
                req = urllib.request.Request(
                    probe_url,
                    headers={"User-Agent": "ATLAS-Risk-Public-Inspector/1.0"}
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        body_snip = resp.read(256).decode("utf-8", errors="replace")
                        if re.search(signature, body_snip, re.IGNORECASE):
                            results["categories"]["security_privacy"]["issues"].append({
                                "check": f"Publicly Exposed {label}",
                                "severity": "CRITICAL",
                                "evidence": f"Path `{path}` returned HTTP 200 with matching signature.",
                                "fix": f"Configure your web server (nginx, Vercel, Netlify) to deny access to hidden files (`location ~ /\\. {{ deny all; }}`)."
                            })
            except Exception:
                # 403, 404 or connection error is normal and safe
                pass

    def _aggregate_findings(self, results: Dict[str, Any]):
        """
        Constructs the 5 required report sections with traceable evidence:
        - What We Could Verify
        - Positive Observations
        - Issues Observed (with practical fixes)
        - What We Could Not Assess (and why)
        - What Access Would Enable Next Checks
        """
        pages = results["pages_inspected"]
        unassessed = results["unassessed_areas"]

        if not pages:
            results["what_could_not_be_assessed"].append({
                "area": results["target_url"],
                "reason": "Root target URL was inaccessible or rejected initial connection.",
                "required_access": "Verify host availability, DNS resolution, and firewall whitelist."
            })
            return

        primary_page = pages[0]
        parsed = primary_page.get("parsed", {})
        headers = primary_page.get("headers", {})
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # -------------------------------------------------------------
        # 1. Usability & Visible Functionality
        # -------------------------------------------------------------
        if parsed.get("title"):
            results["what_we_verified"].append({
                "domain": "Usability",
                "item": "Document Title",
                "evidence": f"Found `<title>{parsed['title']}</title>` on {primary_page['url']}",
                "status": "VERIFIED"
            })
            results["positive_observations"].append({
                "area": "Usability",
                "observation": "Page has a clear, descriptive browser title.",
                "evidence": f"Title: `{parsed['title']}`"
            })
        else:
            results["issues_observed"].append({
                "domain": "Usability",
                "issue": "Missing `<title>` tag",
                "evidence": f"No `<title>` element found in document head on {primary_page['url']}",
                "fix": "Add `<title>Your App Name - Brief Description</title>` inside the `<head>` of your root template or layout component."
            })

        if parsed.get("buttons_count", 0) > 0 or parsed.get("forms_count", 0) > 0:
            results["what_we_verified"].append({
                "domain": "Usability",
                "item": "Interactive UI Elements",
                "evidence": f"Detected {parsed.get('buttons_count')} interactive button(s) and {parsed.get('forms_count')} form(s)",
                "status": "VERIFIED"
            })
            results["positive_observations"].append({
                "area": "Usability",
                "observation": "Interactive entry points and forms are present and discoverable.",
                "evidence": f"{parsed.get('buttons_count')} buttons, {parsed.get('forms_count')} forms"
            })

        # -------------------------------------------------------------
        # 2. Accessibility
        # -------------------------------------------------------------
        if parsed.get("html_lang"):
            results["what_we_verified"].append({
                "domain": "Accessibility",
                "item": "HTML Language Declaration",
                "evidence": f"`<html lang=\"{parsed['html_lang']}\">` defined",
                "status": "VERIFIED"
            })
            results["positive_observations"].append({
                "area": "Accessibility",
                "observation": "HTML language attribute is declared, aiding screen readers and search crawlers.",
                "evidence": f"lang=\"{parsed['html_lang']}\""
            })
        else:
            results["issues_observed"].append({
                "domain": "Accessibility",
                "issue": "Missing `lang` attribute on `<html>` tag",
                "evidence": "Tag is rendered as `<html>` without language specification.",
                "fix": "Update your root `index.html` or Next.js `app/layout.tsx` to `<html lang=\"en\">`."
            })

        if parsed.get("has_meta_viewport"):
            results["what_we_verified"].append({
                "domain": "Accessibility",
                "item": "Mobile Viewport Meta Tag",
                "evidence": "`<meta name=\"viewport\" ...>` configured",
                "status": "VERIFIED"
            })
        else:
            results["issues_observed"].append({
                "domain": "Accessibility",
                "issue": "Missing `<meta name=\"viewport\">`",
                "evidence": "No mobile viewport tag detected, resulting in non-responsive scaling on mobile devices.",
                "fix": "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">` to `<head>`."
            })

        missing_alt = parsed.get("images_missing_alt", [])
        if parsed.get("images_count", 0) > 0:
            if not missing_alt:
                results["positive_observations"].append({
                    "area": "Accessibility",
                    "observation": "All discovered images include non-empty `alt` attributes.",
                    "evidence": f"Verified {parsed['images_count']} image(s) with valid alt text."
                })
            else:
                results["issues_observed"].append({
                    "domain": "Accessibility",
                    "issue": f"{len(missing_alt)} image(s) missing `alt` attribute",
                    "evidence": f"Images lacking alt text: {missing_alt[:3]}",
                    "fix": "Ensure all `<img>` tags include descriptive `alt=\"...\"` text (or `alt=\"\"` for decorative images)."
                })

        # -------------------------------------------------------------
        # 3. Basic Performance Measurements
        # -------------------------------------------------------------
        for p in pages:
            results["what_we_verified"].append({
                "domain": "Performance",
                "item": f"Latency Check ({p['url']})",
                "evidence": f"TTFB: {p['ttfb_ms']}ms | Total Load: {p['total_latency_ms']}ms | Payload: {p['content_length_bytes']} bytes (Direct HTTP GET over local network)",
                "status": "VERIFIED"
            })
            if p['total_latency_ms'] < 800:
                results["positive_observations"].append({
                    "area": "Performance",
                    "observation": f"Fast initial response latency ({p['total_latency_ms']}ms) on `{p['url']}`.",
                    "evidence": f"TTFB: {p['ttfb_ms']}ms, Payload: {p['content_length_bytes']} B"
                })
            elif p['total_latency_ms'] > 2500:
                results["issues_observed"].append({
                    "domain": "Performance",
                    "issue": f"High response latency ({p['total_latency_ms']}ms) on `{p['url']}`",
                    "evidence": f"Total HTTP load time exceeded 2.5 seconds.",
                    "fix": "Review server-side rendering bottlenecks, enable edge caching, or minify initial HTML payloads."
                })

        # -------------------------------------------------------------
        # 4. Publicly Observable Security & Privacy Signals
        # -------------------------------------------------------------
        # Check HTTPS
        if results["target_url"].startswith("https://"):
            results["positive_observations"].append({
                "area": "Security / Privacy",
                "observation": "Enforces HTTPS transport encryption.",
                "evidence": f"Target scheme: https"
            })
        elif not results["target_url"].startswith("http://127.0.0.1") and not results["target_url"].startswith("http://localhost"):
            results["issues_observed"].append({
                "domain": "Security / Privacy",
                "issue": "Insecure HTTP Protocol Detected",
                "evidence": f"Connected via plaintext `{results['target_url']}`",
                "fix": "Enforce HTTPS via automatic redirect on your hosting provider or reverse proxy."
            })

        # Check Security Headers
        security_headers = {
            "x-content-type-options": ("X-Content-Type-Options", "nosniff", "Add `X-Content-Type-Options: nosniff` header in your hosting configuration to prevent MIME-sniffing attacks."),
            "x-frame-options": ("X-Frame-Options", "DENY or SAMEORIGIN", "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to defend against UI clickjacking."),
            "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin", "Set `Referrer-Policy: strict-origin-when-cross-origin` to avoid leaking sensitive URLs in outgoing requests.")
        }

        for h_key, (h_name, expected, fix_code) in security_headers.items():
            if h_key in headers_lower:
                results["what_we_verified"].append({
                    "domain": "Security / Privacy",
                    "item": f"Header: {h_name}",
                    "evidence": f"`{h_name}: {headers_lower[h_key]}`",
                    "status": "VERIFIED"
                })
                results["positive_observations"].append({
                    "area": "Security / Privacy",
                    "observation": f"Security header `{h_name}` is actively configured.",
                    "evidence": f"`{headers_lower[h_key]}`"
                })
            else:
                results["issues_observed"].append({
                    "domain": "Security / Privacy",
                    "issue": f"Missing `{h_name}` header",
                    "evidence": f"Response header `{h_name}` was not returned.",
                    "fix": fix_code
                })

        # Check Content-Security-Policy
        if "content-security-policy" in headers_lower:
            results["positive_observations"].append({
                "area": "Security / Privacy",
                "observation": "Content-Security-Policy (CSP) is active.",
                "evidence": f"`{headers_lower['content-security-policy'][:60]}...`"
            })
        else:
            results["issues_observed"].append({
                "domain": "Security / Privacy",
                "issue": "Missing Content-Security-Policy (CSP)",
                "evidence": "No `Content-Security-Policy` header found on the root HTML response.",
                "fix": "Define a CSP header restricting script and object sources: `Content-Security-Policy: default-src 'self'; script-src 'self';`."
            })

        # -------------------------------------------------------------
        # 5. Published Pricing
        # -------------------------------------------------------------
        pricing_signals = parsed.get("pricing_signals", [])
        if pricing_signals:
            results["categories"]["pricing"]["status"] = "DETECTED"
            results["categories"]["pricing"]["evidence"] = pricing_signals
            results["what_we_verified"].append({
                "domain": "Published Pricing",
                "item": "Pricing Information",
                "evidence": f"Found pricing indicators: {', '.join(pricing_signals[:3])}",
                "status": "VERIFIED"
            })
            results["positive_observations"].append({
                "area": "Published Pricing",
                "observation": "Public pricing structure is clearly published on the accessible site.",
                "evidence": f"Detected: {', '.join(pricing_signals[:2])}"
            })
        else:
            results["categories"]["pricing"]["status"] = "NOT_ASSESSED"
            results["what_we_verified"].append({
                "domain": "Published Pricing",
                "item": "Pricing Transparency",
                "evidence": "Not assessed — no public pricing table or tier keywords detected on crawled pages.",
                "status": "NOT_ASSESSED"
            })

        # -------------------------------------------------------------
        # 6. What We Could Not Assess & Required Access
        # -------------------------------------------------------------
        if unassessed:
            for un in unassessed:
                results["what_could_not_be_assessed"].append({
                    "area": un["url"],
                    "reason": un.get("unassessed_reason", "Protected or inaccessible resource"),
                    "required_access": "Provide test account credentials (username/password) or session cookie to unlock authenticated page analysis."
                })
                results["next_steps_required_access"].append(
                    f"To assess `{un['url']}`: {un.get('unassessed_reason')}. Requires test account credentials or private API connection."
                )

        # Always clearly document backend and active AI probe boundaries
        results["what_could_not_be_assessed"].append({
            "area": "Internal Backend Architecture & Database Security",
            "reason": "Bounded public inspection cannot inspect server-side logic, SQL parameters, or internal storage without source code or repository access.",
            "required_access": "Connect repository (GitHub/GitLab) or authorize white-box assessment."
        })
        results["what_could_not_be_assessed"].append({
            "area": "Active AI Model Red-Teaming (ATLAS Probes)",
            "reason": "Adversarial prompt injection, system prompt extraction, and model red-teaming require explicit scoped authorization and dedicated API keys.",
            "required_access": "Authorize active AI probing in the 'Local AI Testing' or 'New AI System Assessment' tabs with explicit scope agreement."
        })

        results["next_steps_required_access"].append(
            "For active AI red-teaming: Navigate to 'Local AI Testing' or 'New AI System Assessment', grant explicit scope authorization, and connect your model endpoint."
        )
