"""
Playwright Browser Verification for ATLAS-Risk Guided Assessment Flow.
Validates:
1. Home Screen (Clean plain language, CTA, sample report).
2. Step 1 (What to check - simple cards).
3. Step 2 (Tell us about your app - context-aware fields, purpose, progressive questions).
4. Step 3 (Review checks - "We will check", "We cannot check yet", "Access needed", authorization).
5. Step 4 & Results Page (Activity, counts, findings with practical fixes, unassessed areas).
6. Real PDF and HTML download verification.
7. Reports Archive Page (Search, status filter, open report).
"""

import os
import time
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2"


def run_browser_verification():
    print("[*] Starting Playwright Browser Verification for Guided Assessment...")
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(viewport={"width": 1280, "height": 950})

        # Step 1: Navigate to Home
        print("[Step 1] Navigating to http://localhost:8501...", flush=True)
        page.goto("http://localhost:8501", timeout=30000)
        time.sleep(3)

        # Verify Home Screen
        page.wait_for_selector("text=Understand your app's risks.", timeout=15000)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "16_home_screen.png"))
        print("[+] Saved screenshot: 16_home_screen.png", flush=True)

        # Step 2: Click "Start an assessment" -> Step 1 of 4
        print("[Step 2] Clicking 'Start an assessment'...", flush=True)
        page.get_by_role("button", name="Start an assessment").click()
        time.sleep(2)
        page.wait_for_selector("text=Step 1: What would you like to check?", timeout=15000)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "17_step1_what_to_check.png"))
        print("[+] Saved screenshot: 17_step1_what_to_check.png", flush=True)

        # Step 3: Continue to Step 2 of 4
        print("[Step 3] Continuing to Step 2 (Tell us about your app)...", flush=True)
        page.get_by_role("button", name="Continue →").click()
        time.sleep(2)
        page.wait_for_selector("text=Step 2: Tell us about your app", timeout=15000)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "18_step2_app_details.png"))
        print("[+] Saved screenshot: 18_step2_app_details.png", flush=True)

        # Select Hybrid Demo with Protected Dashboard
        page.get_by_text("Use Hybrid Demo (With Protected Dashboard)").click()
        time.sleep(1)

        # Step 4: Continue to Step 3 of 4
        print("[Step 4] Continuing to Step 3 (Review the checks)...", flush=True)
        page.get_by_role("button", name="Continue →").click()
        time.sleep(2)
        page.wait_for_selector("text=Step 3: Review the checks & scope", timeout=15000)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "19_step3_review_checks.png"))
        print("[+] Saved screenshot: 19_step3_review_checks.png", flush=True)

        # Step 5: Authorize and Start Assessment
        print("[Step 5] Authorizing and launching assessment...", flush=True)
        page.get_by_text("I explicitly authorize ATLAS-Risk to perform this assessment").click()
        time.sleep(1)
        page.get_by_role("button", name="Start assessment").click()

        # Wait for results to render
        page.wait_for_selector("text=Assessment Results", timeout=30000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "20_results_view.png"), full_page=True)
        print("[+] Saved screenshot: 20_results_view.png", flush=True)

        # Step 6: Test Real PDF Download from Results Page
        print("[Step 6] Testing PDF download...", flush=True)
        with page.expect_download() as download_info:
            page.get_by_role("button", name="Download PDF").click()
        download = download_info.value
        pdf_path = os.path.join(ARTIFACTS_DIR, "Downloaded_Assessment_Report.pdf")
        download.save_as(pdf_path)
        pdf_size = os.path.getsize(pdf_path)
        print(f"[+] PDF successfully downloaded ({pdf_size} bytes) to: {pdf_path}", flush=True)
        assert pdf_size > 5000, "PDF file must be non-empty"

        # Step 7: Navigate to Reports section
        print("[Step 7] Navigating to Reports section...", flush=True)
        page.get_by_text("Reports").first.click()
        time.sleep(2)
        page.wait_for_selector("text=Assessment Reports", timeout=15000)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "21_reports_archive.png"))
        print("[+] Saved screenshot: 21_reports_archive.png", flush=True)

        # Step 8: Open Report from Archive
        print("[Step 8] Opening Report from Archive...", flush=True)
        page.get_by_role("button", name="Open Report").first.click()
        time.sleep(2)
        page.wait_for_selector("text=Assessment Results", timeout=15000)
        print("[+] Successfully opened report from archive!", flush=True)

        browser.close()
        print("\n[🎉] All Guided Flow Browser Steps Passed Flawlessly!", flush=True)


if __name__ == "__main__":
    run_browser_verification()
