"""
Browser Verification Script for 'Assess My App' Public Review Flow.
Uses Playwright with system Chrome to test:
1. Public Demo (Target 1) - Complete categorized review.
2. Hybrid Demo (Target 2) - Partial useful report with protected dashboard handled gracefully.
3. Download Markdown and JSON reports.
"""

import os
import time
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2"

def run_browser_verification():
    print("[*] Starting Playwright Browser Verification for 'Assess My App'...")
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(viewport={"width": 1280, "height": 950})

        # Step 1: Navigate to Streamlit App
        print("[Step 1] Navigating to http://localhost:8501...", flush=True)
        page.goto("http://localhost:8501", timeout=30000)
        time.sleep(3)

        # Select "Assess My App" mode if not already active
        print("[Step 2] Selecting 'Assess My App' tab...", flush=True)
        page.get_by_text("Assess My App (Public Review)").click()
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "13_assess_my_app_initial.png"))
        print("[+] Saved screenshot: 13_assess_my_app_initial.png", flush=True)

        # Step 3: Run Public Demo
        print("[Step 3] Running Public Demo (Target 1)...", flush=True)
        page.get_by_text("1. Public App Demo").click()
        time.sleep(1)
        page.get_by_role("button", name="Run Public App Review").click()
        page.wait_for_selector("text=Public review completed successfully", timeout=20000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "14_assess_my_app_public_demo.png"), full_page=True)
        print("[+] Saved screenshot: 14_assess_my_app_public_demo.png", flush=True)

        # Step 4: Run Hybrid Demo with Protected Section
        print("[Step 4] Running Hybrid Demo (Target 2 with Protected Area)...", flush=True)
        page.get_by_text("2. Hybrid App (With Protected Area)").click()
        time.sleep(1)
        page.get_by_role("button", name="Run Public App Review").click()
        page.wait_for_selector("text=Partial Review Notice", timeout=20000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "15_assess_my_app_hybrid_demo_partial_report.png"), full_page=True)
        print("[+] Saved screenshot: 15_assess_my_app_hybrid_demo_partial_report.png", flush=True)

        # Step 5: Test Download Markdown Report
        print("[Step 5] Testing Download Markdown Report...", flush=True)
        with page.expect_download() as download_info:
            page.get_by_text("Download Markdown Report").click()
        download = download_info.value
        md_dest = os.path.join(ARTIFACTS_DIR, "AssessMyApp_Hybrid_Report.md")
        download.save_as(md_dest)
        print(f"[+] Downloaded Markdown report saved to: {md_dest}", flush=True)

        # Step 6: Test Download JSON Evidence
        print("[Step 6] Testing Download JSON Evidence...", flush=True)
        with page.expect_download() as download_info:
            page.get_by_text("Download Evidence Telemetry").click()
        download = download_info.value
        json_dest = os.path.join(ARTIFACTS_DIR, "AssessMyApp_Hybrid_Evidence.json")
        download.save_as(json_dest)
        print(f"[+] Downloaded JSON evidence saved to: {json_dest}", flush=True)

        browser.close()
        print("\n[🎉] Playwright Browser Verification for 'Assess My App' Completed Successfully!", flush=True)

if __name__ == "__main__":
    run_browser_verification()
