import os
import re
import time
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2"

def run_e2e():
    print("[*] Starting Playwright E2E Verification for Visual Journey & Red-Team Audit...")
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 1100})
        page = context.new_page()

        # Step 1: Navigate to Home
        print("[Step 1] Navigating to http://localhost:8501...", flush=True)
        page.goto("http://localhost:8501", wait_until="networkidle", timeout=30000)
        time.sleep(3)

        # Step 2: Navigate to Guided Assessment
        print("[Step 2] Navigating to Guided Assessment...", flush=True)
        page.locator('button:has-text("Start assessment →")').first.click()
        time.sleep(2)
        page.wait_for_selector("text=What would you like to check?", timeout=15000)

        # Step 3: Select OpenRouter Free Cloud AI
        print("[Step 3] Selecting OpenRouter Free Cloud AI...", flush=True)
        page.locator('button:has-text("OpenRouter")').first.click()
        time.sleep(2)
        page.wait_for_selector("text=Tell us about your app", timeout=15000)

        # Step 4: Step 2 App Details - Select Demo Sandbox AI & Verify 3 Audit Profiles
        print("[Step 4] Selecting Demo Sandbox AI and checking 3-Tier Audit Profile Cards in Step 2...", flush=True)
        page.wait_for_selector("text=Select Audit Depth & Threat Scope Profile", timeout=15000)

        # Select Demo Sandbox AI from dropdown
        selects = page.locator('div[data-baseweb="select"]').all()
        if len(selects) >= 2:
            selects[1].click()
            time.sleep(1)
            demo_opt = page.locator('li:has-text("Demo Sandbox")').first
            if demo_opt.is_visible():
                demo_opt.click()
                time.sleep(1)

        # Click to select "Full Red-Team" profile
        print("[Step 4b] Selecting Full Red-Team Audit Profile...", flush=True)
        redteam_btn = page.locator('button:has-text("Select Full Red-Team")').first
        if redteam_btn.is_visible():
            redteam_btn.click()
            time.sleep(1)

        step2_path = os.path.join(ARTIFACTS_DIR, "vj_01_step2_profiles_selector.png")
        page.screenshot(path=step2_path, full_page=True)
        print(f"[+] Saved Step 2 screenshot: {step2_path}", flush=True)

        # Step 5: Proceed to Step 3 Review checks & scope
        print("[Step 5] Proceeding to Step 3 Review Scope...", flush=True)
        page.locator('button:has-text("Review checks →")').first.click()
        time.sleep(2)
        page.wait_for_selector("text=Review the checks & permission", timeout=15000)

        # Authorize check
        page.get_by_text("I explicitly authorize ATLAS-Risk to perform this assessment").click()
        time.sleep(1)

        step3_path = os.path.join(ARTIFACTS_DIR, "vj_02_step3_redteam_scope.png")
        page.screenshot(path=step3_path, full_page=True)
        print(f"[+] Saved Step 3 screenshot: {step3_path}", flush=True)

        # Step 6: Start Assessment & Track Visual Journey
        print("[Step 6] Launching Full Red-Team Audit Execution...", flush=True)
        page.locator('button:has-text("Start assessment")').first.click()

        # Capture live visual journey tracker during execution
        time.sleep(1.0)
        journey_path = os.path.join(ARTIFACTS_DIR, "vj_03_step4_live_journey_dashboard.png")
        page.screenshot(path=journey_path, full_page=True)
        print(f"[+] Saved Live Journey screenshot: {journey_path}", flush=True)

        # Wait for assessment completion and results view
        print("[Step 7] Waiting for audit completion and results view...", flush=True)
        page.wait_for_selector("text=Assessment Results:", timeout=90000)
        time.sleep(3)

        results_path = os.path.join(ARTIFACTS_DIR, "vj_04_results_asr_and_matrix.png")
        page.screenshot(path=results_path, full_page=True)
        print(f"[+] Saved Results screenshot: {results_path}", flush=True)

        print("[✓] Playwright verification completed successfully!")
        browser.close()

if __name__ == "__main__":
    run_e2e()

