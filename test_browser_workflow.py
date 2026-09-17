import time
import os
import json
import urllib.request
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2"

def run_browser_verification():
    print("[*] Starting Playwright Browser Verification with System Chrome...", flush=True)
    
    # 1. Reset gateway audit log to ensure fresh state
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/clear_logs", data=b"{}")
        with urllib.request.urlopen(req) as resp:
            print("[*] Gateway logs reset. Assessment count = 0.", flush=True)
    except Exception as e:
        print(f"[!] Warning resetting gateway logs: {e}", flush=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 1100})
        page = context.new_page()

        # Step 1: Open Local Streamlit App
        print("[Step 1] Navigating to http://localhost:8501...", flush=True)
        page.goto("http://localhost:8501", wait_until="domcontentloaded", timeout=15000)
        time.sleep(3)

        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "01_browser_tab_initial.png"))
        print(f"[+] Saved screenshot: 01_browser_tab_initial.png", flush=True)

        # Step 2: Send Pre-Flight Normal Question
        print("[Step 2] Clicking 'Send Normal Question'...", flush=True)
        sample_btn = page.get_by_role("button", name="Send Normal Question")
        sample_btn.click()
        
        # Wait for info alert containing sample response
        page.wait_for_selector("text=Real Sample Response from Model:", timeout=25000)
        time.sleep(1)
        
        sample_text = page.locator(".stAlert").last.inner_text()
        print(f"[+] Sample Response captured from Ollama:\n{sample_text[:120]}...\n", flush=True)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "02_preflight_sample_response.png"))
        print(f"[+] Saved screenshot: 02_preflight_sample_response.png", flush=True)

        # Verify through gateway audit log that assessment requests count is STILL 0
        req = urllib.request.Request("http://127.0.0.1:8080/audit_log")
        with urllib.request.urlopen(req) as resp:
            audit = json.loads(resp.read().decode())
            print(f"[Audit Check] Assessment requests sent so far: {audit['assessment_requests_count']}", flush=True)
            assert audit["assessment_requests_count"] == 0, f"Expected 0 assessment requests before auth, got {audit['assessment_requests_count']}"
        print("[+] Audit Verified: Exactly ZERO assessment probes dispatched prior to authorization.", flush=True)

        # Step 3: Authorize & Execute Baseline Run
        print("[Step 3] Checking authorization checkbox...", flush=True)
        auth_checkbox = page.get_by_text("I explicitly authorize security probe execution")
        auth_checkbox.click()
        time.sleep(1)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "03_scope_authorized.png"))
        print(f"[+] Saved screenshot: 03_scope_authorized.png", flush=True)

        print("[Step 4] Clicking 'Run Local Assessment' (Baseline)...", flush=True)
        run_btn = page.get_by_role("button", name="Run Local Assessment")
        run_btn.click()
        
        # Wait for assessment results to render
        page.wait_for_selector("text=Assessment Evidence & Verdicts", timeout=30000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "04_baseline_assessment_results.png"))
        print(f"[+] Saved screenshot: 04_baseline_assessment_results.png", flush=True)

        # Step 5: Test State Clearing on Profile Change
        print("[Step 5] Changing Configuration Variant to Hardened...", flush=True)
        hardened_radio = page.get_by_text("Hardened (Safeguard Active)")
        hardened_radio.click()
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "05_state_cleared_on_variant_change.png"))
        print(f"[+] Saved screenshot: 05_state_cleared_on_variant_change.png", flush=True)

        # Step 6: Authorize & Run Hardened Assessment
        print("[Step 6] Running Hardened Assessment...", flush=True)
        # Ensure auth checkbox is checked
        checkbox_el = page.locator("input[type='checkbox']").first
        if not checkbox_el.is_checked():
            page.get_by_text("I explicitly authorize security probe execution").click()
            time.sleep(1)

        run_btn = page.get_by_role("button", name="Run Local Assessment")
        run_btn.click()
        page.wait_for_selector("text=Assessment Evidence & Verdicts", timeout=30000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "06_hardened_assessment_results.png"))
        print(f"[+] Saved screenshot: 06_hardened_assessment_results.png", flush=True)

        # Download Markdown Report
        print("[Step 7] Downloading Report...", flush=True)
        with page.expect_download() as download_info:
            page.get_by_role("button", name="Download Markdown Report").click()
        download = download_info.value
        download_path = os.path.join(ARTIFACTS_DIR, "downloaded_local_assessment_report.md")
        download.save_as(download_path)
        print(f"[+] Downloaded Report successfully saved to: {download_path}", flush=True)

        # Step 8: Verify Inconclusive Handling on Error
        print("[Step 8] Testing Inconclusive Handling on Error Simulation...", flush=True)
        page.get_by_text("Simulate Target Failure").click()
        time.sleep(1)

        run_btn = page.get_by_role("button", name="Run Local Assessment")
        run_btn.click()
        time.sleep(4)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "07_inconclusive_error_handling.png"))
        print(f"[+] Saved screenshot: 07_inconclusive_error_handling.png", flush=True)

        browser.close()
        print("\n[🎉] Complete Browser Verification Flow Passed Successfully!", flush=True)

if __name__ == "__main__":
    run_browser_verification()
