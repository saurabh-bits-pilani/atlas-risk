import time
import os
import json
import urllib.request
from playwright.sync_api import sync_playwright

ARTIFACTS_DIR = "/Users/saurabhiim/.gemini/antigravity/brain/bfd1e57c-ef28-4c47-a54f-c8fb3a949dc2"
GATEWAY_URL = "http://127.0.0.1:8080"

def get_audit():
    req = urllib.request.Request(f"{GATEWAY_URL}/audit_log")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def run_browser_verification():
    print("[*] Starting Playwright Browser Verification with System Chrome...", flush=True)
    
    # 1. Reset gateway audit log to ensure fresh state
    try:
        req = urllib.request.Request(f"{GATEWAY_URL}/clear_logs", data=b"{}")
        with urllib.request.urlopen(req) as resp:
            clear_res = json.loads(resp.read().decode())
            print(f"[*] Gateway logs reset at {clear_res.get('timestamp_utc')}. Assessment count = 0.", flush=True)
    except Exception as e:
        print(f"[!] Warning resetting gateway logs: {e}", flush=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 1100})
        page = context.new_page()

        # Step 1: Open Local Streamlit App
        print("[Step 1] Navigating to http://localhost:8501...", flush=True)
        page.goto("http://localhost:8501", wait_until="domcontentloaded", timeout=20000)
        time.sleep(4)

        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "01_browser_tab_initial.png"))
        print(f"[+] Saved screenshot: 01_browser_tab_initial.png", flush=True)

        # Pre-Authorization Audit Snapshot 1
        snap1 = get_audit()
        print(f"[SNAPSHOT 1 - Pre-Authorization] Time: {snap1.get('timestamp_utc')} | Assessment Requests: {snap1.get('assessment_requests_count')}", flush=True)
        assert snap1.get('assessment_requests_count') == 0, f"Expected 0 requests, got {snap1.get('assessment_requests_count')}"

        # Step 2: Send Pre-Flight Normal Question
        print("[Step 2] Clicking 'Send Normal Question'...", flush=True)
        sample_btn = page.get_by_text("Send Normal Question")
        sample_btn.click()
        
        # Wait for response to render in stCodeBlock
        page.wait_for_selector(".stCodeBlock", timeout=35000)
        time.sleep(2)
        
        sample_text = page.locator(".stCodeBlock pre code").first.inner_text()
        print(f"[+] Sample Response captured from Ollama:\n{sample_text[:120]}...\n", flush=True)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "02_preflight_sample_response.png"))
        print(f"[+] Saved screenshot: 02_preflight_sample_response.png", flush=True)

        # Pre-Authorization Audit Snapshot 2 (After sample question)
        snap2 = get_audit()
        print(f"[SNAPSHOT 2 - Post Sample Question] Time: {snap2.get('timestamp_utc')} | Assessment Requests: {snap2.get('assessment_requests_count')}", flush=True)
        assert snap2.get('assessment_requests_count') == 0, f"Expected 0 assessment requests, got {snap2.get('assessment_requests_count')}"
        print("[+] Audit Verified: Exactly ZERO assessment probes dispatched prior to authorization.", flush=True)

        # Step 3: Authorize & Execute Baseline Run
        print("[Step 3] Checking authorization checkbox...", flush=True)
        page.get_by_test_id("stCheckbox").first.click()
        time.sleep(1)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "03_scope_authorized.png"))
        print(f"[+] Saved screenshot: 03_scope_authorized.png", flush=True)

        print("[Step 4] Clicking 'Run Local Assessment' (Baseline)...", flush=True)
        run_btn = page.get_by_text("Run Local Assessment")
        run_btn.click()
        
        # Wait for assessment results to render
        page.wait_for_selector("text=Assessment Evidence & Verdicts", timeout=45000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "04_baseline_assessment_results.png"))
        print(f"[+] Saved screenshot: 04_baseline_assessment_results.png", flush=True)

        # Post-Baseline Audit Snapshot 3
        snap3 = get_audit()
        print(f"[SNAPSHOT 3 - Post-Baseline Execution] Time: {snap3.get('timestamp_utc')} | Assessment Requests: {snap3.get('assessment_requests_count')}", flush=True)
        assert snap3.get('assessment_requests_count') == 3, f"Expected 3 requests, got {snap3.get('assessment_requests_count')}"

        # Step 5: Test Reset & Re-authorization on Profile/Variant Change
        print("[Step 5] Changing Configuration Variant to Hardened...", flush=True)
        hardened_radio = page.get_by_text("Hardened (Safeguard Active)")
        hardened_radio.click()
        time.sleep(3)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "05_state_cleared_on_variant_change.png"))
        print(f"[+] Saved screenshot: 05_state_cleared_on_variant_change.png", flush=True)

        # Verify that checkbox is unchecked
        checkbox_input = page.locator("input[type='checkbox']").first
        is_checked = checkbox_input.is_checked()
        print(f"[Reset Check] Auth checkbox checked state after variant shift: {is_checked}", flush=True)
        assert not is_checked, "Expected authorization to be revoked upon configuration shift"

        # Step 6: Re-authorize & Run Hardened Assessment
        print("[Step 6] Re-authorizing and Running Hardened Assessment...", flush=True)
        page.get_by_text("I explicitly authorize security probe execution").click()
        time.sleep(1)

        run_btn = page.get_by_text("Run Local Assessment")
        run_btn.click()
        page.wait_for_selector("text=Assessment Evidence & Verdicts", timeout=45000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "06_hardened_assessment_results.png"))
        print(f"[+] Saved screenshot: 06_hardened_assessment_results.png", flush=True)

        # Post-Hardened Audit Snapshot 4
        snap4 = get_audit()
        print(f"[SNAPSHOT 4 - Post-Hardened Execution] Time: {snap4.get('timestamp_utc')} | Assessment Requests: {snap4.get('assessment_requests_count')}", flush=True)
        assert snap4.get('assessment_requests_count') == 6, f"Expected 6 requests, got {snap4.get('assessment_requests_count')}"

        # Step 7: Download Markdown Report
        print("[Step 7] Downloading Report...", flush=True)
        with page.expect_download() as download_info:
            page.get_by_text("Download Markdown Report").click()
        download = download_info.value
        download_path = os.path.join(ARTIFACTS_DIR, "downloaded_local_assessment_report.md")
        download.save_as(download_path)
        print(f"[+] Downloaded Report successfully saved to: {download_path}", flush=True)

        # Step 8: Test Truncated / Incomplete Handling
        print("[Step 8] Testing Truncated / Incomplete Handling...", flush=True)
        page.get_by_text("Simulate Incomplete / Truncated Response").click()
        time.sleep(1)

        run_btn = page.get_by_text("Run Local Assessment")
        run_btn.click()
        page.wait_for_selector("text=Assessment Evidence & Verdicts", timeout=30000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "07_truncated_incomplete_response.png"))
        print(f"[+] Saved screenshot: 07_truncated_incomplete_response.png", flush=True)

        # Step 9: Verify Inconclusive Handling on HTTP 500 Error
        print("[Step 9] Testing Inconclusive Handling on Error Simulation...", flush=True)
        # Uncheck truncation, check failure
        page.get_by_text("Simulate Incomplete / Truncated Response").click()
        time.sleep(0.5)
        page.get_by_text("Simulate Target Failure").click()
        time.sleep(1)

        run_btn = page.get_by_text("Run Local Assessment")
        run_btn.click()
        page.wait_for_selector("text=Assessment Evidence & Verdicts", timeout=30000)
        time.sleep(2)
        page.screenshot(path=os.path.join(ARTIFACTS_DIR, "08_inconclusive_error_handling.png"))
        print(f"[+] Saved screenshot: 08_inconclusive_error_handling.png", flush=True)

        # Save snapshots to JSON for audit artifact
        snapshots = {
            "snapshot_1_pre_auth": snap1,
            "snapshot_2_post_sample": snap2,
            "snapshot_3_post_baseline": snap3,
            "snapshot_4_post_hardened": snap4,
            "snapshot_5_final": get_audit()
        }
        snap_path = os.path.join(ARTIFACTS_DIR, "audit_snapshots.json")
        with open(snap_path, "w") as f:
            json.dump(snapshots, f, indent=2)
        print(f"[+] Audit snapshots saved to {snap_path}", flush=True)

        browser.close()
        print("\n[🎉] Complete Browser Verification Flow Passed Successfully!", flush=True)

if __name__ == "__main__":
    run_browser_verification()
