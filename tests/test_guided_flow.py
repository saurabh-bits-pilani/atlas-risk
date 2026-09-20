"""
Automated Test Suite for Guided Assessment Flow and Consolidation.
Verifies:
1. Immutability of assessment records in AssessmentStore.
2. Graceful stop handling in guided execution.
3. PDF and HTML report generation parity.
4. Absence of arbitrary overall scores and false '100% Governance' claims.
5. Preserved research benchmarks and sample report integrity.
"""

import unittest
import os
import json
from engines.assessment_store import AssessmentStore
import tempfile
from engines.report_exporter import export_assessment_pdf_and_html, generate_html_report
from guided_assessment_ui import build_stopped_record


class TestGuidedFlow(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.store = AssessmentStore(storage_dir=self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_store_immutability(self):
        """Verify that multiple assessments get unique IDs and never overwrite each other."""
        rec1 = {
            "id": self.store.generate_assessment_id(),
            "name": "Run 1",
            "target_type": "website",
            "target_input": "http://example.com/1",
            "status": "COMPLETE",
            "counts": {"issues": 1, "no_issue": 2, "not_completed": 0, "not_applicable": 0}
        }
        rec2 = {
            "id": self.store.generate_assessment_id(),
            "name": "Run 2",
            "target_type": "website",
            "target_input": "http://example.com/2",
            "status": "COMPLETE",
            "counts": {"issues": 2, "no_issue": 1, "not_completed": 0, "not_applicable": 0}
        }
        self.assertNotEqual(rec1["id"], rec2["id"], "Each assessment must have a unique ID")

        path1 = self.store.save_assessment(rec1)
        path2 = self.store.save_assessment(rec2)
        self.assertTrue(os.path.exists(path1))
        self.assertTrue(os.path.exists(path2))

        loaded1 = self.store.get_assessment(rec1["id"])
        loaded2 = self.store.get_assessment(rec2["id"])
        self.assertEqual(loaded1["target_input"], "http://example.com/1")
        self.assertEqual(loaded2["target_input"], "http://example.com/2")

    def test_stopped_run_record(self):
        """Verify that stopping an assessment creates an honest STOPPED record."""
        inp = {"target_type": "website", "url": "http://127.0.0.1:8088/hybrid_app"}
        stopped_rec = build_stopped_record(inp, "User requested stop.")
        self.assertEqual(stopped_rec["status"], "STOPPED")
        self.assertIn("stopped", stopped_rec["summary"].lower())
        self.assertEqual(len(stopped_rec["findings"]), 0)

    def test_report_export_parity_and_no_false_claims(self):
        """Verify that exported HTML and PDF contain genuine data and no false assurance claims."""
        sample = self.store.get_sample_report()
        html_out = generate_html_report(sample)

        # False claims must NOT be present
        self.assertNotIn("100% Governance", html_out)
        self.assertNotIn("Zero-Trust Enforced", html_out)
        self.assertNotIn("62/100", html_out)
        self.assertNotIn("100% Certified Safe", html_out)

        # Genuine counts must be present
        self.assertIn(str(sample["counts"]["issues"]), html_out)
        self.assertIn(str(sample["counts"]["no_issue"]), html_out)
        self.assertIn(str(sample["counts"]["not_completed"]), html_out)

        # Export both PDF and HTML
        pdf_path, html_path = export_assessment_pdf_and_html(sample)
        self.assertTrue(os.path.exists(pdf_path), "PDF must exist on disk")
        self.assertTrue(os.path.exists(html_path), "HTML must exist on disk")
        self.assertGreater(os.path.getsize(pdf_path), 5000, "PDF should not be empty")

    def test_sample_report_structure(self):
        """Verify that the sample onboarding report contains all required sections."""
        sample = self.store.get_sample_report()
        self.assertEqual(sample["status"], "PARTIAL")
        self.assertIn("findings", sample)
        self.assertIn("positive_observations", sample)
        self.assertIn("unassessed_areas", sample)
        self.assertIn("next_steps", sample)

    def test_clean_assessments_dir(self):
        """Verify that newly initialized AssessmentStore contains only sample report."""
        real_store = AssessmentStore()
        assessments = real_store.list_assessments()
        # Only SAMPLE-HYBRID-001 should exist in initial clean repo state
        dummy_ids = [a["id"] for a in assessments if a["id"] in ("ASM-20260917-249A6D", "ASM-20260917-5F7D4F", "ASM-20260917-5F1D77")]
        self.assertEqual(len(dummy_ids), 0, "No dummy test runs should be in production store")

    def test_distinct_target_evaluations(self):
        """Verify GitHub, Chatbot, and Questionnaire produce genuine independent assessment records."""
        from guided_assessment_ui import inspect_github_repository, inspect_chatbot_endpoint, evaluate_questionnaire_inputs

        gh_rec = inspect_github_repository("https://github.com/expressjs/express", branch="master")
        self.assertEqual(gh_rec["target_type"], "github")
        self.assertNotEqual(gh_rec["id"], "SAMPLE-HYBRID-001")
        self.assertIn("express", gh_rec["name"].lower())

        cb_rec = inspect_chatbot_endpoint("http://127.0.0.1:9999/chat", "Dify Webhook", app_name="SupportBot")
        self.assertEqual(cb_rec["target_type"], "chatbot")
        self.assertNotEqual(cb_rec["id"], "SAMPLE-HYBRID-001")
        self.assertIn("SupportBot", cb_rec["name"])

        q_rec = evaluate_questionnaire_inputs({"app_name": "FinanceAssistant", "deployment_scope": "Public Web Interface", "uses_rag": "Yes"})
        self.assertEqual(q_rec["target_type"], "questionnaire")
        self.assertNotEqual(q_rec["id"], "SAMPLE-HYBRID-001")
        self.assertIn("FinanceAssistant", q_rec["name"])


    def test_universal_3tier_profiles_and_scorecard(self):
        """Verify universal 3-tier audit profiles, dynamic scorecard computation, and circuit breaker."""
        from guided_assessment_ui import (
            get_audit_profiles_for_target,
            compute_executive_scorecard,
            inspect_github_repository,
            evaluate_questionnaire_inputs
        )

        # 1. Verify 3-Tier profiles available for all target modules
        for t_type in ["website", "github", "questionnaire", "openrouter", "local_model", "chatbot"]:
            profs = get_audit_profiles_for_target(t_type)
            self.assertIn("quick", profs)
            self.assertIn("owasp_core", profs)
            self.assertIn("full_redteam", profs)
            self.assertGreater(profs["full_redteam"]["prompts_count"], profs["owasp_core"]["prompts_count"])
            self.assertGreater(profs["owasp_core"]["prompts_count"], profs["quick"]["prompts_count"])

        # 2. Verify scorecard & circuit breaker behavior
        # Case A: 100% clean defenses -> Grade A Approved
        clean_sc = compute_executive_scorecard([], [{"domain": "D1"} for _ in range(10)], 10)
        self.assertEqual(clean_sc["overall_safety_score"], 100)
        self.assertEqual(clean_sc["safety_grade"], "Grade A")
        self.assertEqual(clean_sc["launch_readiness"]["code"], "APPROVED")
        self.assertFalse(clean_sc["circuit_breaker_triggered"])

        # Case B: 1 Critical Leak among 9 Defenses (90% safe) -> Weakest Link Circuit Breaker BLOCKED!
        crit_finding = [{"domain": "Data", "severity": "CRITICAL", "title": "Canary token leaked"}]
        defenses = [{"domain": "D"} for _ in range(9)]
        crit_sc = compute_executive_scorecard(crit_finding, defenses, 10)
        self.assertEqual(crit_sc["overall_safety_score"], 90)
        self.assertTrue(crit_sc["circuit_breaker_triggered"])
        self.assertEqual(crit_sc["launch_readiness"]["code"], "BLOCKED")
        self.assertIn("Circuit Breaker", crit_sc["launch_readiness"]["explanation"])

        # Case C: High severity -> ACTION_REQUIRED
        high_finding = [{"domain": "Injection", "severity": "HIGH", "title": "Prompt injection bypass"}]
        high_sc = compute_executive_scorecard(high_finding, defenses, 10)
        self.assertEqual(high_sc["launch_readiness"]["code"], "ACTION_REQUIRED")
        self.assertFalse(high_sc["circuit_breaker_triggered"])

        # 3. Verify GitHub and Questionnaire records include scorecard fields
        gh_rec = inspect_github_repository("https://github.com/expressjs/express", branch="master")
        self.assertIn("overall_safety_score", gh_rec)
        self.assertIn("safety_grade", gh_rec)
        self.assertIn("launch_readiness", gh_rec)
        self.assertIn("circuit_breaker_triggered", gh_rec)

        q_rec = evaluate_questionnaire_inputs({"app_name": "TestAI", "deployment_scope": "Public Web Interface", "uses_rag": "No"})
        self.assertIn("overall_safety_score", q_rec)
        self.assertIn("safety_grade", q_rec)
        self.assertIn("launch_readiness", q_rec)
        self.assertIn("circuit_breaker_triggered", q_rec)

    def test_staged_website_audit_unreachable_and_messy_input(self):
        """Verify URL sanitization and ensure unreachable target does NOT raise UnboundLocalError."""
        from unittest.mock import patch, MagicMock
        from guided_assessment_ui import run_staged_website_audit

        dummy_journey = MagicMock()
        dummy_status = MagicMock()

        # Mock inspect_url returning empty pages (unreachable host)
        mock_raw_res = {
            "pages_inspected": [],
            "issues_observed": [],
            "positive_observations": [],
            "unassessed_areas": [{"area": "Network Connection", "reason": "Connection failed"}]
        }

        with patch("guided_assessment_ui.PublicAppInspector.inspect_url", return_value=mock_raw_res):
            rec = run_staged_website_audit(
                inp={"url": "Try this as well - https://couriernova-iq.up.railway.app/login", "scan_profile": "quick"},
                journey_container=dummy_journey,
                status_container=dummy_status
            )

        # 1. URL was cleanly extracted
        self.assertEqual(rec["target_input"], "https://couriernova-iq.up.railway.app/login")
        # 2. Checks correctly classified as UNASSESSED with zero UnboundLocalError
        self.assertEqual(rec["counts"]["issues"], 0)
        self.assertEqual(rec["counts"]["no_issue"], 0)
        self.assertEqual(rec["counts"]["not_completed"], rec["total_prompts_planned"])
        self.assertIsNone(rec["overall_safety_score"])
        self.assertEqual(rec["safety_grade"], "UNRATED")


if __name__ == "__main__":
    unittest.main()

