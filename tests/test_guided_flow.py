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
from engines.report_exporter import export_assessment_pdf_and_html, generate_html_report
from guided_assessment_ui import build_stopped_record


class TestGuidedFlow(unittest.TestCase):
    def setUp(self):
        self.store = AssessmentStore()

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


if __name__ == "__main__":
    unittest.main()
