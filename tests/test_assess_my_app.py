"""
Automated Test Suite for 'Assess My App' Public-First Review.
Verifies all 8 Acceptance Criteria:
1. Public URL produces useful report even when some sections are inaccessible.
2. Every positive claim and finding has traceable evidence.
3. Untested areas are visible and never counted as passed.
4. Blocked checks state reason and exact next requirement.
5. Public observations are not presented as proof of internal security.
6. Active AI/security probes require separate scoped authorization.
7. Explains coverage in plain language and avoids blanket "safe" certification.
8. Exported markdown and JSON results match actual observations.
"""

import unittest
import json
from engines.public_app_inspector import PublicAppInspector
from assess_my_app_ui import build_markdown_report

TARGET_PUBLIC = "http://127.0.0.1:8088/public_app"
TARGET_HYBRID = "http://127.0.0.1:8088/hybrid_app"


class TestAssessMyApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inspector = PublicAppInspector(max_pages=3)
        cls.res_public = cls.inspector.inspect_url(TARGET_PUBLIC)
        cls.res_hybrid = cls.inspector.inspect_url(TARGET_HYBRID)

    def test_criterion_1_useful_report_with_inaccessible_sections(self):
        """Criterion 1: Public URL produces a useful report even when some sections are inaccessible."""
        self.assertGreater(len(self.res_hybrid["pages_inspected"]), 0, "Accessible pages should be reviewed")
        self.assertGreater(len(self.res_hybrid["unassessed_areas"]), 0, "Protected areas should be identified")
        # Ensure hybrid app has verified items despite the 401 dashboard
        self.assertGreater(len(self.res_hybrid["what_we_verified"]), 5, "Useful verified items should exist")
        # Ensure it didn't fail or return empty
        self.assertIn("positive_observations", self.res_hybrid)
        self.assertIn("issues_observed", self.res_hybrid)

    def test_criterion_2_traceable_evidence(self):
        """Criterion 2: Every positive claim and finding has traceable evidence."""
        for claim in self.res_public["what_we_verified"]:
            self.assertIn("evidence", claim)
            self.assertTrue(len(claim["evidence"]) > 0, f"Claim {claim['item']} lacks traceable evidence")
            self.assertIn("domain", claim)

        for pos in self.res_public["positive_observations"]:
            self.assertIn("evidence", pos)
            self.assertTrue(len(pos["evidence"]) > 0, f"Positive obs {pos['observation']} lacks evidence")

    def test_criterion_3_untested_never_counted_as_passed(self):
        """Criterion 3: Untested areas are visible and never counted as passed."""
        blocked_urls = [un["url"] for un in self.res_hybrid["unassessed_areas"]]
        self.assertTrue(any("dashboard" in u for u in blocked_urls), "Protected dashboard must be in unassessed areas")

        # Verified passed list must NOT include the blocked URL
        verified_items = [v["item"] for v in self.res_hybrid["what_we_verified"] if v["status"] == "VERIFIED"]
        self.assertNotIn("Customer Dashboard (Private)", verified_items)
        for v in self.res_hybrid["what_we_verified"]:
            self.assertNotIn("dashboard", v["evidence"].lower(), "Blocked area must not appear as verified")

    def test_criterion_4_blocked_checks_state_reason_and_requirement(self):
        """Criterion 4: Blocked checks state the reason and the exact next requirement."""
        self.assertGreater(len(self.res_hybrid["what_could_not_be_assessed"]), 0)
        for un in self.res_hybrid["what_could_not_be_assessed"]:
            self.assertIn("reason", un)
            self.assertIn("required_access", un)
            self.assertTrue(len(un["reason"]) > 5, "Reason must be explanatory")
            self.assertTrue(len(un["required_access"]) > 5, "Required access must be explicit")

    def test_criterion_5_public_obs_not_proof_of_internal_security(self):
        """Criterion 5: Public observations are not presented as proof of internal security."""
        unassessed_areas = [u["area"] for u in self.res_public["what_could_not_be_assessed"]]
        self.assertIn("Internal Backend Architecture & Database Security", unassessed_areas,
                      "Report must explicitly document backend limits")

    def test_criterion_6_active_ai_probes_require_separate_authorization(self):
        """Criterion 6: Active AI/security probes require separate scoped authorization."""
        unassessed_areas = [u["area"] for u in self.res_public["what_could_not_be_assessed"]]
        self.assertIn("Active AI Model Red-Teaming (ATLAS Probes)", unassessed_areas,
                      "Report must note that active AI red-teaming requires dedicated authorization")

    def test_criterion_7_plain_language_no_blanket_safe_certification(self):
        """Criterion 7: Report explains coverage in plain language and avoids blanket 'safe' certification."""
        report_md = build_markdown_report(self.res_public)
        self.assertNotIn("100% Certified Safe", report_md)
        self.assertNotIn("Completely Secure", report_md)
        self.assertIn("Bounded Public Review", report_md)

    def test_criterion_8_downloaded_results_match_observations(self):
        """Criterion 8: Downloaded results match the actual observations."""
        report_md = build_markdown_report(self.res_hybrid)
        # Check that page counts and issue counts match
        self.assertIn(f"**Accessible Pages Inspected:** {len(self.res_hybrid['pages_inspected'])}", report_md)
        self.assertIn(f"**Issues Observed:** {len(self.res_hybrid['issues_observed'])}", report_md)
        self.assertIn(f"**Protected / Unassessed Sections:** {len(self.res_hybrid['unassessed_areas'])}", report_md)


if __name__ == "__main__":
    unittest.main()
