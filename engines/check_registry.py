"""
ATLAS-Risk Unified Check Registry and Canonical Assessment Ledger (v1.0-FROZEN).

Single Source of Truth for:
- Registry of Planned Checks across domains (Web, AI/LLM, GitHub Repository)
- Canonical Assessment Ledger recording per-check execution, applicability, evidence,
  outcome classification, weights, rubric fractions, and earned credit
- Centralized metric calculation: Coverage, ASPS, ADS, ASR, Category Summaries, and Release Verdicts
- Output parity enforcement across UI, JSON, and PDF exporters.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import math


class CheckDomain(str, Enum):
    SECURITY = "SECURITY"
    OPERATIONAL = "OPERATIONAL"
    GOVERNANCE = "GOVERNANCE"


class CheckOutcome(str, Enum):
    DEFENDED = "DEFENDED"
    BREACHED = "BREACHED"
    DEFICIENCY = "DEFICIENCY"
    INFORMATIONAL = "INFORMATIONAL"
    UNASSESSED = "UNASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ExecutionStatus(str, Enum):
    EVALUATED = "EVALUATED"
    UNASSESSED = "UNASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class CheckDefinition:
    """Immutable definition of a planned check in the versioned registry."""
    check_id: str
    version: str
    name: str
    domain: CheckDomain
    category_id: str
    category_name: str
    category_icon: str
    required_capability: str
    is_security_eligible: bool
    base_weight: float
    framework_mapping: Dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "version": self.version,
            "name": self.name,
            "domain": self.domain.value,
            "category_id": self.category_id,
            "category_name": self.category_name,
            "category_icon": self.category_icon,
            "required_capability": self.required_capability,
            "is_security_eligible": self.is_security_eligible,
            "base_weight": self.base_weight,
            "framework_mapping": self.framework_mapping,
            "description": self.description
        }


@dataclass
class LedgerEntry:
    """Canonical ledger entry for an individual planned check."""
    check_id: str
    definition_version: str
    name: str
    domain: CheckDomain
    category_id: str
    category_name: str
    required_capability: str
    is_applicable: bool
    is_security_eligible: bool
    execution_status: ExecutionStatus
    target: str
    evidence_reference: str
    outcome: CheckOutcome
    specific_reason: str
    unassessed_reason: Optional[str] = None
    scoring_weight: float = 0.0
    rubric_fraction: float = 0.0  # 0.0 to 1.0
    earned_credit: float = 0.0    # scoring_weight * rubric_fraction
    associated_finding_ids: List[str] = field(default_factory=list)
    mapping_rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "definition_version": self.definition_version,
            "name": self.name,
            "domain": self.domain.value,
            "category_id": self.category_id,
            "category_name": self.category_name,
            "required_capability": self.required_capability,
            "is_applicable": self.is_applicable,
            "is_security_eligible": self.is_security_eligible,
            "execution_status": self.execution_status.value,
            "target": self.target,
            "evidence_reference": self.evidence_reference,
            "outcome": self.outcome.value,
            "specific_reason": self.specific_reason,
            "unassessed_reason": self.unassessed_reason,
            "scoring_weight": self.scoring_weight,
            "rubric_fraction": self.rubric_fraction,
            "earned_credit": self.earned_credit,
            "associated_finding_ids": self.associated_finding_ids,
            "mapping_rationale": self.mapping_rationale
        }


# ==============================================================================
# VERSIONED REGISTRY DEFINITIONS
# ==============================================================================

# Web Surface: 25 Planned Checks (CHK-WEB-001 to CHK-WEB-025)
WEB_CHECK_REGISTRY: List[CheckDefinition] = [
    # Category 1: Public Surface & Routing (Discovery)
    CheckDefinition("CHK-WEB-001", "1.0.0", "DNS Resolution & SSL/TLS Handshake", CheckDomain.SECURITY, "discovery", "Public Surface & Routing", "🌐", "public_http", True, 5.0, {"OWASP": "A02: Cryptographic Failures", "ATLAS": "AML.TA0002"}, "Verifies TLS handshake, certificate validity, and transport security."),
    CheckDefinition("CHK-WEB-002", "1.0.0", "Root Landing Page Reachability (HTTP 200)", CheckDomain.OPERATIONAL, "discovery", "Public Surface & Routing", "🌐", "public_http", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Verifies public target endpoint responds with HTTP 200 OK."),
    CheckDefinition("CHK-WEB-003", "1.0.0", "Recursive Same-Origin Route Crawling", CheckDomain.OPERATIONAL, "discovery", "Public Surface & Routing", "🌐", "crawler", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Discovers same-origin navigation routes to establish surface scope."),
    CheckDefinition("CHK-WEB-004", "1.0.0", "Deep Route Hierarchy & Sub-path Mapping", CheckDomain.OPERATIONAL, "discovery", "Public Surface & Routing", "🌐", "crawler", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Maps multi-level application hierarchy and navigation paths."),
    CheckDefinition("CHK-WEB-005", "1.0.0", "Server Response Latency & TTFB Profiling", CheckDomain.OPERATIONAL, "discovery", "Public Surface & Routing", "🌐", "telemetry", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Measures Time to First Byte initial server response responsiveness."),

    # Category 2: Security Headers & CSP
    CheckDefinition("CHK-WEB-006", "1.0.0", "Content-Security-Policy (CSP) Directives", CheckDomain.SECURITY, "security_headers", "Security Headers & CSP", "🛡️", "header_inspector", True, 10.0, {"OWASP": "A05: Security Misconfiguration", "ATLAS": "AML.T0051"}, "Evaluates restrictive CSP directives and inline script fencing."),
    CheckDefinition("CHK-WEB-007", "1.0.0", "Strict-Transport-Security (HSTS) Enforcement", CheckDomain.SECURITY, "security_headers", "Security Headers & CSP", "🛡️", "header_inspector", True, 10.0, {"OWASP": "A02: Cryptographic Failures", "ATLAS": "AML.T0051"}, "Evaluates HSTS max-age and HTTPS transport encryption."),
    CheckDefinition("CHK-WEB-008", "1.0.0", "X-Frame-Options Clickjacking Fencing", CheckDomain.SECURITY, "security_headers", "Security Headers & CSP", "🛡️", "header_inspector", True, 10.0, {"OWASP": "A05: Security Misconfiguration", "ATLAS": "AML.T0051"}, "Verifies framing restrictions (DENY/SAMEORIGIN) to prevent UI redress."),
    CheckDefinition("CHK-WEB-009", "1.0.0", "X-Content-Type-Options MIME Sniffing", CheckDomain.SECURITY, "security_headers", "Security Headers & CSP", "🛡️", "header_inspector", True, 5.0, {"OWASP": "A05: Security Misconfiguration", "ATLAS": "AML.T0051"}, "Ensures nosniff directive is present to prevent MIME confusion."),
    CheckDefinition("CHK-WEB-010", "1.0.0", "Cross-Origin Resource Sharing (CORS) Policy", CheckDomain.SECURITY, "security_headers", "Security Headers & CSP", "🛡️", "header_inspector", True, 5.0, {"OWASP": "A05: Security Misconfiguration", "ATLAS": "AML.T0051"}, "Validates Access-Control-Allow-Origin wildcard and credential policies."),

    # Category 3: Accessibility & Usability (Operational Quality - 0 Weight in ASPS)
    CheckDefinition("CHK-WEB-011", "1.0.0", "HTML Document Language Attribute (`lang`)", CheckDomain.OPERATIONAL, "usability_ui", "Accessibility & Usability", "♿", "dom_inspector", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Verifies root HTML lang attribute for assistive screen readers."),
    CheckDefinition("CHK-WEB-012", "1.0.0", "Mobile Viewport Meta Tag & Responsive Scaling", CheckDomain.OPERATIONAL, "usability_ui", "Accessibility & Usability", "♿", "dom_inspector", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Validates mobile viewport meta tag for responsive rendering."),
    CheckDefinition("CHK-WEB-013", "1.0.0", "Page Title Tag Definition & Semantic Length", CheckDomain.OPERATIONAL, "usability_ui", "Accessibility & Usability", "♿", "dom_inspector", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Ensures descriptive, non-empty HTML <title> tag."),
    CheckDefinition("CHK-WEB-014", "1.0.0", "Image Alt Tag Usability & Accessibility Coverage", CheckDomain.OPERATIONAL, "usability_ui", "Accessibility & Usability", "♿", "dom_inspector", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Scans <img> elements for descriptive alternative text (WCAG 2.1)."),
    CheckDefinition("CHK-WEB-015", "1.0.0", "Form Input Label & ARIA Landmark Associations", CheckDomain.OPERATIONAL, "usability_ui", "Accessibility & Usability", "♿", "dom_inspector", False, 0.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Evaluates accessible input labels and landmark roles."),

    # Category 4: Client Hardening & Cookies
    CheckDefinition("CHK-WEB-016", "1.0.0", "Session Cookie Secure & HttpOnly Attributes", CheckDomain.SECURITY, "client_resilience", "Client Hardening & Cookies", "🍪", "cookie_inspector", True, 10.0, {"OWASP": "A07: Identification & Auth", "ATLAS": "AML.T0057"}, "Verifies Secure and HttpOnly flags on session/authentication cookies."),
    CheckDefinition("CHK-WEB-017", "1.0.0", "SameSite Cookie Lax/Strict Enforcement", CheckDomain.SECURITY, "client_resilience", "Client Hardening & Cookies", "🍪", "cookie_inspector", True, 10.0, {"OWASP": "A07: Identification & Auth", "ATLAS": "AML.T0057"}, "Verifies SameSite attribute prevents Cross-Site Request Forgery."),
    CheckDefinition("CHK-WEB-018", "1.0.0", "Form Method Encryption & Cleartext Warning", CheckDomain.SECURITY, "client_resilience", "Client Hardening & Cookies", "🍪", "dom_inspector", True, 5.0, {"OWASP": "A02: Cryptographic Failures", "ATLAS": "AML.T0057"}, "Validates web forms submit sensitive payloads exclusively over HTTPS."),
    CheckDefinition("CHK-WEB-019", "1.0.0", "Third-Party Script Tracking & Integrity (SRI)", CheckDomain.SECURITY, "client_resilience", "Client Hardening & Cookies", "🍪", "dom_inspector", True, 5.0, {"OWASP": "A08: Software Integrity", "ATLAS": "AML.T0051"}, "Checks remote script tags for Subresource Integrity hashes."),
    CheckDefinition("CHK-WEB-020", "1.0.0", "Referrer-Policy Cross-Origin Leakage Defense", CheckDomain.SECURITY, "client_resilience", "Client Hardening & Cookies", "🍪", "header_inspector", True, 5.0, {"OWASP": "A05: Security Misconfiguration", "ATLAS": "AML.T0057"}, "Validates Referrer-Policy prevents internal URI parameter leakage."),

    # Category 5: Admin & Secret Exposure (Perimeter Fuzzing)
    CheckDefinition("CHK-WEB-021", "1.0.0", "Robots.txt & Sitemap Disclosure Probing", CheckDomain.SECURITY, "perimeter_fuzzing", "Admin & Secret Exposure", "🔍", "path_prober", True, 5.0, {"OWASP": "A01: Broken Access Control", "ATLAS": "AML.T0051"}, "Passively inspects /robots.txt for sensitive path disclosures."),
    CheckDefinition("CHK-WEB-022", "1.0.0", "Exposed Environment Config Files (.env / .git)", CheckDomain.SECURITY, "perimeter_fuzzing", "Admin & Secret Exposure", "🔍", "path_prober", True, 10.0, {"OWASP": "A01: Broken Access Control", "ATLAS": "AML.T0055"}, "Probes /.env and /.git/HEAD for credential and source disclosures."),
    CheckDefinition("CHK-WEB-023", "1.0.0", "Public Administrative Endpoints (/admin, /wp-admin)", CheckDomain.SECURITY, "perimeter_fuzzing", "Admin & Secret Exposure", "🔍", "path_prober", True, 5.0, {"OWASP": "A01: Broken Access Control", "ATLAS": "AML.T0051"}, "Tests admin management interfaces for authentication barriers."),
    CheckDefinition("CHK-WEB-024", "1.0.0", "Debug & Profiler Surfaces (/metrics, /phpinfo.php)", CheckDomain.SECURITY, "perimeter_fuzzing", "Admin & Secret Exposure", "🔍", "path_prober", True, 5.0, {"OWASP": "A05: Security Misconfiguration", "ATLAS": "AML.T0051"}, "Probes common telemetry, diagnostic, and profiling endpoints."),
    CheckDefinition("CHK-WEB-025", "1.0.0", "Backup & Archive File Probing (.bak / backup.zip)", CheckDomain.SECURITY, "perimeter_fuzzing", "Admin & Secret Exposure", "🔍", "path_prober", True, 5.0, {"OWASP": "A01: Broken Access Control", "ATLAS": "AML.T0057"}, "Checks for orphaned source and database backup archives.")
]

# GitHub Repository: 25 Planned Checks (CHK-GH-001 to CHK-GH-025)
GITHUB_CHECK_REGISTRY: List[CheckDefinition] = [
    # 3 Conditional API Checks
    CheckDefinition("CHK-GH-001", "1.0.0", "Repository Reachability & API Access", CheckDomain.GOVERNANCE, "repo_governance", "Repository Governance", "🐙", "github_api", True, 10.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Verifies public accessibility and branch reachability via GitHub API."),
    CheckDefinition("CHK-GH-002", "1.0.0", "Open Source License Declaration", CheckDomain.GOVERNANCE, "repo_governance", "Repository Governance", "🐙", "github_api", True, 10.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Evaluates SPDX open source license declaration in repository root."),
    CheckDefinition("CHK-GH-003", "1.0.0", "Vulnerability Disclosure Policy (`SECURITY.md`)", CheckDomain.SECURITY, "disclosure_policy", "Security & Advisory Policy", "🛡️", "github_api", True, 10.0, {"OWASP": "N/A", "ATLAS": "AML.T0051"}, "Verifies presence of SECURITY.md responsible disclosure channel."),

    # 3 Declared Boundary Checks (Unassessed Without Deep Credentials)
    CheckDefinition("CHK-GH-004", "1.0.0", "Private Git Commit History Secrets Scanning", CheckDomain.SECURITY, "secret_hygiene", "Secret & Canary Hygiene", "🔐", "git_clone", True, 10.0, {"OWASP": "A01", "ATLAS": "AML.T0055"}, "Requires cloned git repository objects for full commit history scan."),
    CheckDefinition("CHK-GH-005", "1.0.0", "Dependency Lockfile Resolution & CVE Audit", CheckDomain.SECURITY, "dependency_posture", "Supply Chain & Lockfiles", "📦", "lockfile_parser", True, 10.0, {"OWASP": "A06", "ATLAS": "AML.T0010"}, "Requires package-lock.json / poetry.lock file contents."),
    CheckDefinition("CHK-GH-006", "1.0.0", "Branch Protection Rules & Admin Configuration", CheckDomain.SECURITY, "repo_governance", "Repository Governance", "🐙", "repo_admin_api", True, 10.0, {"OWASP": "A05", "ATLAS": "AML.T0051"}, "Requires repository admin / organization token permissions.")
] + [
    # 19 Unimplemented Planned Checks (Explicitly Unassessed in Bounded Scope)
    CheckDefinition(f"CHK-GH-{i:03d}", "1.0.0", f"Advanced Static Code Analysis #{i-6}", CheckDomain.SECURITY, "deep_code_audit", "Advanced Code & Supply Chain Audit", "🔬", "ast_scanner", True, 5.0, {"OWASP": "N/A", "ATLAS": "N/A"}, "Requires source code AST analyzer and build environment.")
    for i in range(7, 26)
]


# ==============================================================================
# CANONICAL ASSESSMENT LEDGER
# ==============================================================================

class CanonicalAssessmentLedger:
    """
    Central Ledger and Authoritative Calculation Engine.
    All scores, coverage metrics, category summaries, and verdicts originate here.
    Exporters and UI components MUST consume these pre-calculated metrics directly.
    """

    def __init__(self, target_type: str, target_identifier: str, planned_definitions: List[CheckDefinition]):
        self.target_type = target_type
        self.target_identifier = target_identifier
        self.definitions = {d.check_id: d for d in planned_definitions}
        self.entries: Dict[str, LedgerEntry] = {}

        # Initialize all planned checks as UNASSESSED by default
        for d in planned_definitions:
            self.entries[d.check_id] = LedgerEntry(
                check_id=d.check_id,
                definition_version=d.version,
                name=d.name,
                domain=d.domain,
                category_id=d.category_id,
                category_name=d.category_name,
                required_capability=d.required_capability,
                is_applicable=True,
                is_security_eligible=d.is_security_eligible,
                execution_status=ExecutionStatus.UNASSESSED,
                target=target_identifier,
                evidence_reference="",
                outcome=CheckOutcome.UNASSESSED,
                specific_reason="Check planned but execution not initiated.",
                unassessed_reason="MODULE_NOT_RUN",
                scoring_weight=d.base_weight if d.is_security_eligible else 0.0,
                rubric_fraction=0.0,
                earned_credit=0.0,
                associated_finding_ids=[],
                mapping_rationale=""
            )

    def record_evaluation(
        self,
        check_id: str,
        outcome: CheckOutcome,
        specific_reason: str,
        evidence_reference: str = "",
        rubric_fraction: Optional[float] = None,
        unassessed_reason: Optional[str] = None,
        is_applicable: bool = True,
        associated_finding_ids: Optional[List[str]] = None,
        mapping_rationale: str = ""
    ):
        """Records the execution outcome of a planned check."""
        if check_id not in self.entries:
            raise KeyError(f"Check ID {check_id} not found in planned registry.")

        entry = self.entries[check_id]
        entry.is_applicable = is_applicable
        entry.evidence_reference = evidence_reference
        entry.specific_reason = specific_reason
        entry.associated_finding_ids = associated_finding_ids or []
        entry.mapping_rationale = mapping_rationale

        if not is_applicable:
            entry.execution_status = ExecutionStatus.NOT_APPLICABLE
            entry.outcome = CheckOutcome.NOT_APPLICABLE
            entry.rubric_fraction = 0.0
            entry.earned_credit = 0.0
            entry.unassessed_reason = None
            return

        if outcome == CheckOutcome.UNASSESSED:
            entry.execution_status = ExecutionStatus.UNASSESSED
            entry.outcome = CheckOutcome.UNASSESSED
            entry.unassessed_reason = unassessed_reason or "UNKNOWN_UNASSESSED"
            entry.rubric_fraction = 0.0
            entry.earned_credit = 0.0
            return

        entry.execution_status = ExecutionStatus.EVALUATED
        entry.outcome = outcome
        entry.unassessed_reason = None

        # Calculate rubric fraction and earned credit
        if not entry.is_security_eligible:
            # Operational checks contribute 0 weight and 0 credit to ASPS (AC-04)
            entry.scoring_weight = 0.0
            entry.rubric_fraction = 0.0
            entry.earned_credit = 0.0
        else:
            if rubric_fraction is not None:
                frac = max(0.0, min(1.0, rubric_fraction))
            elif outcome == CheckOutcome.DEFENDED:
                frac = 1.0
            elif outcome == CheckOutcome.DEFICIENCY:
                frac = 0.0
            elif outcome == CheckOutcome.BREACHED:
                frac = 0.0
            else:
                frac = 0.0

            entry.rubric_fraction = frac
            entry.earned_credit = round(entry.scoring_weight * frac, 2)

    def compute_canonical_metrics(self) -> Dict[str, Any]:
        """
        Centrally computes all authoritative metrics over the canonical ledger.
        Enforces AC-01 through AC-15.
        """
        all_entries = list(self.entries.values())
        planned_count = len(all_entries)

        evaluated_entries = [e for e in all_entries if e.execution_status == ExecutionStatus.EVALUATED]
        unassessed_entries = [e for e in all_entries if e.execution_status == ExecutionStatus.UNASSESSED]
        not_applicable_entries = [e for e in all_entries if e.execution_status == ExecutionStatus.NOT_APPLICABLE]

        evaluated_count = len(evaluated_entries)
        unassessed_count = len(unassessed_entries)
        na_count = len(not_applicable_entries)

        # Invariant AC-01: Planned count equals evaluated + unassessed + not applicable
        assert planned_count == (evaluated_count + unassessed_count + na_count), \
            f"Accounting mismatch: Planned ({planned_count}) != Eval ({evaluated_count}) + Unass ({unassessed_count}) + NA ({na_count})"

        # Invariant AC-02: Overall listed-check coverage = evaluated / planned
        coverage_pct = round((evaluated_count / planned_count) * 100.0, 1) if planned_count > 0 else 0.0

        # Invariant AC-04 & AC-05: Security-only ASPS calculation
        eligible_eval = [e for e in evaluated_entries if e.is_security_eligible and e.is_applicable]
        sum_weight = sum(e.scoring_weight for e in eligible_eval)
        sum_credit = sum(e.earned_credit for e in eligible_eval)

        # Invariant AC-06: Zero evaluated eligible weight produces UNRATED (null score)
        if sum_weight > 0:
            asps_numeric = round((sum_credit / sum_weight) * 100.0, 1)
            asps_display = int(round(asps_numeric))
            grade = "Grade A" if asps_display >= 85 else ("Grade B" if asps_display >= 70 else ("Grade C" if asps_display >= 55 else ("Grade D" if asps_display >= 40 else "Grade F")))
        else:
            asps_numeric = None
            asps_display = None
            grade = "UNRATED"

        # Separate security vs operational category tables (AC-04)
        security_categories: Dict[str, Dict[str, Any]] = {}
        operational_categories: Dict[str, Dict[str, Any]] = {}

        for e in all_entries:
            target_cat_dict = security_categories if e.domain == CheckDomain.SECURITY else operational_categories
            cid = e.category_id
            if cid not in target_cat_dict:
                d = self.definitions.get(e.check_id)
                target_cat_dict[cid] = {
                    "id": cid,
                    "name": e.category_name,
                    "icon": d.category_icon if d else "🛡️",
                    "domain": e.domain.value,
                    "total_planned": 0,
                    "evaluated": 0,
                    "defended": 0,
                    "deficiencies": 0,
                    "breaches": 0,
                    "unassessed": 0,
                    "not_applicable": 0,
                    "pass_rate": None,
                    "status": "UNASSESSED"
                }

            c = target_cat_dict[cid]
            c["total_planned"] += 1
            if e.execution_status == ExecutionStatus.EVALUATED:
                c["evaluated"] += 1
                if e.outcome == CheckOutcome.DEFENDED:
                    c["defended"] += 1
                elif e.outcome == CheckOutcome.DEFICIENCY:
                    c["deficiencies"] += 1
                elif e.outcome == CheckOutcome.BREACHED:
                    c["breaches"] += 1
            elif e.execution_status == ExecutionStatus.UNASSESSED:
                c["unassessed"] += 1
            elif e.execution_status == ExecutionStatus.NOT_APPLICABLE:
                c["not_applicable"] += 1

        # Finalize category pass rates and status badges
        for cat_dict in (security_categories, operational_categories):
            for c in cat_dict.values():
                if c["evaluated"] > 0:
                    c["pass_rate"] = round((c["defended"] / c["evaluated"]) * 100.0, 1)
                    if c["breaches"] > 0:
                        c["status"] = "BREACH"
                    elif c["deficiencies"] > 0:
                        c["status"] = "DEFICIENCY"
                    else:
                        c["status"] = "PASS"
                else:
                    c["pass_rate"] = None
                    c["status"] = "UNASSESSED"

        # Explicit unassessed checks ledger (AC-09)
        unassessed_ledger = [
            {
                "check_id": e.check_id,
                "name": e.name,
                "category": e.category_name,
                "unassessed_reason": e.unassessed_reason,
                "specific_explanation": e.specific_reason,
                "required_capability": e.required_capability
            }
            for e in unassessed_entries
        ]

        # Executive Launch Verdict
        any_breach = any(e.outcome == CheckOutcome.BREACHED for e in evaluated_entries)
        any_deficiency = any(e.outcome == CheckOutcome.DEFICIENCY for e in evaluated_entries)

        if evaluated_count == 0 or sum_weight == 0:
            verdict_code = "UNRATED"
            verdict_title = "AUDIT INCOMPLETE"
            verdict_explanation = "Evaluation could not be completed; zero eligible security checks were evaluated."
        elif coverage_pct < 60.0:
            verdict_code = "UNRATED"
            verdict_title = "AUDIT INCOMPLETE (Insufficient Evaluation Coverage)"
            verdict_explanation = f"Evaluation coverage ({evaluated_count}/{planned_count} checks, {coverage_pct}%) is below minimum completeness threshold (60.0%)."
        elif any_breach:
            verdict_code = "BLOCKED"
            verdict_title = "DEPLOYMENT BLOCKED (Security Breaches Detected)"
            verdict_explanation = "Exploitative breach detected during security assessment; production release is blocked."
        elif any_deficiency:
            verdict_code = "ACTION_REQUIRED"
            verdict_title = "ACTION REQUIRED (Security Deficiencies Observed)"
            verdict_explanation = f"Baseline checks executed ({coverage_pct}% coverage), but security header or client hardening deficiencies require remediation."
        else:
            verdict_code = "APPROVED"
            verdict_title = "NO FINDINGS OBSERVED — ASSESSED WEB SCOPE"
            verdict_explanation = f"Evaluated {evaluated_count} of {planned_count} checks ({coverage_pct}% coverage) with zero security deficiencies detected in assessed scope."

        return {
            "planned_count": planned_count,
            "evaluated_count": evaluated_count,
            "unassessed_count": unassessed_count,
            "not_applicable_count": na_count,
            "coverage_pct": coverage_pct,
            "coverage_display": f"{evaluated_count}/{planned_count} ({coverage_pct}%)",
            "asps_numeric": asps_numeric,
            "asps_display": asps_display,
            "safety_grade": grade,
            "scoring_ledger": {
                "sum_earned_credit": sum_credit,
                "sum_eligible_weight": sum_weight,
                "formula": f"ASPS = 100 * ({sum_credit} / {sum_weight}) = {asps_numeric}%" if sum_weight > 0 else "UNRATED (0 eligible weight)",
                "evaluated_eligible_count": len(eligible_eval)
            },
            "security_categories": security_categories,
            "operational_categories": operational_categories,
            "unassessed_ledger": unassessed_ledger,
            "launch_readiness": {
                "code": verdict_code,
                "verdict": verdict_title,
                "explanation": verdict_explanation
            },
            "entries": [e.to_dict() for e in all_entries]
        }


# ==============================================================================
# PROJECT SCORING RUBRICS (Section 3 Implementation)
# ==============================================================================

def evaluate_csp_rubric(csp_header_value: Optional[str]) -> tuple[CheckOutcome, float, str]:
    """
    Project Scoring Rubric for Content-Security-Policy (CSP):
    - Satisfies restrictive directive and inline-script criteria: DEFENDED; fraction 1.0
    - Nonce exception present: DEFENDED; fraction 1.0 (even if 'unsafe-inline' present)
    - Permissive CSP such as default-src *: DEFICIENCY; fraction 0.5
    - CSP absent: DEFICIENCY; fraction 0.0
    """
    if not csp_header_value or not csp_header_value.strip():
        return CheckOutcome.DEFICIENCY, 0.0, "Content-Security-Policy header is absent."

    val = csp_header_value.lower()

    # Nonce exception rule
    has_nonce = "nonce-" in val or "strict-dynamic" in val
    if has_nonce:
        return CheckOutcome.DEFENDED, 1.0, "CSP utilizes cryptographic nonce / strict-dynamic script restriction."

    # Permissive wildcard rule
    if "default-src *" in val or "script-src *" in val or ("unsafe-inline" in val and "unsafe-eval" in val):
        return CheckOutcome.DEFICIENCY, 0.5, "CSP is overly permissive (contains wildcard or unmitigated unsafe-inline/eval)."

    # Restrictive directives
    has_default_or_script = "default-src" in val or "script-src" in val
    has_unsafe_inline = "'unsafe-inline'" in val

    if has_default_or_script and not has_unsafe_inline:
        return CheckOutcome.DEFENDED, 1.0, "CSP specifies restrictive script/default origin policies without unsafe-inline."
    elif has_default_or_script:
        return CheckOutcome.DEFICIENCY, 0.5, "CSP present but contains 'unsafe-inline' without cryptographic nonce mitigations."
    else:
        return CheckOutcome.DEFICIENCY, 0.5, "CSP present but lacks default-src or script-src base directives."


def evaluate_hsts_rubric(hsts_header_value: Optional[str], is_https: bool) -> tuple[CheckOutcome, float, str]:
    """
    Project Scoring Rubric for Strict-Transport-Security (HSTS):
    - Valid HSTS on HTTPS with max-age >= 10886400: DEFENDED; fraction 1.0
    - Valid HSTS with shorter max-age: DEFICIENCY; fraction 0.5
    - HSTS absent or plain HTTP: DEFICIENCY; fraction 0.0
    """
    if not is_https:
        return CheckOutcome.DEFICIENCY, 0.0, "Connection tested over unencrypted HTTP; HSTS not applicable or invalid."

    if not hsts_header_value or not hsts_header_value.strip():
        return CheckOutcome.DEFICIENCY, 0.0, "Strict-Transport-Security header is absent on HTTPS endpoint."

    val = hsts_header_value.lower()
    import re
    match = re.search(r'max-age=(\d+)', val)
    if not match:
        return CheckOutcome.DEFICIENCY, 0.5, "HSTS header present but malformed (missing valid max-age directive)."

    max_age = int(match.group(1))
    if max_age >= 10886400:
        return CheckOutcome.DEFENDED, 1.0, f"Valid HSTS configured with max-age={max_age} (>= 10886400 seconds)."
    else:
        return CheckOutcome.DEFICIENCY, 0.5, f"HSTS configured with max-age={max_age} (< 10886400 minimum recommended duration)."


def evaluate_cookie_rubric(cookie_name: str, is_auth_cookie: bool, has_secure: bool, has_httponly: bool) -> tuple[CheckOutcome, float, str]:
    """
    Project Scoring Rubric for Cookies:
    - Benign cookie lacks Secure or HttpOnly: INFORMATIONAL; excluded from ASPS (weight 0.0, fraction 0.0)
    - Authentication/session cookie lacks a required flag: DEFICIENCY under locked rubric (fraction 0.0)
    - Authentication/session cookie has all required flags: DEFENDED; fraction 1.0
    """
    if not is_auth_cookie:
        return CheckOutcome.INFORMATIONAL, 0.0, f"Non-sensitive / benign cookie '{cookie_name}' lacks optional flags (informational)."

    if has_secure and has_httponly:
        return CheckOutcome.DEFENDED, 1.0, f"Authentication cookie '{cookie_name}' enforces Secure and HttpOnly flags."
    elif has_secure or has_httponly:
        return CheckOutcome.DEFICIENCY, 0.5, f"Authentication cookie '{cookie_name}' partially configured (missing Secure or HttpOnly)."
    else:
        return CheckOutcome.DEFICIENCY, 0.0, f"Authentication cookie '{cookie_name}' lacks both Secure and HttpOnly flags."
