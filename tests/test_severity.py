"""Severity ladder tests. This is the module where a bug means a missed patch."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from patchwatch.models import Vuln
from patchwatch.severity import detect_apple_exploitation, from_cvss, resolve


def v(**kw):
    kw.setdefault("cve_id", "CVE-2026-0001")
    kw.setdefault("platform", "ios")
    return Vuln(**kw)


class TestBands(unittest.TestCase):
    def test_cvss_bands(self):
        self.assertEqual(from_cvss(9.8), "CRITICAL")
        self.assertEqual(from_cvss(9.0), "CRITICAL")
        self.assertEqual(from_cvss(8.9), "HIGH")
        self.assertEqual(from_cvss(7.0), "HIGH")
        self.assertEqual(from_cvss(6.9), "MEDIUM")
        self.assertEqual(from_cvss(3.9), "LOW")
        self.assertEqual(from_cvss(0.0), "NONE")


class TestLadderPrecedence(unittest.TestCase):
    def test_kev_beats_low_cvss(self):
        """A KEV-listed CVE is critical even if someone scored it 3.1."""
        out = resolve(v(kev=True, cvss_score=3.1))
        self.assertEqual(out.severity, "CRITICAL")
        self.assertEqual(out.severity_source, "kev")
        self.assertTrue(out.exploited)

    def test_apple_exploitation_prose_beats_no_score(self):
        out = resolve(v(impact="Apple is aware of a report that this issue may have been exploited."))
        self.assertEqual(out.severity, "CRITICAL")
        self.assertEqual(out.severity_source, "vendor_exploited")

    def test_targeted_individuals_phrasing(self):
        out = resolve(v(impact="may have been used in an extremely sophisticated attack against specific targeted individuals"))
        self.assertEqual(out.severity, "CRITICAL")

    def test_vendor_rating_short_circuits(self):
        """Android's own rating wins; we do not go looking for a CVSS score."""
        out = resolve(v(platform="android", severity="HIGH", severity_source="vendor_rating"))
        self.assertEqual(out.severity, "HIGH")
        self.assertEqual(out.severity_source, "vendor_rating")

    def test_cvss_used_when_no_exploitation(self):
        out = resolve(v(cvss_score=7.5))
        self.assertEqual(out.severity, "HIGH")

    def test_epss_fallback(self):
        out = resolve(v(epss=0.62))
        self.assertEqual(out.severity, "CRITICAL")
        self.assertEqual(out.severity_source, "epss")

        out = resolve(v(epss=0.15))
        self.assertEqual(out.severity, "HIGH")

        out = resolve(v(epss=0.01))
        self.assertEqual(out.severity, "UNKNOWN")

    def test_impact_heuristic_floor(self):
        out = resolve(v(impact="An application may be able to execute arbitrary code with kernel privileges"))
        self.assertEqual(out.severity, "CRITICAL")
        self.assertEqual(out.severity_source, "impact_heuristic")

    def test_unscored_stays_unknown_not_low(self):
        """The critical regression guard.

        Post-April-2026 NIST leaves most CVEs permanently unenriched. If a refactor
        ever makes 'no score' collapse to LOW, this pipeline silently stops working
        and nobody notices until an incident.
        """
        out = resolve(v(impact="A logic issue was addressed with improved checks."))
        self.assertEqual(out.severity, "UNKNOWN")
        self.assertNotEqual(out.severity, "LOW")

    def test_unknown_is_actionable(self):
        from patchwatch.models import Release
        r = Release(platform="ios", product="iOS", version="26.6.1",
                    release_date="2026-08-20", advisory_url="x",
                    vulns=[resolve(v(cve_id="CVE-2026-1111"))])
        self.assertEqual(len(r.actionable("HIGH")), 1)


class TestExploitationDetection(unittest.TestCase):
    def test_positive_cases(self):
        for text in [
            "Apple is aware of a report that this issue may have been exploited",
            "may have been actively exploited against versions of iOS",
            "This issue has been actively exploited in the wild",
        ]:
            self.assertTrue(detect_apple_exploitation(text), text)

    def test_negative_cases(self):
        for text in [
            "A memory corruption issue was addressed with improved validation",
            "This issue could not be exploited in our testing",
            "",
        ]:
            self.assertFalse(detect_apple_exploitation(text), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestRealAppleImpactStrings(unittest.TestCase):
    """Verbatim impact strings in the shapes Apple actually publishes."""

    CASES = [
        ("An application may be able to execute arbitrary code with kernel privileges", "CRITICAL"),
        ("Processing maliciously crafted web content may lead to arbitrary code execution", "HIGH"),
        ("An app may be able to gain root privileges", "HIGH"),
        ("An app may be able to break out of its sandbox", "HIGH"),
        ("An app may be able to cause unexpected system termination", "MEDIUM"),
        ("An app may be able to access sensitive user data", "MEDIUM"),
        ("A logic issue was addressed with improved state management", "UNKNOWN"),
    ]

    def test_all(self):
        for impact, expected in self.CASES:
            with self.subTest(impact=impact[:50]):
                self.assertEqual(resolve(v(impact=impact)).severity, expected)
