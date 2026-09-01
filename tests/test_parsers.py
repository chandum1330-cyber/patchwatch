"""Parser tests against fixtures shaped like the real pages."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from patchwatch.sources.android import parse_bulletin
from patchwatch.sources.apple import parse_advisory_html
from patchwatch.sources.microsoft import parse_cvrf

ANDROID_HTML = """
<html><body>
<h3>2026-08-01 security patch level vulnerability details</h3>
<table>
<tr><th>CVE</th><th>References</th><th>Type</th><th>Severity</th><th>Updated AOSP versions</th></tr>
<tr><td>CVE-2026-2001</td><td>A-987654321</td><td>RCE</td><td>Critical</td><td>13, 14, 15</td></tr>
<tr><td>CVE-2026-2002</td><td>A-987654322</td><td>EoP</td><td>High</td><td>14, 15</td></tr>
<tr><td>CVE-2026-2003</td><td>A-987654323</td><td>ID</td><td>Moderate</td><td>15</td></tr>
</table>
<h3>System</h3>
<table>
<tr><th>CVE</th><th>References</th><th>Type</th><th>Severity</th></tr>
<tr><td>CVE-2026-2004</td><td>A-987654324</td><td>EoP</td><td>High</td></tr>
</table>
</body></html>
"""

APPLE_HTML = """
<html><body>
<h2>Kernel</h2>
<p>Available for: iPhone XS and later</p>
<p>Impact: An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been exploited.</p>
<p>Description: A memory corruption issue was addressed with improved validation.</p>
<p>CVE-ID: CVE-2026-1001</p>
<h2>WebKit</h2>
<p>Available for: iPhone XS and later</p>
<p>Impact: Processing maliciously crafted web content may lead to arbitrary code execution</p>
<p>Description: A use-after-free issue was addressed with improved memory management.</p>
<p>CVE-ID: CVE-2026-1002</p>
</body></html>
"""

CVRF = {
    "DocumentTitle": {"Value": "August 2026 Security Updates"},
    "DocumentTracking": {"CurrentReleaseDate": "2026-08-11T08:00:00Z"},
    "ProductTree": {"FullProductName": [
        {"ProductID": "12001", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
        {"ProductID": "12002", "Value": "Microsoft Edge (Chromium-based)"},
    ]},
    "Vulnerability": [
        {
            "CVE": "CVE-2026-3001",
            "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
            "ProductStatuses": [{"ProductID": ["12001"]}],
            "CVSSScoreSets": [{"BaseScore": 8.8, "Vector": "CVSS:3.1/AV:L/AC:L"}],
            "Threats": [{"Description": {"Value": "Publicly Disclosed:No;Exploited:Yes"}}],
        },
        {
            "CVE": "CVE-2026-3002",
            "Title": {"Value": "Chromium: Type Confusion in V8"},
            "ProductStatuses": [{"ProductID": ["12002"]}],
            "CVSSScoreSets": [],
            "Threats": [],
        },
    ],
}


class TestAndroid(unittest.TestCase):
    def test_severity_column_extracted(self):
        vulns = {v.cve_id: v for v in parse_bulletin(ANDROID_HTML, "2026-08-01")}
        self.assertEqual(len(vulns), 4)
        self.assertEqual(vulns["CVE-2026-2001"].severity, "CRITICAL")
        self.assertEqual(vulns["CVE-2026-2002"].severity, "HIGH")
        self.assertEqual(vulns["CVE-2026-2003"].severity, "MEDIUM")

    def test_vendor_rating_source_set(self):
        """Android ratings must short-circuit the ladder, not fall through to NVD."""
        for v in parse_bulletin(ANDROID_HTML, "2026-08-01"):
            self.assertEqual(v.severity_source, "vendor_rating")

    def test_multiple_tables_merged(self):
        ids = {v.cve_id for v in parse_bulletin(ANDROID_HTML, "2026-08-01")}
        self.assertIn("CVE-2026-2004", ids)


class TestApple(unittest.TestCase):
    def test_impact_attached_to_correct_cve(self):
        vulns = {v.cve_id: v for v in parse_advisory_html(APPLE_HTML, "ios")}
        self.assertEqual(len(vulns), 2)
        self.assertIn("kernel privileges", vulns["CVE-2026-1001"].impact)
        self.assertIn("web content", vulns["CVE-2026-1002"].impact)

    def test_exploitation_survives_to_severity(self):
        from patchwatch.severity import resolve
        vulns = {v.cve_id: resolve(v) for v in parse_advisory_html(APPLE_HTML, "ios")}
        self.assertEqual(vulns["CVE-2026-1001"].severity, "CRITICAL")
        self.assertEqual(vulns["CVE-2026-1001"].severity_source, "vendor_exploited")
        self.assertEqual(vulns["CVE-2026-1002"].severity, "HIGH")


class TestMsrc(unittest.TestCase):
    def test_windows_only_by_default(self):
        rel = parse_cvrf(CVRF, "2026-Aug")
        self.assertIsNotNone(rel)
        self.assertEqual([v.cve_id for v in rel.vulns], ["CVE-2026-3001"])

    def test_cvss_banded_as_vendor_rating(self):
        rel = parse_cvrf(CVRF, "2026-Aug")
        v = rel.vulns[0]
        self.assertEqual(v.cvss_score, 8.8)
        self.assertEqual(v.severity, "HIGH")
        self.assertEqual(v.severity_source, "vendor_rating")

    def test_exploited_flag_parsed(self):
        rel = parse_cvrf(CVRF, "2026-Aug")
        self.assertTrue(rel.vulns[0].exploited)

    def test_edge_included_on_request(self):
        rel = parse_cvrf(CVRF, "2026-Aug", include_edge=True)
        self.assertEqual(len(rel.vulns), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestAndroidUrlScheme(unittest.TestCase):
    """Google inserted a year segment into bulletin URLs starting in 2026.
    Every guessed URL 404'd until this was handled."""

    def test_both_schemes_generated_newest_first(self):
        from patchwatch.sources.android import bulletin_urls
        urls = bulletin_urls("2026-08-01")
        self.assertEqual(urls[0], "https://source.android.com/docs/security/bulletin/2026/2026-08-01")
        self.assertEqual(urls[1], "https://source.android.com/docs/security/bulletin/2026-08-01")

    def test_link_regex_matches_old_and_new(self):
        from patchwatch.sources.android import BULLETIN_LINK_RE
        html = ('<a href="/docs/security/bulletin/2026/2026-08-01">Aug</a>'
                '<a href="/docs/security/bulletin/2025-12-01">Dec</a>'
                '<a href="/docs/security/bulletin/pixel/2026/2026-08-01">Pixel</a>')
        self.assertEqual(
            sorted({m.group(2) for m in BULLETIN_LINK_RE.finditer(html)}),
            ["2025-12-01", "2026-08-01"],
        )


class TestDetailUnavailable(unittest.TestCase):
    """Google published the July and August 2026 bulletins with no vulnerability
    details section. The patch level is still the Intune remediation, so the release
    must still produce a ticket - flagged, never silently empty."""

    def _rel(self):
        from patchwatch.models import Release
        return Release(platform="android", product="Android Security Bulletin",
                       version="2026-08-01", release_date="2026-08-01",
                       advisory_url="x", vulns=[], details_unavailable=True)

    def test_still_needs_a_ticket(self):
        self.assertTrue(self._rel().needs_ticket("HIGH"))

    def test_empty_release_without_flag_does_not(self):
        from patchwatch.models import Release
        r = Release(platform="ios", product="iOS", version="1.0",
                    release_date="2026-08-01", advisory_url="x", vulns=[])
        self.assertFalse(r.needs_ticket("HIGH"))

    def test_intune_mapping_still_produced(self):
        from patchwatch.validate import deterministic_android_patch_level
        rec = deterministic_android_patch_level(self._rel())
        self.assertEqual(rec["value"], "2026-08-01")

    def test_ticket_body_states_the_gap(self):
        from patchwatch.deliver.jira import _body
        body = _body(self._rel(), {"summary": "s", "intune_recommendations": []})
        self.assertIn("NOT PUBLISHED", body)
