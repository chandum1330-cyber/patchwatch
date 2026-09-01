"""Guardrail tests. Each case here is a real failure mode, not a hypothetical."""

import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from patchwatch.models import Release, Vuln
from patchwatch.validate import Allowlist, deterministic_android_patch_level, validate_analysis

ALLOWLIST = Allowlist(Path(__file__).resolve().parents[1] / "config" / "intune_allowlist.json")
TODAY = date(2026, 8, 31)


def ios_release():
    return Release(
        platform="ios", product="iOS and iPadOS", version="26.6.1",
        release_date="2026-08-20", advisory_url="https://support.apple.com/en-us/1",
        vulns=[
            Vuln(cve_id="CVE-2026-1001", platform="ios", severity="CRITICAL", kev=True),
            Vuln(cve_id="CVE-2026-1002", platform="ios", severity="HIGH", cvss_score=7.8),
        ],
    )


def good_payload(**over):
    payload = {
        "summary": "iOS 26.6.1 fixes two flaws including one known-exploited kernel bug.",
        "cited_versions": ["26.6.1"],
        "intune_recommendations": [{
            "setting_key": "ddm_target_os_version",
            "value": "26.6.1",
            "policy_path": "Devices > Configuration > Create policy > iOS/iPadOS > Settings catalog > Declarative Device Management (DDM) > Software Update",
            "rationale": "Pin to the patched version.",
        }],
        "enforcement_deadline": "2026-09-02T18:00:00",
    }
    payload.update(over)
    return payload


class TestHappyPath(unittest.TestCase):
    def test_valid_payload_passes(self):
        r = validate_analysis(good_payload(), ios_release(), ALLOWLIST, today=TODAY)
        self.assertTrue(r.ok, r.errors)


class TestHallucination(unittest.TestCase):
    def test_invented_cve_rejected(self):
        """The single most important check in the file."""
        bad = good_payload(summary="Also fixes CVE-2026-9999, a critical WebKit bug.")
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)
        self.assertTrue(any("CVE-2026-9999" in e for e in r.errors))

    def test_real_cves_in_prose_are_fine(self):
        ok = good_payload(summary="CVE-2026-1001 is known-exploited; patch immediately.")
        r = validate_analysis(ok, ios_release(), ALLOWLIST, today=TODAY)
        self.assertTrue(r.ok, r.errors)

    def test_invented_version_rejected(self):
        bad = good_payload(cited_versions=["26.6.1", "26.7.0"])
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)
        self.assertTrue(any("26.7.0" in e for e in r.errors))


class TestAllowlist(unittest.TestCase):
    def test_off_allowlist_setting_rejected(self):
        bad = good_payload(intune_recommendations=[{
            "setting_key": "enable_magic_patch_mode",
            "value": "on", "policy_path": "x", "rationale": "y",
        }])
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)
        self.assertTrue(any("not in the allowlist" in e for e in r.errors))

    def test_deprecated_intune_surface_rejected(self):
        """The DDM migration trap: a model on older data recommends the dead blade."""
        bad = good_payload(intune_recommendations=[{
            "setting_key": "ddm_target_os_version",
            "value": "26.6.1",
            "policy_path": "Devices > Update policies for iOS",
            "rationale": "Set the minimum version here.",
        }])
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)
        self.assertTrue(any("deprecated" in e.lower() for e in r.errors))

    def test_malformed_version_value_rejected(self):
        bad = good_payload(intune_recommendations=[{
            "setting_key": "ddm_target_os_version",
            "value": "latest",
            "policy_path": "Devices > Configuration > Create policy > iOS/iPadOS > Settings catalog > Declarative Device Management (DDM) > Software Update",
            "rationale": "z",
        }])
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)

    def test_rapid_security_response_version_accepted(self):
        """RSR versions look like '16.5.1 (a)' and must not be rejected as malformed."""
        rel = ios_release()
        rel.version = "26.6.1 (a)"
        ok = good_payload(cited_versions=["26.6.1 (a)"], intune_recommendations=[{
            "setting_key": "ddm_target_os_version",
            "value": "26.6.1 (a)",
            "policy_path": "Devices > Configuration > Create policy > iOS/iPadOS > Settings catalog > Declarative Device Management (DDM) > Software Update",
            "rationale": "Pin to the RSR.",
        }])
        r = validate_analysis(ok, rel, ALLOWLIST, today=TODAY)
        self.assertTrue(r.ok, r.errors)

    def test_integer_bounds_enforced(self):
        bad = good_payload(intune_recommendations=[{
            "setting_key": "ddm_enforce_latest_deferral_days",
            "value": 400,
            "policy_path": "Devices > Configuration > Create policy > iOS/iPadOS > Settings catalog > Declarative Device Management (DDM) > Software Update",
            "rationale": "z",
        }])
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)


class TestDeadlines(unittest.TestCase):
    def test_deadline_beyond_critical_window_rejected(self):
        far = (TODAY + timedelta(days=20)).isoformat() + "T18:00:00"
        r = validate_analysis(good_payload(enforcement_deadline=far), ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)
        self.assertTrue(any("policy window" in e for e in r.errors))

    def test_past_deadline_rejected(self):
        past = (TODAY - timedelta(days=1)).isoformat() + "T18:00:00"
        r = validate_analysis(good_payload(enforcement_deadline=past), ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)


class TestSeverityIsNotNegotiable(unittest.TestCase):
    def test_model_cannot_downgrade_severity(self):
        bad = good_payload(cve_notes=[{"cve_id": "CVE-2026-1001", "note": "minor", "severity": "LOW"}])
        r = validate_analysis(bad, ios_release(), ALLOWLIST, today=TODAY)
        self.assertFalse(r.ok)
        self.assertTrue(any("not yours to assign" in e for e in r.errors))


class TestDeterministicAndroid(unittest.TestCase):
    def test_patch_level_maps_directly(self):
        rel = Release(platform="android", product="Android Security Bulletin",
                      version="2026-08-01", release_date="2026-08-01", advisory_url="x")
        rec = deterministic_android_patch_level(rel)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["value"], "2026-08-01")
        self.assertEqual(rec["setting_key"], "compliance_min_security_patch_level")
        self.assertEqual(rec["source"], "deterministic")

    def test_non_android_returns_none(self):
        self.assertIsNone(deterministic_android_patch_level(ios_release()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
