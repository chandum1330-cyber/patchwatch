"""State and dedupe tests, including the Apple retroactive-edit case."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from patchwatch.models import Release, Vuln
from patchwatch.state import State


def release(version="26.6.1", cves=("CVE-2026-1001",), platform="ios"):
    return Release(
        platform=platform, product="iOS and iPadOS", version=version,
        release_date="2026-08-20", advisory_url="https://support.apple.com/en-us/1",
        vulns=[Vuln(cve_id=c, platform=platform, severity="HIGH") for c in cves],
    )


class TestDedupe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_then_unchanged(self):
        s = State(self.path)
        r = release()
        self.assertEqual(s.classify(r), "new")
        s.upsert_release(r, "new")
        self.assertEqual(s.classify(release()), "unchanged")

    def test_apple_retroactive_cve_addition_detected(self):
        """Apple edits published advisories to add CVEs weeks later, marked
        'Entry added'. A release-key-only dedupe misses these entirely."""
        s = State(self.path)
        s.upsert_release(release(cves=("CVE-2026-1001",)), "new")

        revised = release(cves=("CVE-2026-1001", "CVE-2026-1002"))
        self.assertEqual(s.classify(revised), "changed")
        self.assertEqual(s.newly_added_cves(revised), ["CVE-2026-1002"])

        s.upsert_release(revised, "changed")
        rec = s.releases[revised.release_key]
        self.assertEqual(rec.revision, 2)
        self.assertIsNone(rec.delivered_at, "revision must force re-delivery")
        self.assertIn("CVE-2026-1002", rec.notes[-1])

    def test_cosmetic_change_does_not_trigger(self):
        s = State(self.path)
        r1 = release()
        s.upsert_release(r1, "new")
        r2 = release()
        r2.advisory_url = "https://support.apple.com/en-gb/1"
        self.assertEqual(s.classify(r2), "unchanged")

    def test_same_cve_across_platforms_is_separate_release(self):
        """One CVE spanning iOS and macOS is two patch actions, two tickets."""
        s = State(self.path)
        ios = release(platform="ios", version="26.6.1")
        mac = release(platform="macos", version="26.6.1")
        self.assertNotEqual(ios.release_key, mac.release_key)
        s.upsert_release(ios, "new")
        self.assertEqual(s.classify(mac), "new")

    def test_cve_record_tracks_platforms_and_never_downgrades(self):
        s = State(self.path)
        s.record_cve(Vuln(cve_id="CVE-2026-1001", platform="ios", severity="HIGH"))
        s.record_cve(Vuln(cve_id="CVE-2026-1001", platform="macos", severity="CRITICAL"))
        rec = s.cves["CVE-2026-1001"]
        self.assertEqual(rec.platforms, ["ios", "macos"])
        self.assertEqual(rec.severity, "CRITICAL")

        s.record_cve(Vuln(cve_id="CVE-2026-1001", platform="ios", severity="LOW"))
        self.assertEqual(s.cves["CVE-2026-1001"].severity, "CRITICAL",
                         "automatic de-escalation must never happen")

    def test_alert_dedupe(self):
        s = State(self.path)
        v = Vuln(cve_id="CVE-2026-1001", platform="ios", severity="CRITICAL", kev=True)
        s.record_cve(v)
        self.assertFalse(s.already_alerted("CVE-2026-1001"))
        s.mark_alerted("CVE-2026-1001")
        self.assertTrue(s.already_alerted("CVE-2026-1001"))


class TestPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        s = State(self.path)
        s.upsert_release(release(), "new")
        s.record_cve(Vuln(cve_id="CVE-2026-1001", platform="ios", severity="HIGH"))
        s.heartbeat({"releases_seen": 1})
        s.save()

        s2 = State(self.path)
        self.assertIn("ios-26-6-1", s2.releases)
        self.assertIn("CVE-2026-1001", s2.cves)
        self.assertIn("last_successful_run", s2.meta)

    def test_output_is_deterministic(self):
        """Sorted keys keep the committed diff reviewable."""
        s = State(self.path)
        for cve in ["CVE-2026-3003", "CVE-2026-1001", "CVE-2026-2002"]:
            s.record_cve(Vuln(cve_id=cve, platform="ios", severity="HIGH"))
        s.save()
        first = self.path.read_text()
        State(self.path).save()
        self.assertEqual(first, self.path.read_text())
        self.assertLess(first.index("CVE-2026-1001"), first.index("CVE-2026-2002"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
