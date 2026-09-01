"""Guards against the cold-start explosion: 260 releases and 12,474 CVEs."""
import sys
from datetime import date, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest

from patchwatch.models import Release
from patchwatch.pipeline import _apply_window, _within_window
from patchwatch.sources.microsoft import _release_date_of


def rel(d):
    return Release(platform="ios", product="iOS", version="1.0",
                   release_date=d, advisory_url="x")


class TestWindow(unittest.TestCase):
    def test_recent_kept(self):
        self.assertTrue(_within_window(rel(date.today().isoformat()), 30))

    def test_old_dropped(self):
        self.assertFalse(_within_window(rel("2021-10-25"), 30))

    def test_unparseable_date_kept_not_dropped(self):
        """Fail open. A stray old release is noise; a dropped current one is a miss."""
        for bad in ["", "20 Aug 2026", "unknown", None]:
            self.assertTrue(_within_window(rel(bad), 30), bad)

    def test_datetime_prefix_handled(self):
        self.assertTrue(_within_window(rel(date.today().isoformat() + "T10:00:00Z"), 30))


class TestPerPlatformWindow(unittest.TestCase):
    """Android publishes monthly. A 30-day window drops the current bulletin for
    most of every month - the pipeline reported 4 bulletins found and delivered
    none of them."""

    def _rel(self, platform, d):
        return Release(platform=platform, product="p", version=d,
                       release_date=d, advisory_url="x")

    def test_month_old_android_bulletin_survives(self):
        d = (date.today() - timedelta(days=31)).isoformat()
        self.assertTrue(_within_window(self._rel("android", d), 30))

    def test_month_old_apple_release_does_not(self):
        d = (date.today() - timedelta(days=31)).isoformat()
        self.assertFalse(_within_window(self._rel("ios", d), 30))

    def test_newest_per_platform_always_retained(self):
        """Safety net: no window misconfiguration can blind a whole platform."""
        old = (date.today() - timedelta(days=400)).isoformat()
        older = (date.today() - timedelta(days=800)).isoformat()
        kept = _apply_window([self._rel("android", old), self._rel("android", older)], 30)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].release_date, old)

    def test_windows_spans_two_patch_tuesdays(self):
        d = (date.today() - timedelta(days=40)).isoformat()
        self.assertTrue(_within_window(self._rel("windows", d), 30))


class TestMsrcDate(unittest.TestCase):
    def test_prefers_initial_over_current(self):
        """The 2017-bulletins-look-recent bug. Microsoft bumps CurrentReleaseDate
        when it revises old CVRF docs, so filtering on it pulls a decade of history."""
        d = _release_date_of({
            "ID": "2017-Apr",
            "InitialReleaseDate": "2017-04-11T07:00:00Z",
            "CurrentReleaseDate": "2026-08-15T07:00:00Z",
        })
        self.assertEqual(d, date(2017, 4, 11))

    def test_falls_back_to_release_id(self):
        self.assertEqual(_release_date_of({"ID": "2026-Aug"}), date(2026, 8, 1))
        self.assertEqual(_release_date_of({"ID": "2018-FEB"}), date(2018, 2, 1))

    def test_unknown_returns_none_so_caller_keeps_it(self):
        self.assertIsNone(_release_date_of({"ID": "weird"}))
