"""Pipeline orchestration: fetch -> enrich -> resolve -> analyse -> deliver.

Two invariants worth stating explicitly, because both are easy to lose during
refactors and both are the difference between a working alerting system and a
comforting one that quietly does nothing:

  1. A source that FAILS is not a source that found nothing. Fetch errors are
     collected and surfaced in the run summary, and the process exits non-zero. A
     green build with a broken Apple feed is the worst possible outcome.

  2. An UNSCORED CVE is not a low-severity CVE. Since NIST moved to risk-based
     enrichment most CVEs will never get an NVD score, so unscored items are routed
     to triage rather than filtered out.
"""

from __future__ import annotations

import os
import traceback
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from . import analyze as analyze_mod
from . import http
from .deliver import jira as jira_mod
from .deliver import urgent as urgent_mod
from .models import SEVERITY_ORDER, Release, Vuln
from .severity import resolve_all
from .sources import android, apple, enrich, microsoft
from .state import State
from .validate import Allowlist, deterministic_android_patch_level

DEFAULT_THRESHOLD = "HIGH"

# Releases older than this are ignored entirely. Without it, SOFA hands back Apple's
# full history (196 releases back to Monterey) and MSRC hands back every Patch Tuesday
# since 2017 - roughly 12,500 CVEs and 260 tickets on a cold start.
#
# This is a backstop applied AFTER fetch, deliberately independent of each source's own
# lookback. Sources disagree about what "release date" means and at least one of them
# will eventually lie to you; this catches it regardless.
DEFAULT_SINCE_DAYS = 30

# Per-platform overrides. Cadence differs enormously by vendor and one global
# number cannot serve all of them:
#   Apple   - unpredictable, often several releases a month -> 30 days is generous
#   Windows - Patch Tuesday, monthly + out-of-band          -> 45 days spans two
#   Android - strictly monthly, published on the 1st        -> needs ~100 days,
#             otherwise the current bulletin ages out before the next one lands
PLATFORM_SINCE_DAYS = {
    "android": 100,
    "windows": 45,
}


def _within_window(release: Release, since_days: int) -> bool:
    """Unparseable dates are KEPT, never dropped. A stray old release is noise;
    a dropped current one is a missed patch."""
    days = PLATFORM_SINCE_DAYS.get(release.platform, since_days)
    cutoff = date.today() - timedelta(days=days)
    raw = (release.release_date or "")[:10]
    try:
        return date.fromisoformat(raw) >= cutoff
    except (ValueError, TypeError):
        return True


def _apply_window(releases: list[Release], since_days: int) -> list[Release]:
    """Window each platform on its own cadence, then guarantee the newest release
    per platform survives regardless of age.

    That last guarantee is the real safety net: it means no tuning mistake in the
    table above can ever produce total blindness for a platform.
    """
    kept = [r for r in releases if _within_window(r, since_days)]
    kept_keys = {r.release_key for r in kept}

    newest: dict[str, Release] = {}
    for r in releases:
        current = newest.get(r.platform)
        if current is None or (r.release_date or "") > (current.release_date or ""):
            newest[r.platform] = r
    for r in newest.values():
        if r.release_key not in kept_keys:
            kept.append(r)
            print(f"  window: retained {r.title} (newest for {r.platform}, "
                  f"outside window)")
    return kept


@dataclass
class RunSummary:
    releases_seen: int = 0
    releases_new: int = 0
    releases_changed: int = 0
    releases_delivered: int = 0
    cves_seen: int = 0
    cves_actionable: int = 0
    cves_unscored: int = 0
    kev_hits: int = 0
    exploited: int = 0
    degraded_tickets: int = 0
    urgent_alerts: int = 0
    source_errors: list[str] = field(default_factory=list)
    nvd_stats: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            k: v for k, v in self.__dict__.items()
        }

    def render(self) -> str:
        lines = [
            "",
            "=" * 62,
            "patchwatch run summary",
            "=" * 62,
            f"  releases seen        {self.releases_seen}",
            f"    new                {self.releases_new}",
            f"    revised            {self.releases_changed}",
            f"    delivered          {self.releases_delivered}",
            f"  CVEs seen            {self.cves_seen}",
            f"    actionable         {self.cves_actionable}",
            f"    unscored (triage)  {self.cves_unscored}",
            f"    in KEV             {self.kev_hits}",
            f"    exploited          {self.exploited}",
            f"  urgent alerts        {self.urgent_alerts}",
            f"  degraded tickets     {self.degraded_tickets}",
        ]
        if self.nvd_stats:
            lines.append(
                f"  NVD: queried {self.nvd_stats.get('queried', 0)}, "
                f"scored {self.nvd_stats.get('scored', 0)}, "
                f"not-scheduled {self.nvd_stats.get('not_scheduled', 0)}"
            )
        if self.source_errors:
            lines.append("")
            lines.append("  SOURCE ERRORS (run is NOT clean):")
            for err in self.source_errors:
                lines.append(f"    ! {err}")
        lines.append("=" * 62)
        return "\n".join(lines)


def worst_severity(vulns: list[Vuln]) -> str:
    return min(
        (v.severity for v in vulns),
        key=lambda s: SEVERITY_ORDER.index(s),
        default="UNKNOWN",
    )


def fetch_all(platforms: list[str], summary: RunSummary, *, use_html_fallback: bool = True) -> list[Release]:
    releases: list[Release] = []

    apple_platforms = [p for p in platforms if p in ("ios", "ipados", "macos", "tvos", "watchos", "visionos", "safari")]
    if apple_platforms:
        try:
            got = apple.fetch(apple_platforms)
            releases.extend(got)
            print(f"  apple (sofa): {len(got)} releases")
        except http.FetchError as exc:
            summary.source_errors.append(f"apple/sofa: {exc}")
            if use_html_fallback:
                print(f"  apple: SOFA failed ({exc}); trying HTML fallback")
                try:
                    got = apple.fetch_html_fallback(apple_platforms)
                    releases.extend(got)
                    print(f"  apple (html fallback): {len(got)} releases")
                except http.FetchError as exc2:
                    summary.source_errors.append(f"apple/html: {exc2}")

    if "android" in platforms:
        try:
            android_errors: list[str] = []
            got = android.fetch(
                include_pixel=os.environ.get("PATCHWATCH_PIXEL") == "1",
                errors_out=android_errors,
            )
            releases.extend(got)
            print(f"  android: {len(got)} bulletins")
            # Partial failure must still be reported. Previously any bulletin that
            # failed to parse was silently discarded as long as ONE other bulletin
            # succeeded - so a change in the current month's format would hide
            # behind last month's working page.
            for err in android_errors:
                summary.source_errors.append(f"android: {err}")
            # Zero bulletins is NOT a quiet month. Google publishes monthly without
            # fail, so an empty result means the URL scheme or the page structure
            # changed. This is exactly the silent failure the pipeline must never have.
            if not got:
                summary.source_errors.append(
                    "android: fetched 0 bulletins - Google publishes monthly, so this "
                    "means the URL pattern or table markup changed. Run "
                    "`python -m patchwatch dump-schema android` to diagnose."
                )
        except http.FetchError as exc:
            summary.source_errors.append(f"android: {exc}")

    if "windows" in platforms:
        try:
            got = microsoft.fetch(include_edge=os.environ.get("PATCHWATCH_EDGE") == "1")
            releases.extend(got)
            print(f"  windows: {len(got)} releases")
            if not got:
                summary.source_errors.append("windows: fetched 0 releases from MSRC")
        except http.FetchError as exc:
            summary.source_errors.append(f"windows: {exc}")

    return releases


def enrich_all(releases: list[Release], summary: RunSummary, *, use_nvd: bool = True) -> None:
    all_vulns = [v for r in releases for v in r.vulns]
    if not all_vulns:
        return

    print(f"  enriching {len(all_vulns)} CVE records")

    try:
        kev = enrich.fetch_kev()
        summary.kev_hits = enrich.apply_kev(all_vulns, kev)
        print(f"    KEV: {summary.kev_hits} matches out of {len(kev)} catalogue entries")
    except http.FetchError as exc:
        summary.source_errors.append(f"kev: {exc}")

    try:
        scores = enrich.fetch_epss({v.cve_id for v in all_vulns})
        enrich.apply_epss(all_vulns, scores)
        print(f"    EPSS: {len(scores)} scores")
    except Exception as exc:  # noqa: BLE001 - EPSS is optional, never fatal
        summary.source_errors.append(f"epss: {exc}")

    looked_up = enrich.apply_cna(all_vulns)
    print(f"    CVE Program: {looked_up} lookups")

    if use_nvd:
        summary.nvd_stats = enrich.apply_nvd(all_vulns)
        print(f"    NVD: {summary.nvd_stats}")


def run(
    *,
    platforms: list[str] | None = None,
    threshold: str = DEFAULT_THRESHOLD,
    since_days: int = DEFAULT_SINCE_DAYS,
    state_path: str = "state/state.json",
    allowlist_path: str = "config/intune_allowlist.json",
    dry_run: bool = False,
    use_nvd: bool = True,
    use_model: bool = True,
) -> tuple[RunSummary, int]:
    platforms = platforms or ["ios", "macos", "android", "windows"]
    summary = RunSummary()
    state = State(state_path)
    allowlist = Allowlist(allowlist_path)
    jira = jira_mod.JiraClient()

    print(f"patchwatch: platforms={','.join(platforms)} threshold={threshold} "
          f"since_days={since_days} dry_run={dry_run}")
    print("\n[1/5] fetch")
    releases = fetch_all(platforms, summary)

    before = len(releases)
    releases = _apply_window(releases, since_days)
    if before != len(releases):
        by_platform: dict[str, int] = {}
        for r in releases:
            by_platform[r.platform] = by_platform.get(r.platform, 0) + 1
        print(f"  window: kept {len(releases)} of {before} releases  {by_platform}")
    summary.releases_seen = len(releases)

    print("\n[2/5] enrich")
    enrich_all(releases, summary, use_nvd=use_nvd)

    print("\n[3/5] resolve severity")
    for release in releases:
        resolve_all(release.vulns)
    all_vulns = [v for r in releases for v in r.vulns]
    summary.cves_seen = len(all_vulns)
    summary.cves_unscored = sum(1 for v in all_vulns if v.unscored)
    summary.exploited = sum(1 for v in all_vulns if v.exploited)
    print(f"  {summary.cves_seen} CVEs, {summary.exploited} exploited, "
          f"{summary.cves_unscored} unscored")

    print("\n[4/5] triage")
    work: list[tuple[Release, str, list[Vuln]]] = []
    for release in releases:
        status = state.classify(release)
        if status == "unchanged":
            continue

        actionable = release.actionable(threshold)
        if status == "changed" and not release.details_unavailable:
            # Only the newly added CVEs justify re-notifying, but the ticket update
            # should reflect the whole current set.
            added = set(state.newly_added_cves(release))
            if not any(v.cve_id in added for v in actionable):
                state.upsert_release(release, status)
                continue

        if not release.needs_ticket(threshold):
            state.upsert_release(release, status)
            continue

        work.append((release, status, actionable))
        summary.cves_actionable += len(actionable)
        if status == "new":
            summary.releases_new += 1
        else:
            summary.releases_changed += 1

    print(f"  {len(work)} releases require action")

    print("\n[5/5] deliver")
    for release, status, actionable in work:
        worst = worst_severity(actionable)
        print(f"  {release.title} [{status}] worst={worst} actionable={len(actionable)}")

        # -- analysis, with fallback ---------------------------------------
        if use_model:
            payload, result = analyze_mod.analyze(release, allowlist)
            if payload is None:
                reason = "; ".join(result.errors)[:200]
                print(f"    analysis rejected: {reason}")
                payload = analyze_mod.fallback_payload(release, allowlist, reason)
                summary.degraded_tickets += 1
            elif result.warnings:
                print(f"    warnings: {result.warnings}")
        else:
            payload = analyze_mod.fallback_payload(release, allowlist, "model step disabled")

        # Android's mapping is deterministic; inject it regardless of the model path.
        android_rec = deterministic_android_patch_level(release)
        if android_rec and not any(
            r.get("setting_key") == android_rec["setting_key"]
            for r in payload.get("intune_recommendations", [])
        ):
            payload.setdefault("intune_recommendations", []).insert(0, android_rec)

        # -- urgent path ----------------------------------------------------
        urgent_vulns = [
            v for v in actionable
            if (v.kev or v.exploited) and not state.already_alerted(v.cve_id)
        ]

        # -- ticket ----------------------------------------------------------
        ticket_url = None
        if dry_run:
            print(f"    [dry-run] would file ticket; {len(urgent_vulns)} urgent CVEs")
            print("    " + payload.get("summary", "")[:300].replace("\n", "\n    "))
        elif jira.configured:
            try:
                ticket = jira.upsert(release, payload, worst, status)
                ticket_url = ticket["url"]
                state.mark_delivered(release.release_key, ticket["key"], ticket_url)
                summary.releases_delivered += 1
                print(f"    jira {ticket['action']}: {ticket['key']}")
            except http.FetchError as exc:
                summary.source_errors.append(f"jira/{release.release_key}: {exc}")
                print(f"    jira FAILED: {exc}")
        else:
            print("    jira not configured; skipping ticket")

        if urgent_vulns and not dry_run and urgent_mod.configured():
            sent = urgent_mod.notify(release, urgent_vulns, ticket_url)
            if sent:
                summary.urgent_alerts += len(urgent_vulns)
                for v in urgent_vulns:
                    state.record_cve(v)
                    state.mark_alerted(v.cve_id)
                print(f"    urgent alert sent via {', '.join(sent)}")

        for v in release.vulns:
            state.record_cve(v)
        state.upsert_release(release, status)

    # Record every release we saw, including unchanged ones, so last_seen stays fresh.
    for release in releases:
        if release.release_key not in state.releases:
            state.upsert_release(release, "new")

    state.heartbeat(summary.as_dict())
    if not dry_run:
        state.save()
        print(f"\nstate written to {state_path}")

    print(summary.render())

    # Non-zero exit on any source error. A red build is how you find out the Apple
    # feed moved before you find out from an incident.
    exit_code = 1 if summary.source_errors else 0
    return summary, exit_code
