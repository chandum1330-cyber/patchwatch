"""Pipeline state, committed back to the repo as sorted JSON.

Why a file in git rather than a database:
  - free, and survives runner teardown (Actions cache is evictable, so it is wrong
    for anything you must not lose)
  - every change to what the pipeline believes is a reviewable diff with an author
    and a timestamp, which is an audit trail you would otherwise have to build
  - trivially restorable by reverting a commit

Dedupe is keyed on (platform, release_key), NOT on CVE id. One CVE routinely spans
iOS, iPadOS and macOS in the same week, and each of those is a separate patch action
for a separate fleet.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ReleaseRecord:
    release_key: str
    platform: str
    title: str
    advisory_url: str
    release_date: str
    content_hash: str
    first_seen: str
    last_seen: str
    cve_ids: list[str] = field(default_factory=list)
    ticket_key: str | None = None
    ticket_url: str | None = None
    delivered_at: str | None = None
    revision: int = 1          # bumped when content_hash changes (Apple retro-edits)
    notes: list[str] = field(default_factory=list)


@dataclass
class CveRecord:
    """CVE-level view, independent of which release carried it."""

    cve_id: str
    severity: str
    severity_source: str
    kev: bool = False
    exploited: bool = False
    first_seen: str = ""
    last_updated: str = ""
    platforms: list[str] = field(default_factory=list)
    alerted: bool = False       # has an urgent alert already fired for this CVE


class State:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.releases: dict[str, ReleaseRecord] = {}
        self.cves: dict[str, CveRecord] = {}
        self.meta: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.meta = {"schema_version": SCHEMA_VERSION, "created": utcnow()}
            return
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        self.meta = raw.get("meta", {"schema_version": SCHEMA_VERSION})
        self.releases = {
            k: ReleaseRecord(**v) for k, v in raw.get("releases", {}).items()
        }
        self.cves = {k: CveRecord(**v) for k, v in raw.get("cves", {}).items()}

    def save(self) -> None:
        """Atomic write with sorted keys so diffs stay reviewable."""
        payload = {
            "meta": self.meta,
            "releases": {k: asdict(v) for k, v in sorted(self.releases.items())},
            "cves": {k: asdict(v) for k, v in sorted(self.cves.items())},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # -- release lifecycle ------------------------------------------------

    def classify(self, release: Any) -> str:
        """Return 'new', 'changed', or 'unchanged' for a freshly fetched release.

        'changed' is the case people forget. Apple edits published advisories to add
        CVEs days or weeks later, marking them 'Entry added'. Without a content hash
        those additions are invisible to a pipeline that only checks 'have I seen
        this release key before'.
        """
        existing = self.releases.get(release.release_key)
        if existing is None:
            return "new"
        if existing.content_hash != release.content_hash():
            return "changed"
        return "unchanged"

    def upsert_release(self, release: Any, status: str) -> ReleaseRecord:
        now = utcnow()
        key = release.release_key
        new_hash = release.content_hash()
        cve_ids = sorted({v.cve_id for v in release.vulns})

        if key in self.releases:
            rec = self.releases[key]
            if status == "changed":
                added = sorted(set(cve_ids) - set(rec.cve_ids))
                rec.revision += 1
                rec.notes.append(
                    f"{now}: advisory revised (rev {rec.revision}); "
                    f"added {', '.join(added) if added else 'no new CVEs'}"
                )
                rec.content_hash = new_hash
                rec.cve_ids = cve_ids
                rec.delivered_at = None   # force re-delivery as a ticket update
            rec.last_seen = now
        else:
            rec = ReleaseRecord(
                release_key=key,
                platform=release.platform,
                title=release.title,
                advisory_url=release.advisory_url,
                release_date=release.release_date,
                content_hash=new_hash,
                first_seen=now,
                last_seen=now,
                cve_ids=cve_ids,
            )
            self.releases[key] = rec
        return rec

    def newly_added_cves(self, release: Any) -> list[str]:
        """For a revised advisory: which CVEs were not present last time."""
        rec = self.releases.get(release.release_key)
        if rec is None:
            return sorted({v.cve_id for v in release.vulns})
        return sorted({v.cve_id for v in release.vulns} - set(rec.cve_ids))

    def mark_delivered(self, release_key: str, ticket_key: str, ticket_url: str) -> None:
        rec = self.releases.get(release_key)
        if rec:
            rec.ticket_key = ticket_key
            rec.ticket_url = ticket_url
            rec.delivered_at = utcnow()

    # -- cve lifecycle ----------------------------------------------------

    def record_cve(self, vuln: Any) -> CveRecord:
        now = utcnow()
        rec = self.cves.get(vuln.cve_id)
        if rec is None:
            rec = CveRecord(
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                severity_source=vuln.severity_source,
                kev=vuln.kev,
                exploited=vuln.exploited,
                first_seen=now,
                last_updated=now,
                platforms=[vuln.platform],
            )
            self.cves[vuln.cve_id] = rec
        else:
            rec.last_updated = now
            if vuln.platform not in rec.platforms:
                rec.platforms.append(vuln.platform)
                rec.platforms.sort()
            # Severity can be revised upward as KEV/EPSS/NVD catch up. Never downward
            # automatically - a de-escalation should be a human decision.
            from .models import SEVERITY_ORDER

            if SEVERITY_ORDER.index(vuln.severity) < SEVERITY_ORDER.index(rec.severity):
                rec.severity = vuln.severity
                rec.severity_source = vuln.severity_source
            rec.kev = rec.kev or vuln.kev
            rec.exploited = rec.exploited or vuln.exploited
        return rec

    def already_alerted(self, cve_id: str) -> bool:
        rec = self.cves.get(cve_id)
        return bool(rec and rec.alerted)

    def mark_alerted(self, cve_id: str) -> None:
        if cve_id in self.cves:
            self.cves[cve_id].alerted = True

    # -- health -----------------------------------------------------------

    def heartbeat(self, run_summary: dict[str, Any]) -> None:
        """Written every successful run.

        A stale heartbeat is how you notice GitHub silently disabled the schedule
        after 60 days of repo inactivity, or that cron has been quietly failing.
        Alert on this externally.
        """
        self.meta["last_successful_run"] = utcnow()
        self.meta["last_run_summary"] = run_summary
        self.meta["schema_version"] = SCHEMA_VERSION
