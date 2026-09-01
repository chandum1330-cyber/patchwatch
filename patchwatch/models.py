"""Normalised data model. Every source fetcher emits these types and nothing else."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Ordered worst -> best. Index position is the comparison key.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]

# Where a severity came from. Lower index == more trustworthy / more timely.
# This ordering IS the precedence ladder; severity.py walks it in order.
SEVERITY_SOURCES = [
    "kev",               # CISA Known Exploited Vulnerabilities catalog
    "vendor_exploited",  # vendor says it is being exploited (Apple's wording, MSRC exploited flag)
    "vendor_rating",     # Android bulletin severity column, MSRC CVSS
    "cna_cvss",          # CVSS from the CVE Program record (cve.org), often beats NVD
    "nvd",               # NVD enrichment, when it exists at all
    "epss",              # exploit-probability heuristic, tiebreaker only
    "none",              # nothing known -> triage bucket, never silently dropped
]

PLATFORMS = ["ios", "ipados", "macos", "tvos", "watchos", "visionos", "safari", "android", "windows"]


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


@dataclass
class Vuln:
    """A single CVE as it appears in one platform's advisory."""

    cve_id: str
    platform: str
    severity: str = "UNKNOWN"
    severity_source: str = "none"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    kev: bool = False
    kev_due_date: str | None = None
    exploited: bool = False           # vendor-asserted in-the-wild exploitation
    epss: float | None = None
    component: str | None = None      # "Kernel", "WebKit", "Framework"
    impact: str = ""                  # vendor's prose impact statement
    nvd_status: str | None = None     # Analyzed | Awaiting Analysis | Not Scheduled | Rejected
    references: list[str] = field(default_factory=list)

    def at_or_above(self, threshold: str) -> bool:
        return SEVERITY_ORDER.index(self.severity) <= SEVERITY_ORDER.index(threshold)

    @property
    def unscored(self) -> bool:
        return self.severity == "UNKNOWN"


@dataclass
class Release:
    """One vendor release (e.g. iOS 26.6.1) carrying zero or more CVEs."""

    platform: str
    product: str                      # "iOS and iPadOS"
    version: str                      # "26.6.1"
    release_date: str                 # ISO-8601 date
    advisory_url: str
    vulns: list[Vuln] = field(default_factory=list)
    source: str = ""                  # which fetcher produced this
    build: str | None = None
    # Set when the vendor published the release but withheld CVE detail. The release
    # is still actionable (an Android patch level is an Intune setting on its own),
    # but the ticket must say the CVE list is unavailable rather than imply it is empty.
    details_unavailable: bool = False

    @property
    def release_key(self) -> str:
        """Stable identity for dedupe. Must never change for a given release."""
        return f"{self.platform}-{slugify(self.version)}"

    @property
    def title(self) -> str:
        return f"{self.product} {self.version}"

    def content_hash(self) -> str:
        """Detects Apple-style retroactive edits to an already-published advisory.

        Hashes only the fields whose change should force a re-review: the CVE set
        and each CVE's severity. Cosmetic advisory edits do not trigger reprocessing.
        """
        payload = sorted(
            (v.cve_id, v.severity, v.component or "", v.exploited) for v in self.vulns
        )
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def actionable(self, threshold: str = "HIGH") -> list[Vuln]:
        """CVEs meeting the alert bar, plus everything unscored.

        Unscored CVEs are included deliberately. Post-April-2026 the NVD leaves most
        CVEs permanently unenriched, so 'no score' means 'unknown', not 'low'.
        """
        return [v for v in self.vulns if v.at_or_above(threshold) or v.unscored]

    def needs_ticket(self, threshold: str = "HIGH") -> bool:
        """A release with no CVE detail still warrants a ticket when the vendor
        withheld the detail - the patch level itself is the remediation."""
        return bool(self.actionable(threshold)) or self.details_unavailable

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
