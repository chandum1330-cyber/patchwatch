"""Cross-cutting enrichment applied to CVEs already discovered by the OS fetchers.

Deliberate ordering here mirrors severity.py: cheapest and most authoritative first,
NVD last. Each enricher only fills gaps - none of them overwrite a vendor rating.

Post-April-2026 reality check: NIST now labels CVEs outside its risk-based criteria
'Not Scheduled', meaning they will never receive an NVD CVSS score, and NIST defers
to the CNA's score when one exists. So the CVE Program record (cve.org) is usually a
better and faster source of CVSS than NVD, and NVD's main residual value is the
status label - knowing *why* a CVE has no score.
"""

from __future__ import annotations

import csv
import gzip
import io
import os
from datetime import date, timedelta

from .. import http
from ..models import Vuln

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVEAWG_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

# NVD: 5 requests per rolling 30s without a key, 50 with one. Get the free key.
_nvd_key = os.environ.get("NVD_API_KEY")
NVD_LIMITER = http.RateLimiter(max_calls=45 if _nvd_key else 4, window=30.0)
CVEAWG_LIMITER = http.RateLimiter(max_calls=20, window=10.0)


# ---------------------------------------------------------------- KEV

def fetch_kev() -> dict[str, dict]:
    """Whole catalogue as one JSON download, filtered locally. Never query per-CVE."""
    data = http.get_json(KEV_URL)
    return {
        entry["cveID"]: entry
        for entry in data.get("vulnerabilities", [])
        if entry.get("cveID")
    }


def apply_kev(vulns: list[Vuln], kev: dict[str, dict]) -> int:
    hits = 0
    for v in vulns:
        entry = kev.get(v.cve_id)
        if entry:
            v.kev = True
            v.exploited = True
            v.kev_due_date = entry.get("dueDate")
            hits += 1
    return hits


# ---------------------------------------------------------------- EPSS

def fetch_epss(cve_ids: set[str]) -> dict[str, float]:
    """FIRST publishes the full model output as one gzipped CSV daily. Free, no key.

    Only useful as a tiebreaker for CVEs nobody has scored, but that population is
    now large enough to matter.
    """
    try:
        raw = http.get(EPSS_URL, accept="application/gzip")
    except http.FetchError:
        return {}

    try:
        text = gzip.decompress(raw).decode("utf-8")
    except (OSError, EOFError):
        text = raw.decode("utf-8", errors="replace")

    scores: dict[str, float] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        if len(row) >= 2 and row[0] in cve_ids:
            try:
                scores[row[0]] = float(row[1])
            except ValueError:
                continue
    return scores


def apply_epss(vulns: list[Vuln], scores: dict[str, float]) -> None:
    for v in vulns:
        if v.cve_id in scores:
            v.epss = scores[v.cve_id]


# ------------------------------------------------- CVE Program (CNA)

def fetch_cna_cvss(cve_id: str) -> tuple[float | None, str | None]:
    """CVSS as published by the assigning CNA, from the CVE Program record.

    Faster than NVD and, since NIST now defers to CNA scores, usually identical to
    what NVD would eventually say. Apple is a CNA but does not publish CVSS, so this
    returns nothing for Apple CVEs - that is expected, not a bug.
    """
    try:
        record = http.get_json(CVEAWG_URL.format(cve_id=cve_id), limiter=CVEAWG_LIMITER)
    except http.FetchError:
        return None, None

    containers = record.get("containers", {}) or {}
    for section in ("cna", "adp"):
        blocks = containers.get(section) or []
        blocks = blocks if isinstance(blocks, list) else [blocks]
        for block in blocks:
            for metric in block.get("metrics", []) or []:
                for version_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                    cvss = metric.get(version_key)
                    if cvss and cvss.get("baseScore") is not None:
                        try:
                            return float(cvss["baseScore"]), cvss.get("vectorString")
                        except (TypeError, ValueError):
                            continue
    return None, None


def apply_cna(vulns: list[Vuln], max_lookups: int = 150) -> int:
    """Only queried for CVEs with no score yet. Budgeted to bound runtime."""
    looked_up = 0
    for v in vulns:
        if looked_up >= max_lookups:
            break
        if v.cvss_score is not None or v.kev or v.exploited:
            continue
        if v.severity_source == "vendor_rating":
            continue
        score, vector = fetch_cna_cvss(v.cve_id)
        looked_up += 1
        if score is not None:
            v.cvss_score, v.cvss_vector = score, vector
            v.severity_source = "cna_cvss"
    return looked_up


# ---------------------------------------------------------------- NVD

def fetch_nvd(cve_id: str) -> dict:
    headers = {"apiKey": _nvd_key} if _nvd_key else {}
    return http.get_json(NVD_URL.format(cve_id=cve_id), headers=headers, limiter=NVD_LIMITER)


def apply_nvd(vulns: list[Vuln], max_lookups: int = 60) -> dict[str, int]:
    """Last-resort scoring, plus the status label.

    Recording vulnStatus matters more than the score now. 'Not Scheduled' tells you
    definitively that no NVD score is ever coming, so the ticket should say
    'unscored by policy' rather than 'awaiting analysis' - the operator reading it
    needs to know not to wait.
    """
    stats = {"queried": 0, "scored": 0, "not_scheduled": 0, "awaiting": 0}

    for v in vulns:
        if stats["queried"] >= max_lookups:
            break
        if v.cvss_score is not None or v.severity_source in ("vendor_rating", "kev"):
            continue

        try:
            data = fetch_nvd(v.cve_id)
        except http.FetchError:
            continue
        stats["queried"] += 1

        items = data.get("vulnerabilities", []) or []
        if not items:
            continue
        cve = items[0].get("cve", {})
        v.nvd_status = cve.get("vulnStatus")

        if v.nvd_status == "Not Scheduled":
            stats["not_scheduled"] += 1
        elif v.nvd_status in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
            stats["awaiting"] += 1

        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore")
                if score is not None:
                    v.cvss_score = float(score)
                    v.cvss_vector = cvss.get("vectorString")
                    v.severity_source = "nvd"
                    stats["scored"] += 1
                break

        if not v.impact:
            for desc in cve.get("descriptions", []) or []:
                if desc.get("lang") == "en":
                    v.impact = desc.get("value", "")
                    break

    return stats
