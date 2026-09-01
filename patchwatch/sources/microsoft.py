"""Windows, via the MSRC Security Updates (CVRF) API.

Best-behaved source in the pipeline. The API is public and unauthenticated - no key,
token or credentials needed - you just send Accept: application/json. It returns
CVSS scores inline, so Windows severity never depends on NVD.

Two quirks to design around:

  1. There is no server-side time filter. You pull the full /updates list and filter
     client-side. That is cheap; the list is small.

  2. DO NOT filter on CurrentReleaseDate. Microsoft revises old CVRF documents on an
     ongoing basis and bumps CurrentReleaseDate when it does, so a 2017 bulletin can
     carry a date from last week. Filtering on it pulls in a decade of Patch Tuesdays.
     Filter on InitialReleaseDate, and fall back to parsing the month out of the
     release ID ("2026-Aug") when that field is absent.

Release IDs are month-stamped, e.g. cvrf/v3.0/cvrf/2026-Aug. Out-of-band releases
appear in the same list with their own IDs.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

from .. import http
from ..models import Release, Vuln

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
JSON_HEADERS = {"Accept": "application/json"}

# MSRC returns everything Microsoft ships. Filter to the OS families you manage,
# otherwise every Patch Tuesday drags in Azure, SQL Server and Dynamics.
WINDOWS_PRODUCT_RE = re.compile(r"\bWindows\s+(10|11|Server)\b", re.I)
EDGE_PRODUCT_RE = re.compile(r"Microsoft Edge", re.I)

# CVRF threat types. 'Exploit Status' carries the exploited-in-the-wild assessment.
EXPLOITED_RE = re.compile(r"Exploited:\s*Yes", re.I)


def list_releases(since: date | None = None) -> list[dict]:
    data = http.get_json(f"{API_BASE}/updates", headers=JSON_HEADERS)
    releases = data.get("value", []) if isinstance(data, dict) else []
    if since is None:
        return releases

    out = []
    for rel in releases:
        when = _release_date_of(rel)
        if when is None:
            # Unparseable date: keep it rather than drop it. A spurious extra release
            # is a nuisance; a silently dropped Patch Tuesday is a missed CVE.
            out.append(rel)
        elif when >= since:
            out.append(rel)
    return out


MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def _release_date_of(rel: dict) -> date | None:
    """Original publication date. InitialReleaseDate first, then the release ID."""
    raw = rel.get("InitialReleaseDate") or ""
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
        except (ValueError, AttributeError):
            pass

    # IDs look like "2026-Aug" or "2018-FEB".
    match = re.fullmatch(r"(\d{4})-([A-Za-z]{3})", str(rel.get("ID", "")).strip())
    if match:
        year, mon = int(match.group(1)), MONTHS.get(match.group(2).lower())
        if mon:
            return date(year, mon, 1)
    return None


def _product_map(cvrf: dict) -> dict[str, str]:
    """ProductID -> full product name, flattened out of the nested ProductTree."""
    mapping: dict[str, str] = {}
    tree = cvrf.get("ProductTree", {}) or {}

    for prod in tree.get("FullProductName", []) or []:
        pid = prod.get("ProductID")
        if pid:
            mapping[str(pid)] = prod.get("Value", "")

    for branch in tree.get("Branch", []) or []:
        for item in branch.get("Items", []) or []:
            for prod in item.get("Items", []) or item.get("FullProductName", []) or []:
                pid = prod.get("ProductID")
                if pid:
                    mapping[str(pid)] = prod.get("Value", "")
    return mapping


def _best_cvss(vuln: dict) -> tuple[float | None, str | None]:
    """Highest base score across all product-specific CVSS sets."""
    best_score, best_vector = None, None
    for cvss in vuln.get("CVSSScoreSets", []) or []:
        raw = cvss.get("BaseScore")
        try:
            score = float(raw)
        except (TypeError, ValueError):
            continue
        if best_score is None or score > best_score:
            best_score, best_vector = score, cvss.get("Vector")
    return best_score, best_vector


def _is_exploited(vuln: dict) -> bool:
    for threat in vuln.get("Threats", []) or []:
        desc = (threat.get("Description", {}) or {}).get("Value", "")
        if EXPLOITED_RE.search(desc or ""):
            return True
    return False


def _title_of(vuln: dict) -> str:
    return (vuln.get("Title", {}) or {}).get("Value", "") or ""


def parse_cvrf(cvrf: dict, release_id: str, include_edge: bool = False) -> Release | None:
    products = _product_map(cvrf)
    doc_title = (cvrf.get("DocumentTitle", {}) or {}).get("Value", release_id)
    tracking = cvrf.get("DocumentTracking", {}) or {}
    release_date = (
        tracking.get("InitialReleaseDate") or tracking.get("CurrentReleaseDate") or ""
    )[:10]

    vulns: list[Vuln] = []
    for entry in cvrf.get("Vulnerability", []) or []:
        cve_id = entry.get("CVE")
        if not cve_id:
            continue

        affected = [products.get(str(pid), "") for pid in entry.get("ProductStatuses", [{}])[0].get("ProductID", [])] \
            if entry.get("ProductStatuses") else []
        joined = " ".join(affected)

        is_windows = bool(WINDOWS_PRODUCT_RE.search(joined))
        is_edge = bool(EDGE_PRODUCT_RE.search(joined))
        if not is_windows and not (include_edge and is_edge):
            continue

        score, vector = _best_cvss(entry)
        vulns.append(
            Vuln(
                cve_id=cve_id,
                platform="windows",
                cvss_score=score,
                cvss_vector=vector,
                severity_source="vendor_rating" if score is not None else "none",
                exploited=_is_exploited(entry),
                component="Microsoft Edge" if is_edge and not is_windows else "Windows",
                impact=_title_of(entry),
                references=[
                    f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
                ],
            )
        )

    if not vulns:
        return None

    # Severity for MSRC comes from the CVSS score; band it here so the ladder sees
    # a vendor_rating it can trust rather than falling through to NVD.
    from ..severity import from_cvss

    for v in vulns:
        if v.cvss_score is not None:
            v.severity = from_cvss(v.cvss_score)

    return Release(
        platform="windows",
        product=doc_title,
        version=release_id,
        release_date=release_date,
        advisory_url=f"https://msrc.microsoft.com/update-guide/releaseNote/{release_id}",
        vulns=vulns,
        source="msrc-cvrf",
    )


def fetch(lookback_days: int = 45, include_edge: bool = False) -> list[Release]:
    since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).date()
    releases: list[Release] = []

    for rel in list_releases(since=since):
        release_id = rel.get("ID")
        if not release_id:
            continue
        try:
            cvrf = http.get_json(f"{API_BASE}/cvrf/{release_id}", headers=JSON_HEADERS)
        except http.FetchError:
            continue
        parsed = parse_cvrf(cvrf, release_id, include_edge=include_edge)
        if parsed:
            releases.append(parsed)

    return releases
