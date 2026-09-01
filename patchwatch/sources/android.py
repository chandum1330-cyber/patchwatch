"""Android Security Bulletin.

The easy case. Unlike Apple, Google rates every CVE in the bulletin table itself
(Critical / High / Moderate / Low), so severity arrives the same day as the patch
with no enrichment round-trip. Those ratings map straight onto severity_source
'vendor_rating' and short-circuit the rest of the ladder.

Cadence is monthly, first Monday-ish. Bulletin URLs are date-stamped:
    https://source.android.com/docs/security/bulletin/2026-08-01

The bulletin's security patch level date is also the exact value Intune's Android
compliance policy expects, which makes the Intune mapping for Android purely
deterministic - no model involved. See config/intune_allowlist.json.
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from html.parser import HTMLParser

from .. import http
from ..models import CVE_RE, Release, Vuln

BULLETIN_BASE = "https://source.android.com/docs/security/bulletin"
BULLETIN_INDEX = "https://source.android.com/docs/security/bulletin"

# Google changed the URL scheme in 2026: a year segment was inserted.
#   2025 and earlier:  /docs/security/bulletin/2025-12-01
#   2026 and later:    /docs/security/bulletin/2026/2026-08-01
# Both forms must be matched, and both must be tried when guessing.
BULLETIN_LINK_RE = re.compile(
    r"/docs/security/bulletin/(?:(\d{4})/)?(\d{4}-\d{2}-\d{2})\b"
)
PIXEL_BASE = "https://source.android.com/docs/security/bulletin/pixel"

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
}


class _TableParser(HTMLParser):
    """Collects every table row as a list of cell strings."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._row: list[str] | None = None
        self._buf: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._buf = []

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._row is not None and self._buf is not None:
            self._row.append(" ".join("".join(self._buf).split()))
            self._buf = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._buf is not None:
            self._buf.append(data)


def _severity_in(cells: list[str]) -> str:
    for cell in cells:
        key = cell.strip().lower()
        if key in SEVERITY_MAP:
            return SEVERITY_MAP[key]
    return "UNKNOWN"


def _component_in(cells: list[str], cve_index: int) -> str | None:
    """The cell before the CVE is usually the component or bug reference."""
    for i in range(cve_index - 1, -1, -1):
        cell = cells[i].strip()
        if cell and not CVE_RE.search(cell) and cell.lower() not in SEVERITY_MAP:
            return cell[:80]
    return None


def parse_bulletin(html: str, patch_level: str) -> list[Vuln]:
    parser = _TableParser()
    parser.feed(html)

    seen: dict[str, Vuln] = {}
    for cells in parser.rows:
        cve_ids: list[str] = []
        cve_index = 0
        for i, cell in enumerate(cells):
            found = CVE_RE.findall(cell)
            if found:
                cve_ids.extend(found)
                cve_index = i
        if not cve_ids:
            continue

        severity = _severity_in(cells)
        component = _component_in(cells, cve_index)

        for cve_id in cve_ids:
            # Keep the most severe rating if a CVE appears in multiple tables.
            existing = seen.get(cve_id)
            if existing and existing.severity != "UNKNOWN" and severity == "UNKNOWN":
                continue
            seen[cve_id] = Vuln(
                cve_id=cve_id,
                platform="android",
                severity=severity,
                severity_source="vendor_rating" if severity != "UNKNOWN" else "none",
                component=component,
                impact=f"Android {patch_level} security patch level; component {component or 'unknown'}",
            )
    return list(seen.values())


def discover_bulletins(limit: int = 6) -> list[str]:
    """Read the bulletin index and extract real patch-level dates.

    Preferred over guessing URLs from today's date. Guessing assumes Google's URL
    pattern never changes and that bulletins always land on the 1st or 5th; index
    discovery just reads what actually exists. Falls back to guessing if the index
    is unreachable.
    """
    try:
        html = http.get_text(BULLETIN_INDEX, accept="text/html")
    except http.FetchError:
        return []
    seen: list[str] = []
    for match in BULLETIN_LINK_RE.finditer(html):
        level = match.group(2)
        if level not in seen:
            seen.append(level)
    seen.sort(reverse=True)
    return seen[:limit]


def bulletin_urls(patch_level: str) -> list[str]:
    """Both URL shapes for a patch level, newest scheme first."""
    year = patch_level[:4]
    return [
        f"{BULLETIN_BASE}/{year}/{patch_level}",   # 2026+
        f"{BULLETIN_BASE}/{patch_level}",          # 2025 and earlier
    ]


def candidate_patch_levels(today: date | None = None, lookback_months: int = 3) -> list[str]:
    """Android publishes on the 1st and sometimes the 5th of the month."""
    today = today or date.today()
    levels: list[str] = []
    cursor = today.replace(day=1)
    for _ in range(lookback_months):
        levels.append(cursor.strftime("%Y-%m-01"))
        levels.append(cursor.strftime("%Y-%m-05"))
        cursor = (cursor - timedelta(days=1)).replace(day=1)
    return levels


def probe(lookback_months: int = 2) -> list[tuple[str, str]]:
    """Diagnostic: report the outcome of every candidate URL.

    Used by `dump-schema android`. Distinguishes the three ways this fetcher can
    return nothing: every URL 404s (wrong date pattern), the fetch is blocked
    (403/429), or the page loads but no CVE rows parse (markup changed).
    """
    results: list[tuple[str, str]] = []

    try:
        index_html = http.get_text(BULLETIN_INDEX, accept="text/html")
        links = BULLETIN_LINK_RE.findall(index_html)
        results.append((BULLETIN_INDEX, (
            f"INDEX OK: {len(index_html)} bytes, {len(set(links))} bulletin links found"
            + (f" (newest: {sorted(set(links))[-1]})" if links else " - NO LINKS MATCHED")
        )))
    except http.FetchError as exc:
        results.append((BULLETIN_INDEX, f"INDEX FETCH FAILED: {exc}"))

    discovered = discover_bulletins()
    guessed = candidate_patch_levels(lookback_months=lookback_months)
    for patch_level in (discovered or guessed):
        html, url, tried = None, None, []
        for candidate in bulletin_urls(patch_level):
            tried.append(candidate)
            try:
                html = http.get_text(candidate, accept="text/html")
                url = candidate
                break
            except http.FetchError as exc:
                results.append((candidate, f"FETCH FAILED: {exc}"))
        if html is None:
            continue
        vulns = parse_bulletin(html, patch_level)
        if vulns:
            results.append((url, f"OK: {len(vulns)} CVEs parsed"))
        else:
            has_tables = "<table" in html.lower()
            has_cve = "CVE-" in html
            results.append((url, (
                f"LOADED but 0 CVEs parsed (len={len(html)}, "
                f"tables={has_tables}, cve_text={has_cve})"
            )))
    return results


def fetch(
    lookback_months: int = 3,
    include_pixel: bool = False,
    errors_out: list[str] | None = None,
) -> list[Release]:
    releases: list[Release] = []
    errors: list[str] = []
    found_any = False

    levels = discover_bulletins()
    if levels:
        print(f"    android: discovered {len(levels)} bulletins from the index")
    else:
        levels = candidate_patch_levels(lookback_months=lookback_months)
        errors.append(
            "android: bulletin index unreachable or contained no bulletin links; "
            "fell back to guessing dated URLs"
        )

    for patch_level in levels:
        html, url = None, None
        for candidate in bulletin_urls(patch_level):
            try:
                html = http.get_text(candidate, accept="text/html")
                url = candidate
                break
            except http.FetchError as exc:
                if "HTTP 404" not in str(exc):
                    errors.append(f"{candidate}: {exc}")
        if html is None:
            continue

        vulns = parse_bulletin(html, patch_level)
        if not vulns:
            # The page loaded but contained no parseable CVE rows. That is a markup
            # change, not an empty bulletin - record it rather than moving on quietly.
            if "CVE-" in html:
                errors.append(
                    f"{url}: page loaded and contains CVE text, but no rows parsed "
                    "- the bulletin table markup has changed"
                )
            else:
                # As of the August 2026 bulletin, Google publishes the bulletin body
                # (mitigations, FAQ, Versions table) with NO vulnerability details
                # table listing CVEs. Whether the table is added on later revision,
                # moved to a per-component page, or dropped entirely is unresolved.
                # Either way it is a publishing change, not a quiet month - say so.
                errors.append(
                    f"{url}: bulletin loaded ({len(html)} bytes) but contains no CVE "
                    "identifiers. Google published the July and August 2026 bulletins "
                    "without vulnerability detail sections. Filing the patch level "
                    "anyway - the Intune setting does not depend on the CVE list."
                )
                # Still emit it. The patch-level date is the remediation.
                found_any = True
                releases.append(
                    Release(
                        platform="android",
                        product="Android Security Bulletin",
                        version=patch_level,
                        release_date=patch_level,
                        advisory_url=url,
                        vulns=[],
                        source="android-bulletin",
                        details_unavailable=True,
                    )
                )
            continue
        found_any = True
        releases.append(
            Release(
                platform="android",
                product="Android Security Bulletin",
                version=patch_level,
                release_date=patch_level,
                advisory_url=url,
                vulns=vulns,
                source="android-bulletin",
            )
        )

        if include_pixel:
            pixel_url = f"{PIXEL_BASE}/{patch_level}"
            try:
                pixel_html = http.get_text(pixel_url, accept="text/html")
                pixel_vulns = parse_bulletin(pixel_html, patch_level)
                if pixel_vulns:
                    releases.append(
                        Release(
                            platform="android",
                            product="Pixel Update Bulletin",
                            version=f"pixel-{patch_level}",
                            release_date=patch_level,
                            advisory_url=pixel_url,
                            vulns=pixel_vulns,
                            source="pixel-bulletin",
                        )
                    )
            except http.FetchError:
                pass

    # Surface errors even on PARTIAL success. Returning bulletins while swallowing
    # the failures means a format change in the newest bulletin stays invisible.
    if errors_out is not None:
        errors_out.extend(errors)
    if not found_any and errors:
        raise http.FetchError("android", "; ".join(errors))
    return releases
