"""Apple: iOS, iPadOS, macOS (and optionally tvOS/watchOS/visionOS/Safari).

Primary source is SOFA, a community-maintained machine-readable feed for Apple
software updates, refreshed automatically via GitHub Actions. Its v2 feeds carry
CVE metadata, KEV status and severity context, which is considerably more than the
raw Apple HTML gives you.

  https://sofafeed.macadmins.io/v1/macos_data_feed.json
  https://sofafeed.macadmins.io/v1/ios_data_feed.json

Two operational notes from the SOFA maintainers:
  1. Set a custom User-Agent (patchwatch does, in http.py).
  2. Self-host a fork for production. Do it - it removes a third-party availability
     dependency from your alerting path. Point SOFA_BASE at your own Pages URL.

FIELD-NAME CAVEAT: the exact v2 schema should be verified against a live pull
before you trust this in production. Run `python -m patchwatch dump-schema apple`
on first setup; the parser below is deliberately tolerant of both v1 and v2 shapes
and will tell you loudly if it recognises neither.

The HTML fallback exists because SOFA can lag Apple by a few hours, and a rapid
security response for an actively-exploited bug is exactly the release you cannot
afford to see late.
"""

from __future__ import annotations

import os
import re
from html.parser import HTMLParser

from .. import http
from ..models import CVE_RE, Release, Vuln

SOFA_BASE = os.environ.get("SOFA_BASE", "https://sofafeed.macadmins.io")

FEEDS = {
    "macos": "/v1/macos_data_feed.json",
    "ios": "/v1/ios_data_feed.json",
}

APPLE_INDEX = "https://support.apple.com/en-us/100100"

# Apple's product naming in the releases index, mapped to our platform keys.
PRODUCT_PLATFORM = [
    (re.compile(r"^iOS and iPadOS|^iOS|^iPadOS", re.I), "ios"),
    (re.compile(r"^macOS", re.I), "macos"),
    (re.compile(r"^tvOS", re.I), "tvos"),
    (re.compile(r"^watchOS", re.I), "watchos"),
    (re.compile(r"^visionOS", re.I), "visionos"),
    (re.compile(r"^Safari", re.I), "safari"),
]

VERSION_RE = re.compile(r"(\d+(?:\.\d+)*(?:\s*\([a-z]\))?)")


def _platform_for(product: str) -> str | None:
    for pattern, platform in PRODUCT_PLATFORM:
        if pattern.search(product or ""):
            return platform
    return None


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _parse_cve_block(block, platform: str, exploited_ids: set[str]) -> list[Vuln]:
    """Normalise SOFA's CVE container across v1 and v2 shapes.

    v1: {"CVE-2024-1234": true, ...}   value == actively exploited flag
    v2: [{"CVE": "...", "Severity": "...", "KEV": true, "Description": "..."}, ...]
        (or a dict keyed by CVE id containing the same metadata)
    """
    vulns: list[Vuln] = []

    if isinstance(block, dict):
        for key, value in block.items():
            if not CVE_RE.fullmatch(key or ""):
                continue
            if isinstance(value, bool):                       # v1 shape
                vulns.append(
                    Vuln(cve_id=key, platform=platform, exploited=value or key in exploited_ids)
                )
            elif isinstance(value, dict):                     # v2 keyed-dict shape
                vulns.append(_vuln_from_meta(key, value, platform, exploited_ids))
    elif isinstance(block, list):
        for entry in block:
            if isinstance(entry, str) and CVE_RE.fullmatch(entry):
                vulns.append(
                    Vuln(cve_id=entry, platform=platform, exploited=entry in exploited_ids)
                )
            elif isinstance(entry, dict):
                cve_id = entry.get("CVE") or entry.get("cve") or entry.get("id")
                if cve_id and CVE_RE.fullmatch(cve_id):
                    vulns.append(_vuln_from_meta(cve_id, entry, platform, exploited_ids))

    return vulns


def _vuln_from_meta(cve_id: str, meta: dict, platform: str, exploited_ids: set[str]) -> Vuln:
    score = meta.get("CVSS") or meta.get("cvss_score") or meta.get("BaseScore")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None

    return Vuln(
        cve_id=cve_id,
        platform=platform,
        cvss_score=score,
        kev=bool(meta.get("KEV") or meta.get("kev") or meta.get("in_kev")),
        exploited=bool(meta.get("ActivelyExploited") or meta.get("exploited"))
        or cve_id in exploited_ids,
        component=meta.get("Component") or meta.get("component"),
        impact=meta.get("Description") or meta.get("Impact") or meta.get("impact") or "",
        severity_source="cna_cvss" if score is not None else "none",
    )


def _clean_product(product: str, version: str) -> str:
    """Strip the version out of the product name without leaving artefacts.

    SOFA gives names like "macOS Tahoe 26" alongside version "26.0", and
    "iOS 26 and iPadOS 26" alongside "26.0". A naive replace leaves "macOS Tahoe 26"
    and "iOS  and iPadOS" (note the double space).
    """
    # ORDER MATTERS. Remove the longest token first: stripping the major version "18"
    # out of "iOS 18.7.10" before the full "18.7.10" leaves an orphaned ".7.10".
    # A set here is a bug - iteration order is arbitrary.
    tokens = sorted({version, version.split(".")[0]}, key=len, reverse=True)
    cleaned = product
    for token in tokens:
        if token:
            cleaned = re.sub(rf"(?<!\d)\.?{re.escape(token)}(?![\d.])", "", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" .-")
    return cleaned or product


def _releases_from_feed(feed: dict, default_platform: str) -> list[Release]:
    releases: list[Release] = []
    unrecognised = True

    for os_version in _as_list(feed.get("OSVersions")):
        for entry in _as_list(os_version.get("SecurityReleases")):
            unrecognised = False
            product = entry.get("UpdateName") or os_version.get("OSVersion") or default_platform
            platform = _platform_for(product) or default_platform
            version_match = VERSION_RE.search(product)
            version = entry.get("ProductVersion") or (
                version_match.group(1) if version_match else "unknown"
            )

            exploited_ids = {
                c for c in _as_list(entry.get("ActivelyExploitedCVEs")) if isinstance(c, str)
            }
            vulns = _parse_cve_block(entry.get("CVEs"), platform, exploited_ids)

            releases.append(
                Release(
                    platform=platform,
                    product=_clean_product(product, version),
                    version=version,
                    release_date=(entry.get("ReleaseDate") or "")[:10],
                    advisory_url=entry.get("SecurityInfo") or APPLE_INDEX,
                    vulns=vulns,
                    source="sofa",
                )
            )

    if unrecognised and feed:
        raise http.FetchError(
            "sofa-feed",
            "no OSVersions/SecurityReleases found - the SOFA schema has likely changed. "
            "Run `python -m patchwatch dump-schema apple` and update sources/apple.py.",
        )
    return releases


def fetch(platforms: list[str] | None = None) -> list[Release]:
    """Pull Apple releases from SOFA. Raises FetchError rather than returning []."""
    wanted = set(platforms or ["ios", "macos"])
    out: list[Release] = []
    errors: list[str] = []

    for key, path in FEEDS.items():
        if key not in wanted and not (key == "ios" and "ipados" in wanted):
            continue
        try:
            feed = http.get_json(f"{SOFA_BASE}{path}")
            out.extend(_releases_from_feed(feed, key))
        except http.FetchError as exc:
            errors.append(str(exc))

    if not out and errors:
        raise http.FetchError("apple", "; ".join(errors))
    return out


# --------------------------------------------------------------------------
# HTML fallback
# --------------------------------------------------------------------------


class _AppleIndexParser(HTMLParser):
    """Extracts (product+version, advisory_url, date) rows from the releases index."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, str]] = []
        self._in_row = False
        self._cells: list[str] = []
        self._buf: list[str] = []
        self._href: str | None = None
        self._cell_href: str | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._in_row, self._cells, self._cell_href = True, [], None
        elif tag == "td" and self._in_row:
            self._buf, self._href = [], None
        elif tag == "a" and self._in_row:
            self._href = dict(attrs).get("href")

    def handle_endtag(self, tag):
        if tag == "td" and self._in_row:
            text = " ".join("".join(self._buf).split())
            self._cells.append(text)
            if self._href and self._cell_href is None:
                self._cell_href = self._href
        elif tag == "tr" and self._in_row:
            if len(self._cells) >= 3 and self._cells[0]:
                self.rows.append(
                    {
                        "product": self._cells[0],
                        "url": self._cell_href or "",
                        "date": self._cells[-1],
                    }
                )
            self._in_row = False

    def handle_data(self, data):
        if self._in_row:
            self._buf.append(data)


class _AdvisoryParser(HTMLParser):
    """Pulls Component / Impact / CVE triples out of an Apple advisory page."""

    def __init__(self) -> None:
        super().__init__()
        self.text_blocks: list[str] = []
        self._buf: list[str] = []
        self._capture = False

    def handle_starttag(self, tag, attrs):
        if tag in ("p", "h2", "h3", "div", "li"):
            self._capture, self._buf = True, []

    def handle_endtag(self, tag):
        if tag in ("p", "h2", "h3", "div", "li") and self._capture:
            text = " ".join("".join(self._buf).split())
            if text:
                self.text_blocks.append(text)
            self._capture = False

    def handle_data(self, data):
        if self._capture:
            self._buf.append(data)


def parse_advisory_html(html: str, platform: str) -> list[Vuln]:
    """Apple advisories follow: <component heading> / Available for: / Impact: /
    Description: / CVE-ID: . Parsed as a small state machine over text blocks."""
    parser = _AdvisoryParser()
    parser.feed(html)

    vulns: list[Vuln] = []
    component: str | None = None
    impact = ""

    for block in parser.text_blocks:
        if block.startswith("Impact:"):
            impact = block[len("Impact:") :].strip()
        elif block.startswith("CVE-ID:") or CVE_RE.search(block):
            for cve_id in CVE_RE.findall(block):
                vulns.append(
                    Vuln(cve_id=cve_id, platform=platform, component=component, impact=impact)
                )
            impact = ""
        elif block and not block.startswith(("Available for:", "Description:")) and len(block) < 60:
            component = block

    # Deduplicate, keeping the richest impact text per CVE.
    best: dict[str, Vuln] = {}
    for v in vulns:
        if v.cve_id not in best or len(v.impact) > len(best[v.cve_id].impact):
            best[v.cve_id] = v
    return list(best.values())


def fetch_html_fallback(platforms: list[str] | None = None, limit: int = 12) -> list[Release]:
    """Scrape support.apple.com directly. Slower and more fragile than SOFA -
    use only when the feed is stale or unreachable."""
    wanted = set(platforms or ["ios", "macos"])
    index = http.get_text(APPLE_INDEX, accept="text/html")
    parser = _AppleIndexParser()
    parser.feed(index)

    releases: list[Release] = []
    for row in parser.rows[:limit]:
        platform = _platform_for(row["product"])
        if platform not in wanted:
            continue
        url = row["url"]
        if url.startswith("/"):
            url = "https://support.apple.com" + url
        if not url:
            continue

        match = VERSION_RE.search(row["product"])
        version = match.group(1) if match else "unknown"
        try:
            vulns = parse_advisory_html(http.get_text(url, accept="text/html"), platform)
        except http.FetchError:
            continue

        releases.append(
            Release(
                platform=platform,
                product=row["product"].replace(version, "").strip(),
                version=version,
                release_date=row["date"],
                advisory_url=url,
                vulns=vulns,
                source="apple-html",
            )
        )
    return releases
