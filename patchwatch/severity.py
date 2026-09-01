"""Deterministic severity resolution.

NO LLM TOUCHES THIS FILE. Severity assignment is the security-critical decision in
the pipeline; it must be reproducible, auditable, and diffable in git.

Background: on 2026-04-15 NIST stopped enriching every CVE. CVEs outside its
risk-based criteria get status 'Not Scheduled' and will never receive an NVD CVSS
score. NIST also now defers to the CNA's score when one exists. A pipeline that
gates on "NVD says HIGH" therefore drops most Apple and Android CVEs silently.
This module replaces NVD-as-arbiter with an ordered ladder of faster, more
authoritative signals.
"""

from __future__ import annotations

import re

from .models import Vuln

# Apple never publishes CVSS. Its advisories signal in-the-wild exploitation with a
# stereotyped sentence. Matching it is the fastest exploitation signal available for
# Apple platforms - it lands the same day as the patch, whereas KEV listing can lag.
# Apple has used several phrasings over the years; match the invariant core.
APPLE_EXPLOITED_PATTERNS = [
    re.compile(r"may have been (?:actively )?exploited", re.I),
    re.compile(r"aware of a report that this (?:issue|problem) may have been exploited", re.I),
    re.compile(r"extremely sophisticated attack against specific targeted individuals", re.I),
    re.compile(r"has been (?:actively )?exploited", re.I),
]

# Impact-prose heuristics for Apple's unscored CVEs. These are conservative: they
# only ever RAISE an unknown to a floor, never lower an existing rating, and the
# resulting severity_source is recorded as 'impact_heuristic' so a human reviewing
# the ticket knows it was inferred rather than published.
# Apple writes impact in the verb form ("may be able to execute arbitrary code with
# kernel privileges"), while NVD and most CNAs use the noun form ("arbitrary code
# execution"). Both must match or the heuristic silently never fires on Apple - which
# is the exact platform it exists to serve.
_ARBITRARY_CODE = r"(?:execute arbitrary code|arbitrary code execution)"
_KERNEL_PRIV = r"(?:with (?:kernel|system) privileges)"

IMPACT_FLOORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(rf"{_ARBITRARY_CODE}\s+{_KERNEL_PRIV}", re.I), "CRITICAL"),
    (re.compile(rf"kernel\s+(?:code execution|memory (?:corruption|write))", re.I), "CRITICAL"),
    (re.compile(_ARBITRARY_CODE, re.I), "HIGH"),
    (re.compile(r"kernel memory", re.I), "HIGH"),
    (re.compile(r"elevate privileges|privilege escalation|gain root|elevated privileges", re.I), "HIGH"),
    (re.compile(r"(?:break out of|escape|bypass)\s.{0,40}?(sandbox|SIP|System Integrity|Gatekeeper|Pointer Authentication)", re.I), "HIGH"),
    (re.compile(r"overwrite arbitrary files|arbitrary file (?:write|overwrite)", re.I), "HIGH"),
    (re.compile(r"unexpected (?:system|app)? ?termination|denial[- ]of[- ]service", re.I), "MEDIUM"),
    (re.compile(r"read .{0,25}memory|information (?:leak|disclosure)|access sensitive|leak sensitive", re.I), "MEDIUM"),
]

EPSS_CRITICAL = 0.50   # >=50% chance of exploitation in 30 days
EPSS_HIGH = 0.10


def from_cvss(score: float) -> str:
    """CVSS v3.1 / v4.0 qualitative severity bands."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def detect_apple_exploitation(text: str) -> bool:
    return any(p.search(text or "") for p in APPLE_EXPLOITED_PATTERNS)


def impact_floor(impact: str) -> str | None:
    """First matching floor wins; patterns are ordered most-severe-first."""
    for pattern, level in IMPACT_FLOORS:
        if pattern.search(impact or ""):
            return level
    return None


def resolve(vuln: Vuln) -> Vuln:
    """Assign final severity by walking the precedence ladder. Mutates and returns.

    Precedence, highest authority first:
      1. CISA KEV membership          -> CRITICAL
      2. Vendor-asserted exploitation -> CRITICAL
      3. Vendor-native rating         -> as published (Android column, MSRC CVSS)
      4. CNA CVSS from cve.org        -> banded
      5. NVD CVSS, if any exists      -> banded
      6. EPSS probability             -> heuristic floor
      7. Impact prose heuristic       -> conservative floor, flagged as inferred
      8. Nothing                      -> UNKNOWN, routed to triage
    """
    # 1. KEV. Known-exploited beats every score. KEV entries are also the one slice
    #    where NVD data stays reliable, since NIST excluded them from the backlog.
    if vuln.kev:
        vuln.severity = "CRITICAL"
        vuln.severity_source = "kev"
        vuln.exploited = True
        return vuln

    # 2. Vendor says it is being exploited.
    if vuln.exploited or detect_apple_exploitation(vuln.impact):
        vuln.severity = "CRITICAL"
        vuln.severity_source = "vendor_exploited"
        vuln.exploited = True
        return vuln

    # 3. Vendor-native rating, already set by the fetcher (Android / MSRC).
    if vuln.severity_source == "vendor_rating" and vuln.severity != "UNKNOWN":
        return vuln

    # 4 & 5. A CVSS score from any authority.
    if vuln.cvss_score is not None:
        vuln.severity = from_cvss(vuln.cvss_score)
        if vuln.severity_source not in ("cna_cvss", "nvd"):
            vuln.severity_source = "cna_cvss"
        return vuln

    # 6. EPSS as a probabilistic stand-in when nobody scored it.
    if vuln.epss is not None and vuln.epss >= EPSS_HIGH:
        vuln.severity = "CRITICAL" if vuln.epss >= EPSS_CRITICAL else "HIGH"
        vuln.severity_source = "epss"
        return vuln

    # 7. Impact prose. Apple-shaped fallback.
    floor = impact_floor(vuln.impact)
    if floor:
        vuln.severity = floor
        vuln.severity_source = "impact_heuristic"
        return vuln

    # 8. Genuinely unknown. Do not drop - route to triage.
    vuln.severity = "UNKNOWN"
    vuln.severity_source = "none"
    return vuln


def resolve_all(vulns: list[Vuln]) -> list[Vuln]:
    return [resolve(v) for v in vulns]


def explain(vuln: Vuln) -> str:
    """Human-readable justification, embedded in tickets for auditability."""
    reasons = {
        "kev": "listed in the CISA KEV catalog",
        "vendor_exploited": "vendor reports in-the-wild exploitation",
        "vendor_rating": "severity published by the vendor",
        "cna_cvss": f"CVSS {vuln.cvss_score} from the CVE Program record",
        "nvd": f"CVSS {vuln.cvss_score} from NVD",
        "epss": f"EPSS {vuln.epss:.3f}" if vuln.epss else "EPSS",
        "impact_heuristic": "INFERRED from vendor impact text - no published score exists",
        "none": "no severity signal from any source - requires manual triage",
    }
    return reasons.get(vuln.severity_source, vuln.severity_source)
