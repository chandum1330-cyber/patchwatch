"""Guardrails. Every byte the model produces passes through here before delivery.

Design stance: the validator fails CLOSED on correctness (reject anything unverified)
but the pipeline fails OPEN on delivery (ship a template-only ticket flagged for
manual review). A ticket saying "model output rejected, needs manual Intune mapping"
is still a ticket someone sees. A dropped release is not.

Checks, in order of how badly they bite:
  1. Every CVE id in the output must exist in the input set. Catches hallucinated
     CVEs, which in a security ticket are worse than no ticket at all.
  2. Every version string must appear verbatim in source data.
  3. Every setting key must be in the allowlist, and its value must match the
     declared type and pattern.
  4. No deprecated terminology (the Apple DDM migration trap).
  5. Deadlines within the severity-banded policy window.
  6. Severity fields, if present, must match what severity.py already decided. The
     model does not get a vote on severity.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import CVE_RE, Release


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    cleaned: dict[str, Any] | None = None

    def as_feedback(self) -> str:
        """Rendered back into the retry prompt so the model can self-correct."""
        return "\n".join(f"- {e}" for e in self.errors)


class Allowlist:
    def __init__(self, path: str | Path):
        self.raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self.platforms = self.raw["platforms"]
        self.deprecated = [t.lower() for t in self.raw.get("deprecated_terms", [])]
        self.deadlines = self.raw.get("deadline_policy", {})

    def settings_for(self, platform: str) -> dict[str, Any]:
        key = "ios" if platform in ("ios", "ipados") else platform
        return self.platforms.get(key, {}).get("settings", {})

    def paths_for(self, platform: str) -> list[str]:
        key = "ios" if platform in ("ios", "ipados") else platform
        return self.platforms.get(key, {}).get("policy_paths", [])

    def max_deadline_days(self, severity: str) -> int:
        return int(self.deadlines.get(severity, self.deadlines.get("UNKNOWN", 14)))


def _check_value(key: str, value: Any, spec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    vtype = spec.get("type")

    if vtype == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"setting '{key}' must be an integer, got {type(value).__name__}"]
        lo, hi = spec.get("min"), spec.get("max")
        if lo is not None and value < lo:
            errors.append(f"setting '{key}' value {value} below minimum {lo}")
        if hi is not None and value > hi:
            errors.append(f"setting '{key}' value {value} above maximum {hi}")
        return errors

    if vtype == "enum":
        allowed = spec.get("values", [])
        if value not in allowed:
            errors.append(f"setting '{key}' value '{value}' not in {allowed}")
        return errors

    if not isinstance(value, str):
        return [f"setting '{key}' must be a string, got {type(value).__name__}"]

    pattern = spec.get("pattern")
    if pattern and not re.fullmatch(pattern, value):
        errors.append(f"setting '{key}' value '{value}' does not match required format {pattern}")
    return errors


def validate_analysis(
    payload: dict[str, Any],
    release: Release,
    allowlist: Allowlist,
    *,
    today: date | None = None,
) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    today = today or date.today()

    known_cves = {v.cve_id for v in release.vulns}
    severity_by_cve = {v.cve_id: v.severity for v in release.vulns}
    worst = min(
        (v.severity for v in release.vulns),
        key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"].index(s),
        default="UNKNOWN",
    )

    # ---- 1. hallucinated CVE detection -------------------------------------
    blob = json.dumps(payload)
    for cve_id in set(CVE_RE.findall(blob)):
        if cve_id not in known_cves:
            errors.append(
                f"output references {cve_id}, which is not in this advisory. "
                f"Only these CVEs exist here: {', '.join(sorted(known_cves)) or '(none)'}"
            )

    # ---- 2. version strings must be real -----------------------------------
    source_versions = {release.version}
    if release.build:
        source_versions.add(release.build)
    for cited in payload.get("cited_versions", []) or []:
        if cited not in source_versions:
            errors.append(
                f"output cites version '{cited}' which does not appear in the advisory "
                f"(advisory version is '{release.version}')"
            )

    # ---- 3 & 4. settings allowlist and deprecated terminology --------------
    allowed = allowlist.settings_for(release.platform)
    recs = payload.get("intune_recommendations", [])
    if not isinstance(recs, list):
        errors.append("'intune_recommendations' must be a list")
        recs = []

    for i, rec in enumerate(recs):
        if not isinstance(rec, dict):
            errors.append(f"recommendation[{i}] is not an object")
            continue
        key = rec.get("setting_key")
        if key not in allowed:
            errors.append(
                f"recommendation[{i}] setting_key '{key}' is not in the allowlist for "
                f"{release.platform}. Permitted keys: {', '.join(sorted(allowed))}"
            )
            continue
        errors.extend(_check_value(key, rec.get("value"), allowed[key]))

        path = (rec.get("policy_path") or "").lower()
        for term in allowlist.deprecated:
            if term in path or term in (rec.get("rationale") or "").lower():
                errors.append(
                    f"recommendation[{i}] references deprecated Intune surface '{term}'. "
                    "Apple MDM-based software update policies are being retired; use the "
                    "Settings Catalog DDM path instead."
                )

    # ---- 5. deadline sanity -------------------------------------------------
    max_days = allowlist.max_deadline_days(worst)
    deadline = payload.get("enforcement_deadline")
    if deadline:
        try:
            parsed = datetime.fromisoformat(deadline.replace("Z", "")).date()
        except (ValueError, AttributeError):
            errors.append(f"enforcement_deadline '{deadline}' is not a valid ISO-8601 datetime")
        else:
            if parsed < today:
                errors.append(f"enforcement_deadline '{deadline}' is in the past")
            elif parsed > today + timedelta(days=max_days):
                errors.append(
                    f"enforcement_deadline '{deadline}' exceeds the {max_days}-day policy "
                    f"window for {worst} severity"
                )

    # ---- 6. the model does not get a vote on severity -----------------------
    for i, item in enumerate(payload.get("cve_notes", []) or []):
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cve_id")
        claimed = item.get("severity")
        if claimed and cve_id in severity_by_cve and claimed != severity_by_cve[cve_id]:
            errors.append(
                f"cve_notes[{i}] claims severity '{claimed}' for {cve_id}, but the "
                f"pipeline determined '{severity_by_cve[cve_id]}'. Severity is not "
                "yours to assign - omit the field."
            )

    # ---- soft checks ---------------------------------------------------------
    summary = payload.get("summary", "")
    if not summary or len(summary) < 20:
        warnings.append("summary is missing or very short")
    if len(summary) > 2000:
        warnings.append("summary is unusually long; it will be truncated in the ticket")
    if not recs:
        warnings.append("no Intune recommendations produced")

    return ValidationResult(
        ok=not errors, errors=errors, warnings=warnings, cleaned=payload if not errors else None
    )


def deterministic_android_patch_level(release: Release) -> dict[str, Any] | None:
    """Android's Intune mapping needs no model at all.

    The bulletin's patch-level date IS the value Intune's 'Minimum security patch
    level' compliance setting expects. Computing it in code removes an entire class
    of failure from the Android path.
    """
    if release.platform != "android":
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", release.version):
        return None
    return {
        "setting_key": "compliance_min_security_patch_level",
        "value": release.version,
        "policy_path": "Devices > Compliance policies > Create policy > Android Enterprise",
        "rationale": (
            f"Android bulletin {release.version} patch level maps directly onto the "
            "minimum security patch level compliance setting."
        ),
        "source": "deterministic",
    }
