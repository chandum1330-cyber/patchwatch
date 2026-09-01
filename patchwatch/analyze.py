"""The one place a model is involved.

Scope is deliberately narrow. The model does NOT:
  - extract CVE ids            (regex, sources/*)
  - determine severity         (severity.py)
  - decide what gets a ticket  (pipeline.py)
  - compute Android patch level (validate.deterministic_android_patch_level)

The model DOES:
  - draft a human-readable summary for the ticket
  - propose Intune settings from a fixed allowlist
  - group related CVEs by attack surface

Structured outputs constrain the response to a JSON schema via constrained decoding,
which removes the JSON-parsing failure mode entirely. The parameter now lives at
output_config.format; the older output_format field plus the
structured-outputs-2025-11-13 beta header still work during the transition, and
SCHEMA_COMPAT below lets you fall back if your endpoint predates the move.

Schema complexity limits apply to strict schemas, so this one is kept flat and small
on purpose - nested objects and long optional-parameter lists burn the budget fast.
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import http
from .models import Release
from .severity import explain
from .validate import Allowlist, ValidationResult, validate_analysis

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.environ.get("PATCHWATCH_MODEL", "claude-sonnet-5")
ANTHROPIC_VERSION = "2023-06-01"

# Set to True if your endpoint still expects the pre-GA shape.
SCHEMA_COMPAT = os.environ.get("PATCHWATCH_SCHEMA_COMPAT", "").lower() in ("1", "true", "yes")

MAX_ATTEMPTS = 2


def build_schema(allowed_keys: list[str]) -> dict[str, Any]:
    """Enum-constrain setting_key at the schema level so the decoder cannot emit an
    off-allowlist key in the first place. validate.py still re-checks it - schema
    constraints and the validator are independent layers, on purpose."""
    return {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "2-4 sentences for a security engineer. What shipped, what class of bug, why it matters.",
            },
            "attack_surfaces": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Affected components grouped by attack surface, e.g. 'WebKit (remote, drive-by)'.",
            },
            "cited_versions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Every OS or build version string referenced. Must appear verbatim in the advisory.",
            },
            "intune_recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "setting_key": {"type": "string", "enum": allowed_keys},
                        "value": {"type": ["string", "integer"]},
                        "policy_path": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["setting_key", "value", "policy_path", "rationale"],
                    "additionalProperties": False,
                },
            },
            "enforcement_deadline": {
                "type": "string",
                "description": "ISO-8601 local datetime for the enforced install deadline.",
            },
            "cve_notes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string"},
                        "note": {"type": "string"},
                    },
                    "required": ["cve_id", "note"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["summary", "intune_recommendations", "cited_versions"],
        "additionalProperties": False,
    }


SYSTEM_PROMPT = """You assist a security engineering team with mobile and desktop patch triage.

Hard rules:
- Use ONLY the CVE identifiers present in the supplied advisory data. Never invent, \
infer, or recall a CVE id from memory. A fabricated CVE id in a security ticket is a \
serious defect.
- Never assign or revise severity. Severity has already been determined by \
deterministic code and is given to you as fact.
- Recommend ONLY settings from the supplied allowlist, using the exact setting_key \
strings provided.
- Apple has deprecated MDM-based software update workloads. Do not reference \
"Update policies for iOS", "Update policies for macOS", or any dedicated update \
policy blade. Apple software updates are configured through the Settings Catalog \
under Declarative Device Management.
- Quote version strings exactly as they appear in the advisory data.

Write for an engineer who will act on this within the hour. Be concrete and brief."""


def _render_context(release: Release, allowlist: Allowlist, max_cves: int = 60) -> str:
    vulns = sorted(
        release.vulns,
        key=lambda v: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"].index(v.severity), v.cve_id),
    )[:max_cves]

    lines = [
        f"RELEASE: {release.title}",
        f"PLATFORM: {release.platform}",
        f"VERSION: {release.version}" + (f" (build {release.build})" if release.build else ""),
        f"RELEASE DATE: {release.release_date}",
        f"ADVISORY: {release.advisory_url}",
        f"TOTAL CVEs: {len(release.vulns)}",
        "",
        "CVEs (severity is FINAL - do not revise):",
    ]
    for v in vulns:
        flags = []
        if v.kev:
            flags.append("KEV")
        if v.exploited:
            flags.append("EXPLOITED-IN-WILD")
        if v.nvd_status == "Not Scheduled":
            flags.append("NVD-WILL-NOT-SCORE")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        lines.append(
            f"  {v.cve_id}  {v.severity}{flag_str}  component={v.component or 'unspecified'}"
        )
        lines.append(f"      basis: {explain(v)}")
        if v.impact:
            lines.append(f"      impact: {v.impact[:240]}")

    if len(release.vulns) > max_cves:
        lines.append(f"  ... and {len(release.vulns) - max_cves} lower-severity CVEs omitted")

    allowed = allowlist.settings_for(release.platform)
    lines += ["", "PERMITTED INTUNE SETTINGS (use these setting_key values exactly):"]
    for key, spec in allowed.items():
        constraint = spec.get("pattern") or spec.get("values") or f"{spec.get('min')}-{spec.get('max')}"
        lines.append(f"  {key}: {spec['label']}  [type={spec.get('type')}, constraint={constraint}]")
        if spec.get("description"):
            lines.append(f"      {spec['description']}")

    lines += ["", "PERMITTED POLICY PATHS:"]
    for path in allowlist.paths_for(release.platform):
        lines.append(f"  {path}")

    worst = vulns[0].severity if vulns else "UNKNOWN"
    lines += [
        "",
        f"DEADLINE POLICY: {worst} severity requires enforcement within "
        f"{allowlist.max_deadline_days(worst)} days of today.",
    ]
    return "\n".join(lines)


def _call_api(messages: list[dict], schema: dict, api_key: str) -> dict[str, Any]:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
    }
    payload: dict[str, Any] = {
        "model": MODEL,
        "max_tokens": 2000,
        "system": SYSTEM_PROMPT,
        "messages": messages,
    }

    if SCHEMA_COMPAT:
        headers["anthropic-beta"] = "structured-outputs-2025-11-13"
        payload["output_format"] = {"type": "json_schema", "schema": schema}
    else:
        payload["output_config"] = {"format": {"type": "json_schema", "schema": schema}}

    data = http.post_json(API_URL, payload, headers=headers)

    text = "".join(
        block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
    )
    if not text.strip():
        raise ValueError(f"empty response (stop_reason={data.get('stop_reason')})")
    return json.loads(text)


def analyze(release: Release, allowlist: Allowlist) -> tuple[dict[str, Any] | None, ValidationResult]:
    """Returns (validated_payload, result). On failure the payload is None and the
    caller must fall back to a template-only ticket - never skip the release."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None, ValidationResult(ok=False, errors=["ANTHROPIC_API_KEY is not set"])

    schema = build_schema(sorted(allowlist.settings_for(release.platform)))
    context = _render_context(release, allowlist)
    messages: list[dict] = [{"role": "user", "content": context}]

    last = ValidationResult(ok=False, errors=["no attempt made"])

    for attempt in range(MAX_ATTEMPTS):
        try:
            payload = _call_api(messages, schema, api_key)
        except (http.FetchError, ValueError, json.JSONDecodeError) as exc:
            last = ValidationResult(ok=False, errors=[f"API call failed: {exc}"])
            break

        result = validate_analysis(payload, release, allowlist)
        if result.ok:
            return payload, result

        last = result
        if attempt < MAX_ATTEMPTS - 1:
            # Feed the validator's own errors back. One retry only - if the model
            # cannot satisfy a mechanical schema twice, the fallback is cheaper.
            messages += [
                {"role": "assistant", "content": json.dumps(payload)},
                {
                    "role": "user",
                    "content": (
                        "Your previous output failed validation:\n"
                        + result.as_feedback()
                        + "\n\nProduce a corrected response. Do not repeat these errors."
                    ),
                },
            ]

    return None, last


def fallback_payload(release: Release, allowlist: Allowlist, reason: str) -> dict[str, Any]:
    """Template-only analysis for when the model path fails.

    Deliberately still produces a usable ticket. Degraded, clearly labelled, and
    for Android still fully correct, because that mapping is deterministic anyway.
    """
    recs = []
    android_rec = None
    from .validate import deterministic_android_patch_level

    android_rec = deterministic_android_patch_level(release)
    if android_rec:
        recs.append(android_rec)

    worst = min(
        (v.severity for v in release.vulns),
        key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"].index(s),
        default="UNKNOWN",
    )
    counts: dict[str, int] = {}
    for v in release.vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))

    return {
        "summary": (
            f"{release.title} was published on {release.release_date} and addresses "
            f"{len(release.vulns)} CVEs ({breakdown}). Highest severity: {worst}.\n\n"
            f"AUTOMATED ANALYSIS UNAVAILABLE - {reason}. "
            f"Intune configuration requires manual review against {release.advisory_url}."
        ),
        "attack_surfaces": sorted({v.component for v in release.vulns if v.component}),
        "cited_versions": [release.version],
        "intune_recommendations": recs,
        "cve_notes": [],
        "_degraded": True,
        "_degraded_reason": reason,
    }
