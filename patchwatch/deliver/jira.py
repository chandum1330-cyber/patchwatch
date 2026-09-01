"""Jira delivery: one ticket per release, upserted.

Dedupe is belt-and-braces. The state file is the primary record, but Jira is queried
too, because state can be reverted, a run can die between creating a ticket and
committing state, and someone may have filed the ticket by hand. The label is set at
creation time so the JQL lookup is always reliable.

Revised advisories update the existing ticket with a comment rather than opening a
duplicate. Apple adds CVEs to published advisories weeks later; those additions need
to land on the ticket the team is already working.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from typing import Any

from .. import http
from ..models import Release
from ..severity import explain

LABEL_PREFIX = "patchwatch"

PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Medium",
}


class JiraClient:
    def __init__(
        self,
        base_url: str | None = None,
        email: str | None = None,
        token: str | None = None,
        project: str | None = None,
        issue_type: str = "Task",
    ):
        self.base_url = (base_url or os.environ.get("JIRA_BASE_URL", "")).rstrip("/")
        self.email = email or os.environ.get("JIRA_EMAIL", "")
        self.token = token or os.environ.get("JIRA_API_TOKEN", "")
        self.project = project or os.environ.get("JIRA_PROJECT", "")
        self.issue_type = os.environ.get("JIRA_ISSUE_TYPE", issue_type)

    @property
    def configured(self) -> bool:
        return all([self.base_url, self.email, self.token, self.project])

    def _headers(self) -> dict[str, str]:
        raw = f"{self.email}:{self.token}".encode()
        return {
            "Authorization": "Basic " + base64.b64encode(raw).decode(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # -- lookup -----------------------------------------------------------

    def find_by_label(self, label: str) -> dict[str, Any] | None:
        jql = f'project = "{self.project}" AND labels = "{label}" ORDER BY created DESC'
        url = f"{self.base_url}/rest/api/3/search?" + urllib.parse.urlencode(
            {"jql": jql, "maxResults": 1, "fields": "key,summary,status"}
        )
        try:
            data = http.get_json(url, headers=self._headers())
        except http.FetchError:
            return None
        issues = data.get("issues", [])
        return issues[0] if issues else None

    # -- write ------------------------------------------------------------

    def create(self, release: Release, analysis: dict[str, Any], worst: str) -> dict[str, Any]:
        label = f"{LABEL_PREFIX}-{release.release_key}"
        payload = {
            "fields": {
                "project": {"key": self.project},
                "issuetype": {"name": self.issue_type},
                "summary": _summary_line(release, worst),
                "description": _adf(_body(release, analysis)),
                "labels": [
                    label,
                    f"{LABEL_PREFIX}-{release.platform}",
                    f"{LABEL_PREFIX}-sev-{worst.lower()}",
                ],
            }
        }
        if worst in PRIORITY_MAP:
            payload["fields"]["priority"] = {"name": PRIORITY_MAP[worst]}

        result = http.post_json(
            f"{self.base_url}/rest/api/3/issue", payload, headers=self._headers()
        )
        key = result.get("key", "")
        return {"key": key, "url": f"{self.base_url}/browse/{key}"}

    def comment(self, issue_key: str, text: str) -> None:
        http.post_json(
            f"{self.base_url}/rest/api/3/issue/{issue_key}/comment",
            {"body": _adf(text)},
            headers=self._headers(),
        )

    # -- orchestration ----------------------------------------------------

    def upsert(
        self, release: Release, analysis: dict[str, Any], worst: str, status: str
    ) -> dict[str, Any]:
        label = f"{LABEL_PREFIX}-{release.release_key}"
        existing = self.find_by_label(label)

        if existing:
            key = existing["key"]
            if status == "changed":
                self.comment(
                    key,
                    f"Advisory revised. Current CVE count: {len(release.vulns)}. "
                    f"Highest severity: {worst}.\n\n"
                    + _body(release, analysis),
                )
            return {"key": key, "url": f"{self.base_url}/browse/{key}", "action": "updated"}

        created = self.create(release, analysis, worst)
        created["action"] = "created"
        return created


def _summary_line(release: Release, worst: str) -> str:
    n = len(release.vulns)
    exploited = sum(1 for v in release.vulns if v.exploited)
    tag = " [EXPLOITED]" if exploited else ""
    return f"[{worst}]{tag} {release.title} - {n} CVE{'s' if n != 1 else ''}"


def _body(release: Release, analysis: dict[str, Any]) -> str:
    lines = [analysis.get("summary", ""), ""]

    if analysis.get("_degraded"):
        lines += [
            "!! DEGRADED TICKET - automated Intune mapping was rejected by the "
            f"validator ({analysis.get('_degraded_reason')}). Configure manually. !!",
            "",
        ]

    if release.details_unavailable:
        lines += [
            "!! CVE DETAIL UNAVAILABLE - the vendor published this release without a "
            "vulnerability details section, so the CVE list below is EMPTY BECAUSE IT "
            "WAS NOT PUBLISHED, not because no CVEs were fixed. The patch level itself "
            "is still the required remediation. Re-check the advisory; vendors "
            "sometimes add detail on later revision. !!",
            "",
        ]

    lines += [f"Advisory: {release.advisory_url}", f"Released: {release.release_date}", ""]

    exploited = [v for v in release.vulns if v.exploited]
    if exploited:
        lines += ["ACTIVELY EXPLOITED:"]
        for v in exploited:
            lines.append(f"  {v.cve_id} - {explain(v)}")
        lines.append("")

    by_sev: dict[str, list] = {}
    for v in release.vulns:
        by_sev.setdefault(v.severity, []).append(v)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        group = by_sev.get(sev)
        if not group:
            continue
        lines.append(f"{sev} ({len(group)}):")
        for v in sorted(group, key=lambda x: x.cve_id):
            detail = f"  {v.cve_id}"
            if v.component:
                detail += f" [{v.component}]"
            detail += f" - {explain(v)}"
            lines.append(detail)
        lines.append("")

    unscored = [v for v in release.vulns if v.nvd_status == "Not Scheduled"]
    if unscored:
        lines += [
            f"NOTE: {len(unscored)} CVE(s) carry NVD status 'Not Scheduled'. NIST will "
            "not enrich these; do not wait for an NVD score that is never coming.",
            "",
        ]

    recs = analysis.get("intune_recommendations", [])
    if recs:
        lines.append("INTUNE CONFIGURATION:")
        for rec in recs:
            lines.append(f"  {rec.get('policy_path')}")
            lines.append(f"    {rec.get('setting_key')} = {rec.get('value')}")
            if rec.get("rationale"):
                lines.append(f"    {rec['rationale']}")
            if rec.get("source") == "deterministic":
                lines.append("    (computed deterministically, not model-generated)")
        lines.append("")

    if analysis.get("enforcement_deadline"):
        lines.append(f"Enforcement deadline: {analysis['enforcement_deadline']}")

    lines += ["", "--", "Filed automatically by patchwatch. Severity determined by "
              "deterministic rules, not by a language model."]
    return "\n".join(lines)


def _adf(text: str) -> dict[str, Any]:
    """Jira Cloud v3 wants Atlassian Document Format, not a plain string."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": para}]}
            for para in text.split("\n\n")
            if para.strip()
        ],
    }
