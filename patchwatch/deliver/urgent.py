"""Fast path for KEV and actively-exploited CVEs.

These must not sit in a Jira queue behind a routine ticket. This fires a webhook the
moment such a CVE is seen, independently of and in addition to the ticket. Works with
a Slack incoming webhook or a PagerDuty Events v2 routing key - both are just a POST.

Deduped on the CVE-level 'alerted' flag in state, so a KEV CVE spanning iOS, iPadOS
and macOS pages once, not three times.
"""

from __future__ import annotations

import os
from typing import Any

from .. import http
from ..models import Release, Vuln
from ..severity import explain

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
PAGERDUTY_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
PAGERDUTY_URL = "https://events.pagerduty.com/v2/enqueue"


def configured() -> bool:
    return bool(SLACK_WEBHOOK or PAGERDUTY_KEY)


def _slack_blocks(release: Release, vulns: list[Vuln], ticket_url: str | None) -> dict[str, Any]:
    header = f"Actively exploited vulnerability patched in {release.title}"
    lines = [f"*{header}*", f"Released {release.release_date} - <{release.advisory_url}|advisory>"]
    for v in vulns:
        marker = "KEV" if v.kev else "vendor-confirmed"
        due = f" (KEV due {v.kev_due_date})" if v.kev_due_date else ""
        lines.append(f"- `{v.cve_id}` [{marker}]{due} - {v.impact[:160] or explain(v)}")
    if ticket_url:
        lines.append(f"Ticket: {ticket_url}")

    return {"text": header, "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}
    ]}


def _pagerduty_event(release: Release, vulns: list[Vuln], ticket_url: str | None) -> dict[str, Any]:
    cve_list = ", ".join(v.cve_id for v in vulns)
    return {
        "routing_key": PAGERDUTY_KEY,
        "event_action": "trigger",
        "dedup_key": f"patchwatch-{release.release_key}-exploited",
        "payload": {
            "summary": f"Exploited CVE patched in {release.title}: {cve_list}"[:1024],
            "severity": "critical",
            "source": "patchwatch",
            "component": release.platform,
            "custom_details": {
                "advisory": release.advisory_url,
                "release_date": release.release_date,
                "cves": [
                    {"id": v.cve_id, "kev": v.kev, "due": v.kev_due_date, "basis": explain(v)}
                    for v in vulns
                ],
                "ticket": ticket_url or "not yet filed",
            },
        },
        "links": [{"href": release.advisory_url, "text": "Vendor advisory"}],
    }


def notify(release: Release, vulns: list[Vuln], ticket_url: str | None = None) -> list[str]:
    """Returns the list of channels successfully notified."""
    if not vulns:
        return []

    sent: list[str] = []

    if SLACK_WEBHOOK:
        try:
            http.post_json(SLACK_WEBHOOK, _slack_blocks(release, vulns, ticket_url))
            sent.append("slack")
        except http.FetchError as exc:
            print(f"  slack notify failed: {exc}")

    if PAGERDUTY_KEY:
        try:
            http.post_json(PAGERDUTY_URL, _pagerduty_event(release, vulns, ticket_url))
            sent.append("pagerduty")
        except http.FetchError as exc:
            print(f"  pagerduty notify failed: {exc}")

    return sent
