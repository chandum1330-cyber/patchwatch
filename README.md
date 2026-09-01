# patchwatch

Daily monitoring of Android, iOS, macOS and Windows security patches, with CVE triage
at High severity or above, Intune configuration guidance, and Jira delivery.

Zero runtime dependencies. Python 3.11+ stdlib only — no `pip install` step, no
lockfile, no supply chain. For a tool that gates security alerting, that is a feature.

```bash
python -m patchwatch run --dry-run          # see what it would do
python -m patchwatch run                    # for real
python -m patchwatch dump-schema apple      # verify feed shapes on first setup
python -m patchwatch health                 # heartbeat freshness
python -m unittest discover -s tests        # 44 tests, all offline
```

---

## The design decision that matters most

**Do not gate on NVD severity.** On 2026-04-15 NIST abandoned the goal of enriching
every CVE, moving to risk-based triage. CVEs outside its criteria — KEV membership,
US federal government software, EO 14028 critical software — are labelled
`Not Scheduled` and will never receive an NVD CVSS score. NIST also stopped issuing
its own score when the assigning CNA already provided one, and now re-analyses a
modified CVE only when the change materially affects enrichment.

Apple compounds this: it is a CNA but publishes no CVSS at all. So for a typical
Apple CVE there is no vendor score *and* no NVD score. A pipeline whose filter is
"NVD says HIGH" drops most of what it exists to catch, and drops it silently.

`severity.py` replaces NVD-as-arbiter with an ordered ladder:

| # | Signal | Result | Timing |
|---|--------|--------|--------|
| 1 | CISA KEV membership | CRITICAL | same day |
| 2 | Vendor-asserted exploitation (Apple's wording, MSRC flag) | CRITICAL | same day |
| 3 | Vendor-native rating (Android column, MSRC CVSS) | as published | same day |
| 4 | CNA CVSS from cve.org | banded | hours–days |
| 5 | NVD CVSS, when one exists | banded | days–never |
| 6 | EPSS probability | heuristic floor | daily |
| 7 | Impact-prose heuristic | conservative floor, flagged inferred | same day |
| 8 | Nothing | UNKNOWN → triage, never dropped | — |

**Unscored is not low.** `Release.actionable()` includes UNKNOWN deliberately.
`test_unscored_stays_unknown_not_low` is the regression guard; if it ever fails, the
pipeline has quietly stopped working.

---

## Sources

| Platform | Source | Severity? | Cadence |
|---|---|---|---|
| iOS / macOS | [SOFA](https://sofa.macadmins.io) JSON feed, HTML fallback | No — Apple publishes none | Unpredictable |
| Android | `source.android.com/docs/security/bulletin/YYYY-MM-DD` | **Yes**, in the table | Monthly, ~first Monday |
| Windows | MSRC CVRF API | **Yes**, CVSS inline | Patch Tuesday + OOB |
| KEV | CISA JSON catalogue | Exploitation | Continuous |
| EPSS | FIRST daily CSV | Probability | Daily |
| CNA | cveawg.mitre.org | CVSS when the CNA scored it | Per-CVE |
| NVD | NVD API 2.0 | Sometimes, decreasingly | Per-CVE |

**Apple.** SOFA is a machine-readable feed maintained by the MacAdmins community and
refreshed via GitHub Actions; its v2 feeds carry CVE metadata, KEV status and severity
context. The maintainers ask integrators to set a User-Agent (done in `http.py`) and
recommend self-hosting a fork for production. **Do self-host** — set `SOFA_BASE` to
your fork's Pages URL and you remove a third-party availability dependency from your
alerting path. Note the feed moved to `sofafeed.macadmins.io`; the old
`sofa.macadmins.io` addresses are deprecated.

⚠️ **Verify the SOFA v2 field names before trusting this in production.** Run
`python -m patchwatch dump-schema apple`. The parser handles both v1 and v2 shapes and
raises loudly if it recognises neither, but the exact v2 key names in
`sources/apple.py` are the one part of this scaffold written without a live sample.

**Windows.** The MSRC CVRF API is public and unauthenticated — no key or token, just
`Accept: application/json`. It has no server-side time filter, so the full `/updates`
list is fetched and filtered client-side.

**Android.** The easy case. Google rates every CVE in the bulletin table itself, so
severity arrives same-day with no enrichment round-trip.

---

## Cadence: every 4 hours, not daily

Android is monthly, Microsoft is Patch Tuesday, but Apple ships rapid security
responses for actively-exploited bugs on no schedule at all. A 24-hour detection gap
on those is the scenario this exists to prevent. Runs are idempotent — nothing new
means a byte-identical state file and no commit.

Two GitHub scheduler caveats the workflow works around:

- `schedule` is best-effort; runs are delayed under load. The heartbeat check, not the
  cron, is the real detector.
- **Scheduled workflows are auto-disabled after 60 days of repository inactivity.**
  The state commit-back counts as activity and keeps the schedule alive. Don't remove it.

---

## Dedupe

Keyed on `(platform, release_key)`, never on CVE id. One CVE routinely spans iOS,
iPadOS and macOS in the same week; each is a separate patch action for a separate fleet.

The case people miss: **Apple retroactively edits published advisories** to add CVEs
weeks later, marked "Entry added". A pipeline that only asks "have I seen this release
key" never notices. `Release.content_hash()` covers the CVE set and each CVE's
severity, so an addition flips the release to `changed`, bumps the revision, clears
`delivered_at`, and updates the existing Jira ticket with a comment rather than opening
a duplicate. Cosmetic edits don't trigger it.

State lives in `state/state.json`, committed back to the repo. Sorted keys, atomic
writes. Every change to what the pipeline believes is a reviewable diff with an author
and a timestamp — an audit trail you'd otherwise have to build. Actions cache is
evictable and wrong for this.

---

## Where the model is, and isn't

`analyze.py` is the only file that calls a model. It does **not** extract CVE ids
(regex), determine severity (`severity.py`), decide what gets a ticket
(`pipeline.py`), or compute the Android patch level (deterministic — the bulletin date
*is* the Intune value).

It drafts the ticket summary, proposes Intune settings from a fixed allowlist, and
groups CVEs by attack surface.

Two independent guardrail layers:

1. **Constrained decoding.** Structured outputs compile the schema into a grammar, so
   `setting_key` is enum-constrained and off-allowlist keys can't be emitted. Set
   `PATCHWATCH_SCHEMA_COMPAT=1` if your endpoint predates `output_config.format`.
2. **`validate.py`**, which re-checks everything anyway:
   - every CVE id must exist in the input set (hallucination guard — a fabricated CVE
     in a security ticket is worse than no ticket)
   - every version string must appear verbatim in source
   - every setting key must be allowlisted, with type and pattern enforced
   - no deprecated Intune terminology
   - deadlines within the severity-banded policy window
   - any severity the model states must match what `severity.py` decided

**Fails closed on correctness, open on delivery.** A rejected analysis produces a
template-only ticket banner-flagged for manual review. A degraded ticket is still a
ticket someone sees; a dropped release is not.

### The Intune allowlist is load-bearing

Apple deprecated MDM-based software update workloads and Intune is ending support for
MDM-based Apple software update policies; the guidance is declarative device
management instead. There are no longer dedicated update policy blades for iOS/macOS —
everything moved to Settings Catalog profiles under DDM, requiring iOS/iPadOS 17.0+ or
macOS 14.0+. Two models are available: enforce-latest with a deferral period, and
targeted-version pinning.

A model working from older training data will confidently recommend
`Devices > Update policies for iOS`. `config/intune_allowlist.json` is the only thing
that catches that. **Review it whenever Intune ships release notes.**

---

## Delivery

One Jira ticket per release, not per CVE — an iOS point release can carry 40+ CVEs.
Deduped by label (`patchwatch-<release_key>`) via JQL before create, set at creation
so the lookup is always reliable. Belt-and-braces with the state file, because state
can be reverted and a run can die mid-flight.

KEV and actively-exploited CVEs also fire a separate urgent webhook (Slack or
PagerDuty) immediately, deduped on the CVE-level `alerted` flag so a cross-platform
KEV CVE pages once, not three times. Those must not queue behind a routine ticket.

---

## Setup

```bash
gh repo create patchwatch --private && git init && git add . && git commit -m "init"
python -m patchwatch dump-schema apple     # confirm the feed shape
python -m patchwatch run --dry-run --no-model
```

Secrets: `ANTHROPIC_API_KEY`, `NVD_API_KEY` (free, raises 5→50 req/30s),
`JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `SLACK_WEBHOOK_URL`,
`PAGERDUTY_ROUTING_KEY`.
Variables: `JIRA_PROJECT`, `JIRA_ISSUE_TYPE`, `SOFA_BASE`.

All optional. Missing Jira config skips ticketing; missing `ANTHROPIC_API_KEY` falls
back to template tickets. Nothing crashes, everything degrades visibly.

## Operational notes

- **A source that fails is not a source that found nothing.** Fetch errors are
  collected and the process exits non-zero. A green build with a broken Apple feed is
  the worst possible outcome, so it's made loud.
- **Monitor the heartbeat externally.** `python -m patchwatch health` exits 2 when the
  last successful run is stale. Wire it to whatever pages you — the failure mode where
  the pipeline stops running and nobody notices is more likely than a parsing bug.
- **Review `impact_heuristic` tickets.** They carry an inferred severity with no
  published score, marked as such in the ticket body.
