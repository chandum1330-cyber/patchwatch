"""CLI entry point: python -m patchwatch [command] [options]"""

from __future__ import annotations

import argparse
import json
import sys

from . import pipeline
from .models import SEVERITY_ORDER


def cmd_run(args: argparse.Namespace) -> int:
    _, exit_code = pipeline.run(
        platforms=args.platforms.split(",") if args.platforms else None,
        threshold=args.threshold,
        since_days=args.since_days,
        state_path=args.state,
        allowlist_path=args.allowlist,
        dry_run=args.dry_run,
        use_nvd=not args.no_nvd,
        use_model=not args.no_model,
    )
    return exit_code


def cmd_dump_schema(args: argparse.Namespace) -> int:
    """Print the raw shape of a source feed. Run this on first setup to verify the
    field names in sources/*.py against live data before trusting the parser."""
    from . import http
    from .sources import apple

    if args.source == "apple":
        for name, path in apple.FEEDS.items():
            data = http.get_json(f"{apple.SOFA_BASE}{path}")
            print(f"=== {name} : {apple.SOFA_BASE}{path} ===")
            print("top-level keys:", list(data.keys()))
            versions = data.get("OSVersions", [])
            if versions:
                print("OSVersions[0] keys:", list(versions[0].keys()))
                rels = versions[0].get("SecurityReleases", [])
                if rels:
                    print("SecurityReleases[0]:")
                    print(json.dumps(rels[0], indent=2)[:2500])
    elif args.source == "msrc":
        from .sources import microsoft

        releases = microsoft.list_releases()
        print(f"{len(releases)} releases; most recent 5:")
        for rel in releases[:5]:
            print(f"  {rel.get('ID')}  {rel.get('CurrentReleaseDate')}")
    elif args.source == "android":
        from .sources import android as android_mod

        print("Probing Android bulletin URLs:\n")
        for url, outcome in android_mod.probe(lookback_months=3):
            print(f"  {outcome}\n    {url}")
    elif args.source == "kev":
        from .sources import enrich

        kev = enrich.fetch_kev()
        print(f"{len(kev)} KEV entries")
        first = next(iter(kev.values()))
        print(json.dumps(first, indent=2))
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Check heartbeat freshness. Wire this to external monitoring."""
    from datetime import datetime, timedelta, timezone

    from .state import State

    state = State(args.state)
    last = state.meta.get("last_successful_run")
    if not last:
        print("UNHEALTHY: no successful run recorded")
        return 2

    age = datetime.now(timezone.utc) - datetime.fromisoformat(last)
    print(f"last successful run: {last} ({age.total_seconds() / 3600:.1f}h ago)")
    print(f"tracked releases: {len(state.releases)}")
    print(f"tracked CVEs: {len(state.cves)}")

    if age > timedelta(hours=args.max_age_hours):
        print(f"UNHEALTHY: heartbeat older than {args.max_age_hours}h")
        return 2
    print("healthy")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchwatch", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="fetch, triage and deliver")
    p_run.add_argument("--platforms", default="ios,macos,android,windows")
    p_run.add_argument("--threshold", default="HIGH", choices=SEVERITY_ORDER)
    p_run.add_argument("--since-days", type=int, default=30,
                       help="ignore releases older than this (default 30)")
    p_run.add_argument("--state", default="state/state.json")
    p_run.add_argument("--allowlist", default="config/intune_allowlist.json")
    p_run.add_argument("--dry-run", action="store_true", help="no tickets, no state write")
    p_run.add_argument("--no-nvd", action="store_true", help="skip the NVD pass")
    p_run.add_argument("--no-model", action="store_true", help="template-only tickets")
    p_run.set_defaults(func=cmd_run)

    p_dump = sub.add_parser("dump-schema", help="inspect a live source feed")
    p_dump.add_argument("source", choices=["apple", "msrc", "android", "kev"])
    p_dump.set_defaults(func=cmd_dump_schema)

    p_health = sub.add_parser("health", help="check heartbeat freshness")
    p_health.add_argument("--state", default="state/state.json")
    p_health.add_argument("--max-age-hours", type=int, default=8)
    p_health.set_defaults(func=cmd_health)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
