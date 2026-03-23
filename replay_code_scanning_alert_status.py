#!/usr/bin/env python3

"""Replay code scanning alert status for a GitHub repository, organization or Enterprise, based on a provide file of previous statuses."""

import sys
import os
import argparse
import re
import logging
import datetime
import json
from typing import Generator, Iterable
from collections import defaultdict
from defusedcsv import csv  # type: ignore
from githubapi import GitHub, parse_date
from list_code_scanning_alerts import list_code_scanning_alerts


LOG = logging.getLogger(__name__)

ALERT_NUMBER_RE = re.compile(r"/code-scanning/(\d+)$")


def extract_alert_number(url: str) -> str | None:
    """Extract alert number from a code-scanning URL."""
    m = ALERT_NUMBER_RE.search(url)
    return m.group(1) if m else None


def index_csv(reader: csv.DictReader) -> tuple[dict, dict, int]:
    """Index CSV results by alert number (primary) and location (fallback).

    Returns (by_number, by_location, row_count).
    - by_number: {(repo, alert_number): row}
    - by_location: {repo: {path: {start_loc: {end_loc: row}}}}
    """
    by_number: dict[tuple[str, str], dict] = {}
    by_location: dict = {}
    row_count = 0

    for result in reader:
        row_count += 1
        repo = result["repo"]
        path = result["path"]
        url = result.get("url", "")

        # Primary index: alert number from URL
        alert_num = extract_alert_number(url)
        if alert_num:
            by_number[(repo, alert_num)] = result

        # Fallback index: location
        start_line = int(result["start_line"])
        start_column = int(result["start_column"])
        end_line = int(result["end_line"])
        end_column = int(result["end_column"])
        start_loc = (start_line, start_column)
        end_loc = (end_line, end_column)

        by_location.setdefault(repo, {}).setdefault(path, {}).setdefault(start_loc, {})[end_loc] = result

    total_files = sum(len(paths) for paths in by_location.values())
    LOG.info("CSV loaded: %d rows, %d repos, %d unique files, %d with alert numbers",
             row_count, len(by_location), total_files, len(by_number))
    for repo, paths in by_location.items():
        alert_count = sum(len(locs) for start_locs in paths.values() for locs in start_locs.values())
        LOG.info("  CSV repo: %s — %d files, %d alerts", repo, len(paths), alert_count)

    if row_count == 0:
        LOG.warning("CSV is empty — no existing results to match against. Check stdin/pipe.")

    return by_number, by_location, row_count


def change_state(hostname, result: dict, res: dict) -> None:
    """Change the state of the alert to match the existing result using the GitHub API to update the alert."""
    g = GitHub(hostname=hostname)

    repo_name = result["repo"]
    target_state = res["state"]

    state_update = {"state": target_state}

    # dismissed_reason and dismissed_comment are only valid when dismissing
    if target_state == "dismissed":
        if res.get("dismissed_reason"):
            state_update["dismissed_reason"] = res["dismissed_reason"]
        if res.get("dismissed_comment"):
            state_update["dismissed_comment"] = res["dismissed_comment"]

    alert_number = result["url"].split("/")[-1]

    LOG.debug(f"Changing state of alert {repo_name}/{alert_number} to {state_update}")

    g.query_once(
        "repo",
        repo_name,
        f"/code-scanning/alerts/{alert_number}",
        data=state_update,
        method="PATCH",
    )

    return


def update_states(hostname: str, results: Iterable[dict], by_number: dict, by_location: dict) -> dict:
    """Update alert states using cascading match: alert number first, location fallback.

    Returns a summary dict with counts for diagnosis.
    """
    stats = {
        "api_alerts": 0,
        "matched": 0,
        "matched_by_number": 0,
        "matched_by_location": 0,
        "state_same": 0,
        "state_changed": 0,
        "unmatched": 0,
        "miss_repo": 0,
        "miss_path": 0,
        "miss_location": 0,
    }

    for result in results:
        stats["api_alerts"] += 1
        repo = result["repo"]
        path = result["path"]
        url = result.get("url", "")
        start_loc = (result["start_line"], result["start_column"])
        end_loc = (result["end_line"], result["end_column"])

        LOG.debug(f"{repo}, {path}, {start_loc}, {end_loc}")

        res = None
        match_strategy = None

        # Strategy 1: Match by alert number (stable across code changes)
        alert_num = extract_alert_number(url)
        if alert_num and (repo, alert_num) in by_number:
            res = by_number[(repo, alert_num)]
            match_strategy = "number"

        # Strategy 2: Fall back to exact location match
        if res is None:
            if repo not in by_location:
                stats["unmatched"] += 1
                stats["miss_repo"] += 1
                LOG.debug(f"No CSV data for repo: {repo}")
                continue
            if path not in by_location[repo]:
                stats["unmatched"] += 1
                stats["miss_path"] += 1
                LOG.debug(f"No CSV data for path: {repo}/{path}")
                continue
            if start_loc not in by_location[repo][path]:
                stats["unmatched"] += 1
                stats["miss_location"] += 1
                LOG.debug(f"No CSV match at start {start_loc} in {repo}/{path}")
                continue
            if end_loc not in by_location[repo][path][start_loc]:
                stats["unmatched"] += 1
                stats["miss_location"] += 1
                LOG.debug(f"No CSV match at end {end_loc} (start {start_loc}) in {repo}/{path}")
                continue
            res = by_location[repo][path][start_loc][end_loc]
            match_strategy = "location"

        stats["matched"] += 1
        if match_strategy == "number":
            stats["matched_by_number"] += 1
            LOG.info(f"Matched by alert number #{alert_num}: {repo}/{path}")
        else:
            stats["matched_by_location"] += 1
            LOG.info(f"Matched by location: {repo}/{path} {start_loc}->{end_loc}")

        if res["state"] == result["state"]:
            stats["state_same"] += 1
            LOG.debug(f"State already matches: {result['state']}")
        else:
            stats["state_changed"] += 1
            LOG.warning(f"State mismatch: CSV={res['state']} API={result['state']} — updating")
            change_state(hostname, result, res)

    return stats


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command-line arguments to the parser."""
    parser.add_argument(
        "name", type=str, help="Name of the repo/org/Enterprise to query"
    )
    parser.add_argument(
        "--scope",
        type=str,
        default="org",
        choices=["ent", "org", "repo"],
        required=False,
        help="Scope of the query",
    )
    parser.add_argument(
        "--state",
        "-s",
        type=str,
        choices=["open", "resolved"],
        required=False,
        help="State of the alerts to query",
    )
    parser.add_argument(
        "--since",
        "-S",
        type=str,
        required=False,
        help="Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or 2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output in JSON format (otherwise CSV)"
    )
    parser.add_argument(
        "--quote-all", "-q", action="store_true", help="Quote all fields in CSV output"
    )
    parser.add_argument(
        "--hostname",
        type=str,
        default="github.com",
        required=False,
        help="GitHub Enterprise hostname (defaults to github.com)",
    )
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Enable debug logging"
    )


def main() -> None:
    """CLI entrypoint."""
    prog = os.environ.get("GH_PROG_NAME")
    parser = argparse.ArgumentParser(description=__doc__, prog=prog)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    since = parse_date(args.since)

    LOG.debug("Since: %s (%s) [%s]", since, args.since, type(since))

    scope = "repo" if "/" in args.name and args.scope != "repo" else args.scope
    name = args.name
    state = args.state
    hostname = args.hostname

    if not GitHub.check_name(args.name, scope):
        raise ValueError("Invalid name: %s for %s", args.name, scope)

    reader = csv.DictReader(sys.stdin)

    by_number, by_location, csv_row_count = index_csv(reader)

    results = list_code_scanning_alerts(name, scope, hostname, state=state, since=since)

    stats = update_states(hostname, results, by_number, by_location)

    # Summary — always printed so customer/support can diagnose immediately
    LOG.info("")
    LOG.info("=== Replay Summary ===")
    LOG.info("API alerts processed: %d", stats["api_alerts"])
    LOG.info("Matched to CSV:      %d", stats["matched"])
    LOG.info("  By alert number:   %d", stats["matched_by_number"])
    LOG.info("  By location:       %d", stats["matched_by_location"])
    LOG.info("  State already same: %d", stats["state_same"])
    LOG.info("  State changed:      %d", stats["state_changed"])
    LOG.info("Unmatched:            %d", stats["unmatched"])
    if stats["unmatched"] > 0:
        LOG.info("  Repo not in CSV:    %d", stats["miss_repo"])
        LOG.info("  Path not in CSV:    %d", stats["miss_path"])
        LOG.info("  Location mismatch:  %d", stats["miss_location"])
    LOG.info("======================")

    if stats["api_alerts"] > 0 and stats["matched"] == 0:
        LOG.warning("")
        LOG.warning("Zero matches found. Common causes:")
        LOG.warning("  1. Alerts were re-generated by a new scan (different alert numbers)")
        LOG.warning("  2. CSV repo name doesn't match API repo name")
        LOG.warning("  3. CSV was generated from a different branch or scan")
        if stats["miss_location"] > 0:
            LOG.warning("  → %d alerts matched repo+path but NOT line/column — code edits shifted locations", stats["miss_location"])

    # Exit non-zero if CSV had data but nothing matched
    if csv_row_count > 0 and stats["api_alerts"] > 0 and stats["matched"] == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
