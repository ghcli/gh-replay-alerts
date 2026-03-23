#!/usr/bin/env python3

"""Tests for replay_code_scanning_alert_status.py — CSV indexing, matching, and summary stats."""

import io
import unittest
from unittest.mock import patch, MagicMock
from defusedcsv import csv

from replay_code_scanning_alert_status import (
    existing_results_by_location,
    update_states,
)


def make_csv_reader(rows: list[dict]) -> csv.DictReader:
    """Create a csv.DictReader from a list of dicts."""
    if not rows:
        output = io.StringIO("")
        return csv.DictReader(output)
    fieldnames = list(rows[0].keys())
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)
    return csv.DictReader(output)


def make_csv_row(
    repo="owner/repo",
    path="src/main.py",
    start_line=10, start_column=5,
    end_line=10, end_column=20,
    state="dismissed",
    dismissed_reason="won't fix",
    dismissed_comment="test",
    url="https://github.com/owner/repo/security/code-scanning/1",
) -> dict:
    """Create a single CSV row dict."""
    return {
        "repo": repo,
        "path": path,
        "start_line": str(start_line),
        "start_column": str(start_column),
        "end_line": str(end_line),
        "end_column": str(end_column),
        "state": state,
        "dismissed_reason": dismissed_reason,
        "dismissed_comment": dismissed_comment,
        "url": url,
    }


def make_api_alert(
    repo="owner/repo",
    path="src/main.py",
    start_line=10, start_column=5,
    end_line=10, end_column=20,
    state="open",
    url="https://github.com/owner/repo/security/code-scanning/1",
) -> dict:
    """Create a simulated API alert result (as returned by list_code_scanning_alerts)."""
    return {
        "repo": repo,
        "path": path,
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
        "state": state,
        "url": url,
    }


class TestExistingResultsByLocation(unittest.TestCase):
    """Tests for CSV indexing."""

    def test_empty_csv(self):
        reader = make_csv_reader([])
        result = existing_results_by_location(reader)
        self.assertEqual(result, {})

    def test_single_row(self):
        row = make_csv_row()
        reader = make_csv_reader([row])
        result = existing_results_by_location(reader)

        self.assertIn("owner/repo", result)
        self.assertIn("src/main.py", result["owner/repo"])
        self.assertIn((10, 5), result["owner/repo"]["src/main.py"])
        self.assertIn((10, 20), result["owner/repo"]["src/main.py"][(10, 5)])

    def test_multiple_repos(self):
        rows = [
            make_csv_row(repo="org/repo-a", path="a.py"),
            make_csv_row(repo="org/repo-b", path="b.py"),
        ]
        reader = make_csv_reader(rows)
        result = existing_results_by_location(reader)

        self.assertEqual(len(result), 2)
        self.assertIn("org/repo-a", result)
        self.assertIn("org/repo-b", result)

    def test_multiple_files_same_repo(self):
        rows = [
            make_csv_row(path="file1.py"),
            make_csv_row(path="file2.py"),
        ]
        reader = make_csv_reader(rows)
        result = existing_results_by_location(reader)

        self.assertEqual(len(result["owner/repo"]), 2)

    def test_multiple_locations_same_file(self):
        rows = [
            make_csv_row(start_line=10, end_line=10),
            make_csv_row(start_line=20, end_line=20),
        ]
        reader = make_csv_reader(rows)
        result = existing_results_by_location(reader)

        file_results = result["owner/repo"]["src/main.py"]
        self.assertIn((10, 5), file_results)
        self.assertIn((20, 5), file_results)

    def test_duplicate_location_keeps_last(self):
        rows = [
            make_csv_row(state="open"),
            make_csv_row(state="dismissed"),
        ]
        reader = make_csv_reader(rows)
        result = existing_results_by_location(reader)

        stored = result["owner/repo"]["src/main.py"][(10, 5)][(10, 20)]
        self.assertEqual(stored["state"], "dismissed")


class TestUpdateStates(unittest.TestCase):
    """Tests for alert matching and state update logic."""

    def test_no_api_alerts(self):
        existing = existing_results_by_location(make_csv_reader([make_csv_row()]))
        stats = update_states("github.com", iter([]), existing)

        self.assertEqual(stats["api_alerts"], 0)
        self.assertEqual(stats["matched"], 0)
        self.assertEqual(stats["unmatched"], 0)

    def test_exact_match_same_state(self):
        csv_row = make_csv_row(state="open")
        existing = existing_results_by_location(make_csv_reader([csv_row]))
        api_alert = make_api_alert(state="open")

        stats = update_states("github.com", iter([api_alert]), existing)

        self.assertEqual(stats["api_alerts"], 1)
        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["state_same"], 1)
        self.assertEqual(stats["state_changed"], 0)

    @patch("replay_code_scanning_alert_status.change_state")
    def test_state_mismatch_triggers_change(self, mock_change):
        csv_row = make_csv_row(state="dismissed")
        existing = existing_results_by_location(make_csv_reader([csv_row]))
        api_alert = make_api_alert(state="open")

        stats = update_states("github.com", iter([api_alert]), existing)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["state_changed"], 1)
        mock_change.assert_called_once()

    def test_repo_mismatch(self):
        csv_row = make_csv_row(repo="org/repo-a")
        existing = existing_results_by_location(make_csv_reader([csv_row]))
        api_alert = make_api_alert(repo="org/repo-b")

        stats = update_states("github.com", iter([api_alert]), existing)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_repo"], 1)

    def test_path_mismatch(self):
        csv_row = make_csv_row(path="old_file.py")
        existing = existing_results_by_location(make_csv_reader([csv_row]))
        api_alert = make_api_alert(path="new_file.py")

        stats = update_states("github.com", iter([api_alert]), existing)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_path"], 1)

    def test_start_location_mismatch(self):
        csv_row = make_csv_row(start_line=10)
        existing = existing_results_by_location(make_csv_reader([csv_row]))
        api_alert = make_api_alert(start_line=15)

        stats = update_states("github.com", iter([api_alert]), existing)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_location"], 1)

    def test_end_location_mismatch(self):
        csv_row = make_csv_row(end_line=10, end_column=20)
        existing = existing_results_by_location(make_csv_reader([csv_row]))
        api_alert = make_api_alert(end_line=12, end_column=20)

        stats = update_states("github.com", iter([api_alert]), existing)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_location"], 1)

    def test_mixed_matches_and_misses(self):
        csv_rows = [
            make_csv_row(path="found.py", start_line=10, state="dismissed"),
            make_csv_row(path="also_found.py", start_line=20, state="open"),
        ]
        existing = existing_results_by_location(make_csv_reader(csv_rows))

        api_alerts = [
            make_api_alert(path="found.py", start_line=10, state="open"),
            make_api_alert(path="also_found.py", start_line=20, state="open"),
            make_api_alert(path="missing.py", start_line=30, state="open"),
        ]

        with patch("replay_code_scanning_alert_status.change_state"):
            stats = update_states("github.com", iter(api_alerts), existing)

        self.assertEqual(stats["api_alerts"], 3)
        self.assertEqual(stats["matched"], 2)
        self.assertEqual(stats["state_changed"], 1)  # found.py: dismissed != open
        self.assertEqual(stats["state_same"], 1)      # also_found.py: open == open
        self.assertEqual(stats["unmatched"], 1)        # missing.py
        self.assertEqual(stats["miss_path"], 1)

    def test_empty_csv_all_unmatched(self):
        existing = existing_results_by_location(make_csv_reader([]))
        api_alerts = [make_api_alert(), make_api_alert(path="other.py")]

        stats = update_states("github.com", iter(api_alerts), existing)

        self.assertEqual(stats["api_alerts"], 2)
        self.assertEqual(stats["matched"], 0)
        self.assertEqual(stats["unmatched"], 2)
        self.assertEqual(stats["miss_repo"], 2)


class TestGitHubAPIHelpers(unittest.TestCase):
    """Tests for githubapi.py helpers."""

    def test_check_name_valid_repo(self):
        from githubapi import GitHub
        self.assertTrue(GitHub.check_name("owner/repo", "repo"))

    def test_check_name_invalid_repo_no_slash(self):
        from githubapi import GitHub
        self.assertFalse(GitHub.check_name("justrepo", "repo"))

    def test_check_name_valid_org(self):
        from githubapi import GitHub
        self.assertTrue(GitHub.check_name("my-org", "org"))

    def test_check_hostname_valid(self):
        from githubapi import GitHub
        self.assertTrue(GitHub.check_hostname("github.com"))
        self.assertTrue(GitHub.check_hostname("ghes.example.com"))

    def test_check_hostname_invalid(self):
        from githubapi import GitHub
        self.assertFalse(GitHub.check_hostname(""))
        self.assertFalse(GitHub.check_hostname("-invalid.com"))

    def test_parse_date_days_ago(self):
        from githubapi import parse_date
        result = parse_date("7d")
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.tzinfo)

    def test_parse_date_iso(self):
        from githubapi import parse_date
        result = parse_date("2024-10-08")
        self.assertIsNotNone(result)

    def test_parse_date_none(self):
        from githubapi import parse_date
        self.assertIsNone(parse_date(None))

    def test_parse_link_header(self):
        from githubapi import GitHub
        header = '<https://api.github.com/repos?page=2>; rel="next", <https://api.github.com/repos?page=5>; rel="last"'
        links = GitHub.parse_link_header(header)
        self.assertEqual(links["next"], "https://api.github.com/repos?page=2")
        self.assertEqual(links["last"], "https://api.github.com/repos?page=5")


if __name__ == "__main__":
    unittest.main()
