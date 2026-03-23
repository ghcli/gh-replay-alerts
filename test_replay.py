#!/usr/bin/env python3

"""Tests for replay_code_scanning_alert_status.py — CSV indexing, matching, and summary stats."""

import io
import unittest
from unittest.mock import patch, MagicMock
from defusedcsv import csv

from replay_code_scanning_alert_status import (
    index_csv,
    extract_alert_number,
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


class TestExtractAlertNumber(unittest.TestCase):
    """Tests for URL-based alert number extraction."""

    def test_standard_url(self):
        self.assertEqual(extract_alert_number("https://github.com/owner/repo/security/code-scanning/42"), "42")

    def test_single_digit(self):
        self.assertEqual(extract_alert_number("https://github.com/owner/repo/security/code-scanning/1"), "1")

    def test_large_number(self):
        self.assertEqual(extract_alert_number("https://github.com/owner/repo/security/code-scanning/99999"), "99999")

    def test_no_match(self):
        self.assertIsNone(extract_alert_number("https://github.com/owner/repo/issues/1"))

    def test_empty_string(self):
        self.assertIsNone(extract_alert_number(""))

    def test_ghes_url(self):
        self.assertEqual(extract_alert_number("https://ghes.example.com/owner/repo/security/code-scanning/5"), "5")


class TestIndexCsv(unittest.TestCase):
    """Tests for CSV dual-indexing (by number + by location)."""

    def test_empty_csv(self):
        by_number, by_location, count = index_csv(make_csv_reader([]))
        self.assertEqual(count, 0)
        self.assertEqual(by_number, {})
        self.assertEqual(by_location, {})

    def test_single_row_indexes_both(self):
        row = make_csv_row(url="https://github.com/owner/repo/security/code-scanning/7")
        by_number, by_location, count = index_csv(make_csv_reader([row]))

        self.assertEqual(count, 1)
        self.assertIn(("owner/repo", "7"), by_number)
        self.assertIn("owner/repo", by_location)
        self.assertIn("src/main.py", by_location["owner/repo"])

    def test_multiple_repos(self):
        rows = [
            make_csv_row(repo="org/repo-a", path="a.py", url="https://github.com/org/repo-a/security/code-scanning/1"),
            make_csv_row(repo="org/repo-b", path="b.py", url="https://github.com/org/repo-b/security/code-scanning/1"),
        ]
        by_number, by_location, count = index_csv(make_csv_reader(rows))

        self.assertEqual(len(by_location), 2)
        self.assertIn(("org/repo-a", "1"), by_number)
        self.assertIn(("org/repo-b", "1"), by_number)

    def test_url_without_alert_number_still_indexes_location(self):
        row = make_csv_row(url="https://github.com/owner/repo/issues/1")
        by_number, by_location, count = index_csv(make_csv_reader([row]))

        self.assertEqual(len(by_number), 0)
        self.assertIn("owner/repo", by_location)


class TestUpdateStates(unittest.TestCase):
    """Tests for cascading match: alert number → location fallback."""

    def _index(self, rows):
        return index_csv(make_csv_reader(rows))

    def test_no_api_alerts(self):
        by_number, by_location, _ = self._index([make_csv_row()])
        stats = update_states("github.com", iter([]), by_number, by_location)

        self.assertEqual(stats["api_alerts"], 0)
        self.assertEqual(stats["matched"], 0)

    def test_match_by_alert_number(self):
        """Same alert number, different line — should match by number."""
        csv_row = make_csv_row(
            start_line=10, state="dismissed",
            url="https://github.com/owner/repo/security/code-scanning/42",
        )
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(
            start_line=99,  # line changed!
            state="open",
            url="https://github.com/owner/repo/security/code-scanning/42",
        )

        with patch("replay_code_scanning_alert_status.change_state"):
            stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["matched_by_number"], 1)
        self.assertEqual(stats["matched_by_location"], 0)
        self.assertEqual(stats["state_changed"], 1)

    def test_fallback_to_location_when_no_number(self):
        """No alert number in URL — falls back to location match."""
        csv_row = make_csv_row(
            start_line=10, state="open",
            url="https://github.com/owner/repo/issues/1",  # not a code-scanning URL
        )
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(
            start_line=10, state="open",
            url="https://github.com/owner/repo/issues/1",
        )

        stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["matched_by_number"], 0)
        self.assertEqual(stats["matched_by_location"], 1)

    def test_fallback_to_location_when_number_doesnt_match(self):
        """Alert number in CSV doesn't match API — falls back to location."""
        csv_row = make_csv_row(
            start_line=10, state="dismissed",
            url="https://github.com/owner/repo/security/code-scanning/1",
        )
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(
            start_line=10, state="open",
            url="https://github.com/owner/repo/security/code-scanning/999",  # different number
        )

        with patch("replay_code_scanning_alert_status.change_state"):
            stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["matched_by_number"], 0)
        self.assertEqual(stats["matched_by_location"], 1)

    def test_exact_match_same_state(self):
        csv_row = make_csv_row(state="open")
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(state="open")

        stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["state_same"], 1)
        self.assertEqual(stats["state_changed"], 0)

    @patch("replay_code_scanning_alert_status.change_state")
    def test_state_mismatch_triggers_change(self, mock_change):
        csv_row = make_csv_row(state="dismissed")
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(state="open")

        stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(stats["state_changed"], 1)
        mock_change.assert_called_once()

    def test_repo_mismatch(self):
        csv_row = make_csv_row(repo="org/repo-a")
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(repo="org/repo-b", url="https://github.com/org/repo-b/security/code-scanning/99")

        stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_repo"], 1)

    def test_path_mismatch(self):
        csv_row = make_csv_row(path="old_file.py", url="https://github.com/owner/repo/security/code-scanning/1")
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(path="new_file.py", url="https://github.com/owner/repo/security/code-scanning/2")

        stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_path"], 1)

    def test_location_mismatch_no_number(self):
        csv_row = make_csv_row(start_line=10, url="https://github.com/owner/repo/issues/1")
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(start_line=15, url="https://github.com/owner/repo/issues/2")

        stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_location"], 1)

    def test_mixed_matches_and_misses(self):
        csv_rows = [
            make_csv_row(path="found.py", start_line=10, state="dismissed",
                         url="https://github.com/owner/repo/security/code-scanning/1"),
            make_csv_row(path="also_found.py", start_line=20, state="open",
                         url="https://github.com/owner/repo/security/code-scanning/2"),
        ]
        by_number, by_location, _ = self._index(csv_rows)

        api_alerts = [
            make_api_alert(path="found.py", start_line=10, state="open",
                           url="https://github.com/owner/repo/security/code-scanning/1"),
            make_api_alert(path="also_found.py", start_line=20, state="open",
                           url="https://github.com/owner/repo/security/code-scanning/2"),
            make_api_alert(path="missing.py", start_line=30, state="open",
                           url="https://github.com/owner/repo/security/code-scanning/99"),
        ]

        with patch("replay_code_scanning_alert_status.change_state"):
            stats = update_states("github.com", iter(api_alerts), by_number, by_location)

        self.assertEqual(stats["api_alerts"], 3)
        self.assertEqual(stats["matched"], 2)
        self.assertEqual(stats["matched_by_number"], 2)
        self.assertEqual(stats["state_changed"], 1)
        self.assertEqual(stats["state_same"], 1)
        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["miss_path"], 1)

    def test_empty_csv_all_unmatched(self):
        by_number, by_location, _ = self._index([])
        api_alerts = [make_api_alert(), make_api_alert(path="other.py")]

        stats = update_states("github.com", iter(api_alerts), by_number, by_location)

        self.assertEqual(stats["api_alerts"], 2)
        self.assertEqual(stats["matched"], 0)
        self.assertEqual(stats["unmatched"], 2)
        self.assertEqual(stats["miss_repo"], 2)

    def test_number_match_takes_priority_over_location(self):
        """When BOTH number and location could match, number wins."""
        csv_row = make_csv_row(
            start_line=10, state="dismissed",
            url="https://github.com/owner/repo/security/code-scanning/5",
        )
        by_number, by_location, _ = self._index([csv_row])
        api_alert = make_api_alert(
            start_line=10, state="open",  # location also matches
            url="https://github.com/owner/repo/security/code-scanning/5",
        )

        with patch("replay_code_scanning_alert_status.change_state"):
            stats = update_states("github.com", iter([api_alert]), by_number, by_location)

        self.assertEqual(stats["matched_by_number"], 1)
        self.assertEqual(stats["matched_by_location"], 0)


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
