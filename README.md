# gh-replay-alerts

A [GitHub CLI](https://cli.github.com/) extension that replays code scanning alert statuses from a CSV export onto current alerts.

## Use Case

When migrating repositories, changing code scanning tools, or restoring alert states after re-scanning, you may need to restore previously dismissed/resolved alert statuses. This extension:

1. Reads a CSV of previous alert statuses (from `gh-list-alerts` or the code scanning API)
2. Fetches current alerts from the GitHub API
3. Matches alerts by file location (repo, path, line, column)
4. Updates mismatched states via the API

## Installation

```bash
gh extension install ghcli/gh-replay-alerts
```

### Prerequisites

- [GitHub CLI](https://cli.github.com/) (`gh`) — authenticated via `gh auth login`
- Python 3.10+
- Python dependencies:

```bash
pip install -r "$(gh extension list | grep replay-alerts | awk '{print $3}')/requirements.txt"
```

## Usage

```bash
# Replay alert states for a specific repo
cat alerts.csv | gh replay-alerts owner/repo --scope repo

# Replay for an entire org
cat alerts.csv | gh replay-alerts my-org --scope org

# With debug output for diagnosis
cat alerts.csv | gh replay-alerts owner/repo --scope repo --debug

# Filter by state
cat alerts.csv | gh replay-alerts owner/repo --scope repo --state open

# GitHub Enterprise Server
cat alerts.csv | gh replay-alerts owner/repo --scope repo --hostname ghes.example.com
```

## Generating the CSV Input

Use the companion `list_code_scanning_alerts.py` script (included) to export current alert states:

```bash
export GITHUB_TOKEN=$(gh auth token)
python3 list_code_scanning_alerts.py owner/repo --scope repo > alerts.csv
```

## Output

The extension always prints a diagnostic summary:

```
INFO:  CSV loaded: 2650 rows, 1 repos, 2650 unique files
INFO:  === Replay Summary ===
INFO:  API alerts processed: 12
INFO:  Matched to CSV:      8
INFO:    State already same: 6
INFO:    State changed:      2
INFO:  Unmatched:            4
INFO:    Repo not in CSV:    0
INFO:    Path not in CSV:    1
INFO:    Location mismatch:  3
INFO:  ======================
```

If zero matches are found, it auto-diagnoses the likely cause:

```
WARNING: Zero matches found. Common causes:
WARNING:   1. Code changed between CSV export and now (line numbers shifted)
WARNING:   2. CSV repo name doesn't match API repo name
WARNING:   3. CSV was generated from a different branch or scan
WARNING:   → 12 alerts matched repo+path but NOT line/column — likely cause: code edits shifted locations
```

## Options

| Flag | Description |
|------|-------------|
| `name` | Repository (`owner/repo`), org, or Enterprise name |
| `--scope` | `repo`, `org`, or `ent` (default: `org`) |
| `--state` | Filter: `open` or `resolved` |
| `--since` | Only alerts after date (`2024-10-08`, `7d`) |
| `--hostname` | GHES hostname (default: `github.com`) |
| `--debug` | Enable debug logging |

## How Matching Works

Alerts are matched by **exact location**:

```
(repo, path, start_line, start_column) → (end_line, end_column)
```

If code has changed between the CSV export and replay (lines added/removed), locations shift and matches fail. The summary output diagnoses this automatically.

## License

MIT
