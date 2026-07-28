# ai-defense-labs

## sysmon-parser

Extracts key fields from Sysmon Event ID 1 (Process Creation) XML and outputs JSON, JSON Lines, or CSV. Code lives in [`sysmon-parser/`](sysmon-parser/); see `sysmon-parser/CLAUDE.md` for architectural decisions and `sysmon-parser/HANDOFF.md` for session history and open items.

**Fields extracted:** `EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`

Accepts either a single `<Event>` document or a batched `<Events>` document containing multiple events.

### Requirements

Python 3. On this environment, the plain `python`/`python3` commands are Windows Store stub aliases that don't work — use `python3.14` instead.

### Usage

```
cd sysmon-parser
python3.14 parser.py <input.xml> [options]
```

**Basic parsing:**

```
python3.14 parser.py samples/event1.xml
python3.14 parser.py samples/multi_events.xml
```

**Write output to a file instead of stdout:**

```
python3.14 parser.py samples/multi_events.xml -o events.json
```

### Filtering

Results can be narrowed at parse time with the following flags. Multiple filters combine with **AND** logic.

| Flag | Match type | Notes |
|---|---|---|
| `--image` | substring, case-insensitive | matches against `Image` (process path) |
| `--user` | exact, case-insensitive | matches against `User` (`domain\user`) |
| `--command-line` | substring, case-insensitive | matches against `CommandLine` |
| `--integrity-level` | exact | one of `Low`, `Medium`, `High`, `System` (case-insensitive input) |

```
# Process path contains "powershell"
python3.14 parser.py samples/multi_events.xml --image powershell

# Exact user match
python3.14 parser.py samples/multi_events.xml --user "corp\jdoe"

# Flag encoded PowerShell invocations (note the = syntax, since -enc starts with a dash)
python3.14 parser.py samples/multi_events.xml --command-line=-enc

# Only High integrity events
python3.14 parser.py samples/multi_events.xml --integrity-level high

# Combine filters (AND)
python3.14 parser.py samples/multi_events.xml --image powershell --user "corp\jdoe"
```

### Output format

Controlled with `--format`:

| Format | Description |
|---|---|
| `json` (default) | A single JSON object for one matching event, or a JSON array for multiple |
| `jsonl` | One compact JSON object per line — good for streaming/piping to other tools |
| `csv` | CSV with a header row |

```
python3.14 parser.py samples/multi_events.xml --format json
python3.14 parser.py samples/multi_events.xml --format jsonl
python3.14 parser.py samples/multi_events.xml --format csv

# combine with filters and -o like any other run
python3.14 parser.py samples/multi_events.xml --format csv -o events.csv
```

### Stats mode

`--stats` outputs summary statistics instead of individual events — useful for quick triage of what's in a file before diving into deep analysis. Always JSON, regardless of `--format`. Respects filters (`--image`, `--user`, `--command-line`, `--integrity-level`), so you can scope the stats to a subset first.

```
python3.14 parser.py samples/multi_events.xml --stats
```

Outputs:
- `total_events` — count of matching events
- `unique_images` — count + sorted list of distinct `Image` values
- `unique_users` — count + sorted list of distinct `User` values
- `events_by_integrity_level` — event count per `IntegrityLevel`

### Sample data

`sysmon-parser/samples/` contains example Sysmon Event ID 1 XML for testing:
- `event1.xml` — `whoami.exe` execution
- `event2.xml` — `cmd.exe` spawning `powershell.exe`
- `event3.xml` — Office document spawning `powershell.exe` with an encoded (`-enc`) command
- `multi_events.xml` — 30 synthetic events across 14 distinct process images, 6 users, and mixed integrity levels (Low/Medium/High/System) — a larger batch for exercising `--stats` and other flags at scale
