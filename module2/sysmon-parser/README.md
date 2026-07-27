# sysmon-parser

Extracts key fields from Sysmon Event ID 1 (Process Creation) XML and outputs JSON.

**Fields extracted:** `EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`

Accepts either a single `<Event>` document or a batched `<Events>` document containing multiple events. Output is a single JSON object for one matching event, or a JSON array for multiple.

## Requirements

Python 3. On this environment, the plain `python`/`python3` commands are Windows Store stub aliases that don't work — use `python3.14` instead.

## Usage

```
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

## Sample data

`samples/` contains example Sysmon Event ID 1 XML for testing:
- `event1.xml` — `whoami.exe` execution
- `event2.xml` — `cmd.exe` spawning `powershell.exe`
- `event3.xml` — Office document spawning `powershell.exe` with an encoded (`-enc`) command
- `multi_events.xml` — all three events combined under an `<Events>` root
