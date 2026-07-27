# Handoff: sysmon-parser

## What we built

A Python CLI tool (`module-02-security-tool/sysmon-parser/parser.py`) that parses Sysmon Event ID 1 (Process Creation) XML and extracts key fields to JSON:

`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`

It accepts either a single `<Event>` document or a batched `<Events>` document containing multiple events.

It also supports filtering results at parse time:
- `--image` — substring match on `Image`, case-insensitive
- `--user` — exact match on `User`, case-insensitive
- `--command-line` — substring match on `CommandLine`, case-insensitive
- `--integrity-level` — exact match, restricted to `Low`/`Medium`/`High`/`System`

Multiple filters combine with AND logic.

And a choice of output format via `--format`:
- `json` (default) — a single JSON object for one matching event, a JSON array for multiple
- `jsonl` — one compact JSON object per line, always, regardless of match count (streaming/piping)
- `csv` — CSV with a header row

Plus a `--stats` mode that outputs summary statistics instead of events (total events, unique images/users with counts, events by IntegrityLevel) — always JSON, and still respects the filter flags.

Sample data lives in `module-02-security-tool/sysmon-parser/samples/`:
- `event1.xml` — `whoami.exe` execution (benign)
- `event2.xml` — `cmd.exe` spawning `powershell.exe`
- `event3.xml` — Office doc (`WINWORD.EXE`) spawning `powershell.exe` with a base64-encoded (`-enc`) command — simulates a phishing/macro execution chain
- `multi_events.xml` — all three combined under an `<Events>` root

Full usage examples are in `README.md` in this directory.

## How to use it

```
cd module-02-security-tool/sysmon-parser
python3.14 parser.py samples/multi_events.xml
python3.14 parser.py samples/multi_events.xml --image powershell --user "corp\jdoe"
python3.14 parser.py samples/multi_events.xml --command-line=-enc
python3.14 parser.py samples/multi_events.xml -o events.json
python3.14 parser.py samples/multi_events.xml --format jsonl
python3.14 parser.py samples/multi_events.xml --format csv -o events.csv
```

Note: on this machine, plain `python`/`python3` are Windows Store stub aliases that fail — use `python3.14`.

## Decisions made, and why

- **Filter matching is case-insensitive for `--image`, `--user`, `--command-line`.** Windows paths and `domain\user` values are case-insensitive by convention, so exact-case matching would be surprising and error-prone for analysts.
- **`--integrity-level` is validated via argparse `choices`** against the four real Sysmon integrity levels rather than accepting any string. A typo (e.g. `Hihg`) fails fast with a CLI error instead of silently returning zero results.
- **Filters combine with AND logic**, applied after extraction on the normalized record dicts (not baked into the XML parsing). This keeps `parse_file`/`parse_event` unchanged and works uniformly for single-event and batched files.
- **Only Event ID 1 records are extracted**, even from a batched file that could in principle contain other event IDs — the tool is scoped specifically to Process Creation events per the original goal.
- **JSON output shape depends on match count**: a single object for one match, an array for multiple. This mirrors the "one object per event, or array for multiple" requirement from the original spec. `jsonl` and `csv` don't get this treatment — they're inherently per-record streaming formats, so they always emit one line/row per record regardless of count.
- **CSV writer uses `lineterminator="\n"`**, and all `-o` file writes use `open(..., newline="")`. Without this, Python's csv module emits `\r\n` row terminators, and a text-mode file write on Windows would then re-translate the `\n` half of that into `\r\n` again, producing broken `\r\r\n` line endings.
- **`--stats` runs after filtering but skips the "no matching records" exit**, so a filter combo that matches nothing still returns valid (zeroed) stats rather than erroring — useful during triage to confirm "yes, this filter really matches zero events" rather than getting an unhelpful CLI error.

## What's left to do

- No automated tests exist (no pytest suite) — verification so far has been manual CLI runs against the sample files.
- No support yet for other Sysmon event types (e.g. Event ID 3 network connections, Event ID 11 file creation) — scope has been Event ID 1 only, per the original ask.

## Repo layout note

The repo root is `ai-defense-labs/`, organized by module:
- `module-01-claude-ecosystem/hello.txt` — placeholder
- `module-02-security-tool/sysmon-parser/` — this tool
- `module-03-mcp/` through `module-12-cross-siem-investigation/` — placeholder folders (`.gitkeep`) for upcoming modules
- `notes/`, `project/` — placeholder folders (`.gitkeep`) for course notes and the capstone project
