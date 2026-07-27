# Handoff: sysmon-parser

## What we built

A Python CLI tool (`module2/sysmon-parser/parser.py`) that parses Sysmon Event ID 1 (Process Creation) XML and extracts key fields to JSON:

`EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`

It accepts either a single `<Event>` document or a batched `<Events>` document containing multiple events, and outputs a single JSON object (one event) or a JSON array (multiple events).

It also supports filtering results at parse time:
- `--image` — substring match on `Image`, case-insensitive
- `--user` — exact match on `User`, case-insensitive
- `--command-line` — substring match on `CommandLine`, case-insensitive
- `--integrity-level` — exact match, restricted to `Low`/`Medium`/`High`/`System`

Multiple filters combine with AND logic.

Sample data lives in `module2/sysmon-parser/samples/`:
- `event1.xml` — `whoami.exe` execution (benign)
- `event2.xml` — `cmd.exe` spawning `powershell.exe`
- `event3.xml` — Office doc (`WINWORD.EXE`) spawning `powershell.exe` with a base64-encoded (`-enc`) command — simulates a phishing/macro execution chain
- `multi_events.xml` — all three combined under an `<Events>` root

Full usage examples are in `module2/sysmon-parser/README.md`.

## How to use it

```
cd module2/sysmon-parser
python3.14 parser.py samples/multi_events.xml
python3.14 parser.py samples/multi_events.xml --image powershell --user "corp\jdoe"
python3.14 parser.py samples/multi_events.xml --command-line=-enc
python3.14 parser.py samples/multi_events.xml -o events.json
```

Note: on this machine, plain `python`/`python3` are Windows Store stub aliases that fail — use `python3.14`.

## Decisions made, and why

- **Filter matching is case-insensitive for `--image`, `--user`, `--command-line`.** Windows paths and `domain\user` values are case-insensitive by convention, so exact-case matching would be surprising and error-prone for analysts.
- **`--integrity-level` is validated via argparse `choices`** against the four real Sysmon integrity levels rather than accepting any string. A typo (e.g. `Hihg`) fails fast with a CLI error instead of silently returning zero results.
- **Filters combine with AND logic**, applied after extraction on the normalized record dicts (not baked into the XML parsing). This keeps `parse_file`/`parse_event` unchanged and works uniformly for single-event and batched files.
- **Only Event ID 1 records are extracted**, even from a batched file that could in principle contain other event IDs — the tool is scoped specifically to Process Creation events per the original goal.
- **JSON output shape depends on match count**: a single object for one match, an array for multiple. This mirrors the "one object per event, or array for multiple" requirement from the original spec.

## What's left to do

- `README.md` and this `HANDOFF.md` are written but **not yet committed/pushed** — only the parser filtering feature and `.gitignore` are on `origin/main` (commit `0fe5879`).
- `CLAUDE.md` is stale — it still describes the project as "planned"/not yet built. Should be updated to reflect the actual architecture and add real build/lint/test commands.
- No automated tests exist (no pytest suite) — verification so far has been manual CLI runs against the sample files.
- No handling for malformed/truncated XML input (e.g. `ET.parse` will raise an uncaught `ParseError`); error messaging for bad input hasn't been designed.
- There's a stray nested duplicate clone at `ai-defense-labs/ai-defense-labs/` in the working tree (untracked, same repo/commits) — likely leftover from an accidental clone-inside-the-repo. Not touched; worth cleaning up or confirming it's not needed.
- No support yet for other Sysmon event types (e.g. Event ID 3 network connections, Event ID 11 file creation) — scope has been Event ID 1 only, per the original ask.
