# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

- `module-01-claude-ecosystem/hello.txt` — a placeholder file
- `module-02-security-tool/sysmon-parser/` — a Python CLI tool for parsing Sysmon Event ID 1 (Process Creation) XML, described below

There are no lint or test commands defined yet.

## Sysmon XML parser (`module-02-security-tool/sysmon-parser/parser.py`)

Parses Sysmon Event ID 1 (Process Creation) events from XML and extracts key fields to JSON.

**Run it:**
```
cd module-02-security-tool/sysmon-parser
python3.14 parser.py samples/multi_events.xml
```
Note: plain `python`/`python3` are Windows Store stub aliases on this machine and fail — use `python3.14`.

**Fields extracted:** EventID, UtcTime, Image, CommandLine, User, IntegrityLevel, ParentImage, ParentCommandLine, Computer, Hashes.

Sample data for manual testing lives in `module-02-security-tool/sysmon-parser/samples/` (`event1.xml`–`event3.xml`, plus `multi_events.xml` — 30 synthetic events across 14 images, 6 users, and mixed integrity levels — for exercising flags at a larger scale).

### Architectural decisions

- **XML parsing uses the standard library's `xml.etree.ElementTree`** — no third-party dependency needed for straightforward namespaced XML extraction. The Sysmon XML namespace (`http://schemas.microsoft.com/win/2004/08/events/event`) is handled via a single `NS` dict passed to all `find`/`findall` calls.
- **Input can be a single `<Event>` or a batched `<Events>` root** containing multiple `<Event>` children; `parse_file` detects which by checking the root tag, so downstream code doesn't need to care which shape it got.
- **Only `EventID == 1` records are extracted**, even from a batched file that could contain other event types — the tool is scoped specifically to Process Creation events.
- **Output is JSON, shaped by match count**: a single JSON object when exactly one event matches, a JSON array when multiple do. This avoids always wrapping a lone result in a single-element array.
- **Filtering happens after extraction**, not during XML traversal — `matches_filters()` is a pure function operating on the already-normalized record dicts (not on `argparse.Namespace` or raw XML), keeping `parse_file`/`parse_event` filter-agnostic and easy to reuse.
- **Filter flags:** `--image` (substring), `--user` (exact), `--command-line` (substring) — all case-insensitive, since Windows paths and `domain\user` values are case-insensitive by convention. `--integrity-level` is exact-match and validated via argparse `choices` against `Low`/`Medium`/`High`/`System`, so a typo fails fast with a CLI error instead of silently returning zero results.
- **Multiple filters combine with AND logic** — a record must satisfy every supplied filter to be included.
- **`--format` controls output shape**: `json` (default, single object or array depending on match count), `jsonl` (one compact JSON object per line, always — for streaming/piping), or `csv` (header row + one row per record). The CSV writer uses `lineterminator="\n"` and file writes use `open(..., newline="")` to avoid double-translated `\r\r\n` line endings on Windows.
- **`--stats` outputs summary statistics instead of events** (total events, unique images/users with counts, events by IntegrityLevel), for quick triage before deep analysis. Always JSON regardless of `--format`; still respects the filter flags; and skips the "no matching records" exit so a zero-match filter combo still returns valid zeroed stats.

See the module README (`../README.md`) for full usage examples and `HANDOFF.md` in this directory for outstanding work.
