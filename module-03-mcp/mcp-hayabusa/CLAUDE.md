# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (the Rust-based Windows event log / EVTX analysis and threat-hunting tool) and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) (a second, independent Rust-based EVTX hunting tool) for EVTX analysis.

**Goals:**
- Expose a `scan_evtx` tool that runs the Hayabusa CLI against EVTX files
- Return results as structured JSON
- Support filtering by severity level, and by rule keyword (`rule_filter`)
- Support a condensed vs. full output shape (`output_format`) and capping result count (`max_results`)
- Expose a `get_hayabusa_rules` tool to browse/search the bundled detection rules before scanning
- Expose a `scan_chainsaw` tool that runs Chainsaw's native EVTX rules, for cross-checking Hayabusa's results with a second detection engine
- Handle errors gracefully

**Stack:**
- Python, using the `mcp` library (`mcp.server.fastmcp.FastMCP`)
- Hayabusa CLI — not vendored; either present on PATH, or downloaded locally via `download_hayabusa.py`
- Chainsaw CLI — not vendored; either present on PATH, or downloaded locally via `download_chainsaw.py`

## Setup

```
python3.14 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt         # Linux/Mac

python3.14 download_hayabusa.py   # only needed if hayabusa isn't already on PATH
python3.14 download_chainsaw.py   # only needed if chainsaw isn't already on PATH
```

Note: on this machine, plain `python`/`python3` are Windows Store stub aliases that fail — use `python3.14`. The system Python is `uv`-managed and externally-managed (PEP 668), so dependencies must go in a venv rather than a global `pip install`.

**Run the server:** `python3.14 server.py` (or `.venv/Scripts/python.exe server.py` if deps are only in the venv).

## Architecture

- **`server.py`** — the MCP server. `FastMCP("hayabusa")` exposes three tools: `scan_evtx(evtx_path, min_severity=None, rule_filter=None, output_format="summary", max_results=None)`, `get_hayabusa_rules(keyword=None)`, and `scan_chainsaw(evtx_path, rule_type=None)`.
- **`resolve_hayabusa_binary()`** checks `PATH` first (`shutil.which("hayabusa")`), then falls back to `./hayabusa/hayabusa*` (the location `download_hayabusa.py` extracts to). The downloaded binary is versioned (e.g. `hayabusa-3.10.0-win-x64.exe`), not literally named `hayabusa`, hence the glob rather than an exact-name check.
- **`scan_evtx` shells out to `hayabusa json-timeline`**, writing JSONL to a temp file (`-o <path> -L`) rather than reading stdout directly, then parses that file line-by-line into a list of dicts. `-w` (no-wizard) is required — without it, Hayabusa's interactive rule-selection prompt would hang the subprocess. `-d` vs `-f` is chosen based on whether `evtx_path` is a directory.
- **Severity filtering** uses Hayabusa's own `-m/--min-level` flag (values: `informational`, `low`, `medium`, `high`, `critical`) rather than filtering results after the fact, so Hayabusa only loads/runs the relevant detection rules.
- **`rule_filter` restricts which rules Hayabusa loads**, not just which results come back. Hayabusa's CLI has no free-text "match rule title" flag (checked `json-timeline --help` on v3.10.0 — only `--include-tag`/`--include-category`/etc.), so the wrapper resolves matching rule files itself via `_load_rule_index()`/`_rule_matches_keyword()`, copies just those files (mirroring their subfolder structure, to avoid filename collisions — several rule filenames repeat across `rules/sigma/builtin/` and `rules/sigma/sysmon/`) into a temp dir, and passes `-r <temp dir> -c <RULES_DIR>/config` so Hayabusa only loads that subset. Verified experimentally: pointing `-r` at a one-rule temp dir cut the UACME sample's detections from 8 to 5 (only the "Proc Access" rule's hits). An empty match set short-circuits with a `{"success": False, ...}` error instead of invoking Hayabusa with zero rules.
- **`get_hayabusa_rules`** lists/searches the same rule index used by `rule_filter`, without running a scan. Matching is against rule title, tags, rule ID, and file path — deliberately *not* full-text body search, since a naive `grep -r mimikatz` over rule YAML also matches unrelated rules that merely mention "mimikatz" in prose fields like `falsepositives`. Results are capped at `RULE_INDEX_DISPLAY_LIMIT` (200) with a `truncated` flag, since the bundled ruleset has ~5000 rule files and returning all of them unfiltered would be a large response.
- **Rule metadata parsing (`_parse_rule_metadata`) is regex-based, not a full YAML parse** — deliberately, to avoid adding PyYAML as a dependency (see `requirements.txt`'s existing stdlib-only stance) for what's only ever a handful of top-level scalar/list fields (`title`, `id`, `level`, `status`, `tags`). Reads every rule file under `RULES_DIR` (excluding `rules/config/`, which holds non-rule YAML like data-mapping config, and `.git/`) and caches the parsed list in a module-level global (`_rule_index_cache`) for the life of the process — parsing all ~5000 files is I/O-bound and takes ~5s (benchmarked directly; re-parsing on every call would make every `rule_filter`/`get_hayabusa_rules` call pay that cost).
- **`RULES_DIR` (`./hayabusa/rules`) is only known for the locally-downloaded binary.** If Hayabusa was resolved from `PATH` instead, `RULES_DIR` won't exist, and both `rule_filter` and `get_hayabusa_rules` return a clear `{"success": False, ...}` error rather than guessing another location.
- **`output_format`**: `"summary"` (default) strips each event down to `SUMMARY_FIELDS` (`Timestamp`, `RuleTitle`, `Level`, `Computer`, `Channel`, `EventID`, `RecordID`, `RuleID`), dropping the bulky `Details`/`ExtraFieldInfo` blocks. `"full"` returns Hayabusa's complete per-event dict, matching the tool's original (pre-this-change) behavior.
- **`max_results`** truncates the returned `events` list but not the reported `event_count` (the true total) — the response also carries `returned_count` and a `truncated` bool so a caller can tell results were capped.
- **Error handling returns a structured `{"success": False, "error": ...}` dict instead of raising** for every known failure mode: binary not found, input path missing, invalid severity, invalid `output_format`, non-positive `max_results`, no rules matching `rule_filter`, missing `RULES_DIR`, subprocess timeout/OSError, non-zero exit code, missing output file, and JSON parse errors. Note that Hayabusa itself is lenient — it can exit 0 and still fail to produce meaningful results for e.g. a non-EVTX input file, logging the real error to its own `./logs/errorlog-*.log` instead of stderr. The wrapper doesn't currently inspect that log; a scan of unparseable input surfaces as `event_count: 0` rather than an explicit error.
- **`download_hayabusa.py`** queries the GitHub releases API for the latest Hayabusa release, matches the asset for the current OS/architecture (excluding the `-live-response` variant via an exact `-<suffix>.zip` suffix match, not a substring match), downloads and extracts it to `./hayabusa/`, and chmods any `hayabusa*` file executable (relevant on Linux/Mac; extracted `.exe` on Windows doesn't need it).
- **`resolve_chainsaw_binary()`** mirrors `resolve_hayabusa_binary()`: checks `PATH` (`shutil.which("chainsaw")`), then falls back to `./chainsaw/chainsaw*`.
- **`scan_chainsaw` shells out to `chainsaw hunt`**, writing JSON (not JSONL — Chainsaw's `hunt` only supports `--json`/`--jsonl` as whole-array vs. line-delimited, and the whole-array form is what gets parsed with a single `json.load()`) to a temp file via `-o`. `--no-banner` is a top-level flag and must precede the `hunt` subcommand (verified against `chainsaw hunt --help` on v2.16.2 — passing it after `hunt` errors as an unexpected argument). Unlike Hayabusa, Chainsaw takes the EVTX path as a plain positional (`hunt <RULES> <PATH>...`) with no separate file-vs-directory flag.
- **`scan_chainsaw` only uses Chainsaw's own native `rules/evtx/` ruleset**, not Chainsaw's Sigma-rule mode (`-s/--sigma` + `-m/--mapping`). The native rules are ~600KB, organized into category subfolders (`credential_access`, `lateral_movement`, `persistence`, `login_attacks`, etc.) that map directly onto the `rule_type` parameter — pass one to restrict `CHAINSAW_RULES_DIR` to that subfolder, matching the same "point `-r`/first-positional at a subset dir" trick `scan_evtx`'s `rule_filter` uses. `rule_type` validation checks the subfolder exists on disk at call time (not a hardcoded list) so it stays correct if the ruleset changes; an invalid value's error message lists the real available categories. Sigma-mode was tried and rejected: hunting the full ~3000-rule vendored Sigma corpus against the UACME sample took ~32s (benchmarked directly) vs. <1s for the native ruleset, and would have meant vendoring a second full Sigma corpus alongside Hayabusa's.
- **`download_chainsaw.py`** downloads two things separately: the platform binary zip/tarball from the latest GitHub release (flattening its single-level wrapper directory on extract), and — from a separate source-tarball download — just the `rules/evtx/` subtree, extracted to `./chainsaw/rules/`. It deliberately does *not* use the `chainsaw_all_platforms+rules.zip` release asset, which bundles every platform's binary plus the entire vendored Sigma corpus (~90MB extracted) that `scan_chainsaw` doesn't use and that would duplicate `download_hayabusa.py`'s own Sigma-derived ruleset.
- **`hayabusa/`, `chainsaw/`** (downloaded binaries + bundled detection rules) and `.venv/` are gitignored — none of it is project source.

## MCP registration

Registered in two places, for two different purposes:

- **`.claude/settings.json`** contains an `mcpServers.hayabusa` entry with `command: "python"`, `args: ["server.py"]` — per this module's assignment spec ("MCP servers are configured in .claude/settings.json ... started with 'python server.py' from this directory"). Also sets `enableAllProjectMcpServers: true` so servers are auto-approved without a trust prompt.
- **`.mcp.json`** also registers a `hayabusa` server, but pointed at `.venv/Scripts/python.exe` instead of plain `python` — this is the file Claude Code actually reads to launch MCP servers; `settings.json`'s real schema only has approval/toggle keys (`enableAllProjectMcpServers`, `enabledMcpjsonServers`, `disabledMcpjsonServers`), not server definitions. Plain `python` is a broken Windows Store stub alias on this machine, and `mcp` is only installed in the project-local `.venv` (see Setup above), so `.mcp.json` uses the venv interpreter to actually work here.

In short: `.claude/settings.json` satisfies the assignment's literal spec; `.mcp.json` is what makes the server actually launch in this environment. If ported to Linux/Mac, `.mcp.json`'s `command` needs to change to `.venv/bin/python`.

## Sample data

`samples/` holds real EVTX files for manual testing (no README of its own — kept here to avoid an extra file per directory).

- **`UACME_59_Sysmon.evtx`** (68 KB) — Sysmon-instrumented capture of a UAC bypass via [UACME](https://github.com/hfiref0x/UACME) method 59, from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (downloaded from `raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/UACME_59_Sysmon.evtx`). Contains real Sysmon Event ID 10 (ProcessAccess) and Event ID 1 (ProcessCreate) records.
  - Scanned with default `scan_evtx()`: 8 detections —
    - 5x `Level: "low"`, `RuleTitle: "Proc Access"`, `EventID: 10` (`Akagi_64.exe`/`svchost.exe`/`explorer.exe` accessing `cmd.exe`, `explorer.exe`, `taskmgr.exe`)
    - 2x `Level: "info"`, `RuleTitle: "Proc Exec"`, `EventID: 1` (`Taskmgr.exe` spawned by `Akagi_64.exe`; `cmd.exe` spawned by `Taskmgr.exe`)
    - 1x `Level: "low"`, `RuleTitle: "New Process Created Via Taskmgr.EXE"`, `EventID: 1` (`cmd.exe` launched via `Taskmgr.exe` — the UACME method 59 signature: auto-elevated Task Manager spawning a child process, yielding an elevated shell without a UAC prompt)
    - Note: an earlier run of this same file logged all 8 as `Proc Access`/`low` only — the "Proc Exec" and "New Process Created Via Taskmgr.EXE" rules apparently weren't firing then. Likely due to a bundled detection-rule update between runs (rules live in `./hayabusa/`, which is gitignored and re-downloaded by `download_hayabusa.py`, so its contents drift over time independent of this repo's git history).
  - Scanned with `min_severity="high"`: 0 detections (correctly excludes the low/info-severity hits — confirms the `-m` filter actually narrows results).
  - Scanned with `scan_chainsaw()` (default, all native rule categories) and `scan_chainsaw(rule_type="credential_access")`: 0 detections either way. Expected, not a bug — Chainsaw's native `rules/evtx/` ruleset mostly targets Security-log event IDs (logons, account tampering, RDP, etc.), and this sample only contains Sysmon Event IDs 1 and 10. Confirms the plumbing works (valid empty JSON, exit 0) without exercising a real hit; see `test_server.py` for the invalid-`rule_type` and missing-file error-path coverage instead.

Add new samples here with the same pattern: filename, size, source, what technique/event types it contains, and the actual tool output it produces, so this doubles as a regression reference. A sample with Security-log events (e.g. 4624/4625/4769 logon events) would be a better fit for exercising `scan_chainsaw`'s native ruleset with an actual hit.

## Testing

`test_server.py` is a manual smoke test (no framework, no pytest) that imports `server` and calls `scan_evtx()`/`get_hayabusa_rules()`/`scan_chainsaw()` directly against `samples/UACME_59_Sysmon.evtx` (see Sample data above). Run it with `.venv/Scripts/python.exe test_server.py` (takes a couple minutes — several full Hayabusa runs plus the ~5s rule-index parse add up). It checks: the default (summary) scan, `min_severity="high"`, `output_format="full"`, `max_results=2` (truncation), `rule_filter="access"` (narrows 8 detections to the 5 "Proc Access" hits), a `rule_filter` with no matches (error path), a missing input file (error path), `get_hayabusa_rules(keyword="mimikatz")`, `get_hayabusa_rules()` with no keyword (verifying the 200-result cap kicks in against the ~5000-rule bundled set), `scan_chainsaw()` default and `rule_type="credential_access"`, an invalid `rule_type` (error path listing real categories), and a missing input file for `scan_chainsaw` — see Sample data for the expected scan result counts.
