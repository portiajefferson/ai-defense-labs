# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (the Rust-based Windows event log / EVTX analysis and threat-hunting tool) for EVTX analysis.

**Goals:**
- Expose a `scan_evtx` tool that runs the Hayabusa CLI against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully

**Stack:**
- Python, using the `mcp` library (`mcp.server.fastmcp.FastMCP`)
- Hayabusa CLI — not vendored; either present on PATH, or downloaded locally via `download_hayabusa.py`

## Setup

```
python3.14 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt         # Linux/Mac

python3.14 download_hayabusa.py   # only needed if hayabusa isn't already on PATH
```

Note: on this machine, plain `python`/`python3` are Windows Store stub aliases that fail — use `python3.14`. The system Python is `uv`-managed and externally-managed (PEP 668), so dependencies must go in a venv rather than a global `pip install`.

**Run the server:** `python3.14 server.py` (or `.venv/Scripts/python.exe server.py` if deps are only in the venv).

## Architecture

- **`server.py`** — the MCP server. `FastMCP("hayabusa")` exposes one tool, `scan_evtx(evtx_path, min_severity=None)`.
- **`resolve_hayabusa_binary()`** checks `PATH` first (`shutil.which("hayabusa")`), then falls back to `./hayabusa/hayabusa*` (the location `download_hayabusa.py` extracts to). The downloaded binary is versioned (e.g. `hayabusa-3.10.0-win-x64.exe`), not literally named `hayabusa`, hence the glob rather than an exact-name check.
- **`scan_evtx` shells out to `hayabusa json-timeline`**, writing JSONL to a temp file (`-o <path> -L`) rather than reading stdout directly, then parses that file line-by-line into a list of dicts. `-w` (no-wizard) is required — without it, Hayabusa's interactive rule-selection prompt would hang the subprocess. `-d` vs `-f` is chosen based on whether `evtx_path` is a directory.
- **Severity filtering** uses Hayabusa's own `-m/--min-level` flag (values: `informational`, `low`, `medium`, `high`, `critical`) rather than filtering results after the fact, so Hayabusa only loads/runs the relevant detection rules.
- **Error handling returns a structured `{"success": False, "error": ...}` dict instead of raising** for every known failure mode: binary not found, input path missing, invalid severity, subprocess timeout/OSError, non-zero exit code, missing output file, and JSON parse errors. Note that Hayabusa itself is lenient — it can exit 0 and still fail to produce meaningful results for e.g. a non-EVTX input file, logging the real error to its own `./logs/errorlog-*.log` instead of stderr. The wrapper doesn't currently inspect that log; a scan of unparseable input surfaces as `event_count: 0` rather than an explicit error.
- **`download_hayabusa.py`** queries the GitHub releases API for the latest Hayabusa release, matches the asset for the current OS/architecture (excluding the `-live-response` variant via an exact `-<suffix>.zip` suffix match, not a substring match), downloads and extracts it to `./hayabusa/`, and chmods any `hayabusa*` file executable (relevant on Linux/Mac; extracted `.exe` on Windows doesn't need it).
- **`hayabusa/`** (downloaded binary + bundled detection rules) and `.venv/` are gitignored — neither is project source.
