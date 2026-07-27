# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This directory is currently empty — no code has been written yet.

## Planned project: MCP server wrapping Hayabusa

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (the Rust-based Windows event log / EVTX analysis and threat-hunting tool) for EVTX analysis.

**Goals:**
- Expose a `scan_evtx` tool that runs the Hayabusa CLI against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully

**Stack:**
- Python, using the `mcp` library
- Hayabusa CLI (installed locally — invoked as a subprocess, not vendored)

There are no build, lint, or test commands defined yet, and no architecture to document.

Update this file with real build/lint/test commands and architecture notes once the tool's code is written.
