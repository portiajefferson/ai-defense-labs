# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This directory is currently empty — no code has been written yet.

## Planned project: MCP server for a detection engineering knowledge base

An MCP server that exposes a Sigma-rule-based detection engineering knowledge base: browsable Sigma rules, ATT&CK technique mappings, and detection-coverage queries — designed to complement the Hayabusa EVTX scanner built in Module 3 (`module-03-mcp/mcp-hayabusa`).

**Goals:**
- Expose Sigma rules as browsable resources
- Expose ATT&CK technique mappings
- Allow Claude to query detection coverage
- Combine with Hayabusa scanning from Module 3

**Stack:**
- Python, using the `mcp` library — likely both `@mcp.resource()` (for browsable rules/mappings) and `@mcp.tool()` (for coverage queries), unlike Module 3's `mcp-hayabusa`, which only exposes tools

**Planned structure:**
- `rules/` — Sigma detection rules (YAML)
- `mappings/` — ATT&CK technique to rule mappings
- `server.py` — MCP server with resources and tools

There are no build, lint, or test commands defined yet, and no architecture to document beyond the planned structure above.

Update this file with real build/lint/test commands and architecture notes once the tool's code is written.
