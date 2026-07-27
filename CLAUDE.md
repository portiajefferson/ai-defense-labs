# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository is currently a placeholder with no established codebase yet. It contains:
- `hello.txt` — a placeholder file
- `module2/sysmon-parser/` — empty directory, target location for the Sysmon parser project described below

There are no build, lint, or test commands defined yet, and no architecture to document.

## Planned project: Sysmon XML parser

`module2/sysmon-parser` will hold a Python tool that parses Sysmon Event ID 1 (Process Creation) events from XML and extracts key fields to JSON.

**Fields to extract:**
- EventID
- UtcTime
- Image (process path)
- CommandLine
- User
- IntegrityLevel
- ParentImage
- ParentCommandLine
- Computer
- Hashes

**Output format:** JSON — a single object per event, or a JSON array when parsing multiple events.

Update this file with real build/lint/test commands and architecture notes once the tool's code is written.
