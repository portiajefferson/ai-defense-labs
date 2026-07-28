# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

An MCP server exposing a Sigma-rule-based detection engineering knowledge base: browsable Sigma rules, ATT&CK technique mappings, and detection-coverage queries — designed to complement the Hayabusa EVTX scanner built in Module 3 (`module-03-mcp/mcp-hayabusa`).

**Goals:**
- Expose Sigma rules as browsable resources
- Expose ATT&CK technique mappings and per-technique coverage lookups
- Allow Claude to query aggregate detection coverage against the local rule set
- Combine with Hayabusa scanning from Module 3

**Stack:**
- Python, using the `mcp` library — both `@mcp.resource()` (browsable rules/mappings) and `@mcp.tool()` (coverage queries), unlike Module 3's `mcp-hayabusa`, which only exposes tools
- Sigma YAML is parsed with regex/line-parsing, not PyYAML — stdlib-only, matching Module 3's approach (see `requirements.txt`)

## Structure

```
CLAUDE.md
server.py
rules/                          # Sigma detection rules (YAML)
    dcsync.yml
    kerberoasting.yml
    lsass_memory_access.yml
    mimikatz_command_line.yml
    pass_the_hash.yml
mappings/
    technique_coverage.yml       # ATT&CK technique -> expected rule_name list
.claude/
    settings.json                # MCP registration
```

Rule files are named after the technique/concept they detect (`lsass_memory_access.yml`, `kerberoasting.yml`), not SigmaHQ's `<category>_win_<description>.yml` convention used by Module 3's vendored corpus.

## Resource URI schemes

This server (and sibling modules in this repo) use a common URI-scheme convention for MCP resources:

| Scheme         | Use case                                    | Status |
|----------------|-----------------------------------------------|--------|
| `detection://` | Detection rules, coverage, environment, cases  | Implemented — backed by `rules/`, `mappings/technique_coverage.yml`, and live MITRE ATT&CK data; environment/investigations sub-paths are stubs (see below) |
| `playbook://`  | IR playbooks, procedures                       | Stub — no `playbooks/` data source exists yet |
| `intel://`     | Threat intelligence (actors, IOCs)             | Stub — no intel data source exists yet |
| `docs://`      | Documentation                                  | Stub — no `docs/` directory exists yet |

Environment context and past-investigation lookups live under `detection://` rather than a
separate scheme (`detection://environment/*`, `detection://investigations*`) — there is no
top-level `env://`.

The stub resources in `server.py` return `{"status": "not_implemented", ...}` rather than
erroring, so a caller can distinguish "not configured" from "broken." Wire up a real backing
store (a new top-level directory, typically) before removing the stub status.

## Architecture

- **`server.py`** — `FastMCP("detection-kb")`.
  - **Resources:**
    - `detection://rules` — list all Sigma rules under `rules/` (title, id, level, status, tags parsed via regex — see `_parse_rule`)
    - `detection://rules/{rule_name}` — raw YAML for one rule, by filename stem; path-traversal-guarded via `_resolve_rule_path`
    - `detection://rules/by-technique/{technique_id}` — rules tagged `attack.<technique_id>` (case-insensitive)
    - `detection://attack/techniques/{technique_id}` — looks up a technique against the live MITRE ATT&CK Enterprise STIX bundle (fetched once, cached in `_attack_technique_index_cache`) and reports `covered`/`partial`/`gap` based on which local rules are tagged for it or a related (parent/child) technique, via the shared `_assess_technique_coverage()` helper (also used by the `analyze_coverage`/`suggest_rule` tools below)
    - `detection://environment/hosts`, `detection://environment/services`, `detection://environment/baselines` — stubs; no host/service/baseline inventory exists yet
    - `detection://investigations`, `detection://investigations/{case_id}`, `detection://investigations/by-technique/{technique_id}` — stubs; no past-case data source exists yet
    - `playbook://list`, `intel://list`, `docs://list` — stubs, see table above
  - **Tools:**
    - `assess_coverage()` — cross-checks `mappings/technique_coverage.yml`'s tracked techniques against what's actually tagged in `rules/`, reporting per-technique coverage and flagging drift (`in_sync: false`) if the mapping file's expected rule list no longer matches reality. This is the aggregate/local-only counterpart to `detection://attack/techniques/{id}`, which checks one technique at a time against live MITRE data.
    - `analyze_coverage(identifier)` — takes either a technique ID (`T1003.001`) or a tactic name (`credential-access`, "Lateral Movement" — normalized via `_normalize_tactic_name`); for a tactic, resolves every technique under it via `_techniques_for_tactic()` (matching STIX `kill_chain_phases`) and reports covered/partial/gap counts plus a `gap_technique_ids` list. Tool-shaped counterpart to `detection://attack/techniques/{id}`: same coverage logic, but takes either a single ID or a whole tactic and always returns a report.
    - `suggest_rule(technique_id, create_template=False)` — for a single technique ID: if already covered, says so and stops; if a gap, suggests a detection approach from that technique's ATT&CK `x_mitre_data_sources`/`x_mitre_platforms`. With `create_template=True` on a gap, writes a placeholder Sigma rule (`status: experimental`, empty `detection.selection`, tagged `attack.<technique_id>`) into `rules/` via `_render_rule_template()`, named after the technique (`_slugify()`), refusing to overwrite an existing file of that name.
- **`_load_technique_mappings()`** parses `mappings/technique_coverage.yml` with a purpose-built line parser (not PyYAML) — tractable because that file's shape (a flat `techniques:` list of small mappings) is fixed and small, unlike Sigma rules' more varied structure.
- **`.claude/settings.json`** registers this server, matching Module 3's registration pattern (see that module's CLAUDE.md for why Module 3 also needed a separate `.mcp.json` on this machine — worth checking whether this module hits the same `python` vs. venv-interpreter issue).

There are no build, lint, or automated-test commands defined yet.
