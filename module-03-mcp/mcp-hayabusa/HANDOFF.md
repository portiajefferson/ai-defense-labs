# HANDOFF

## Where things stand

Mid-restructuring of the whole `ai-defense-labs` repo: consolidating from
per-module directories down to a flat, cleaned-up layout. This file picks up
right where a late-night session left off, in the middle of planning (not yet
executing) the module-03 + module-04 merge.

## Done and pushed (commits d3cd2eb, f8f5003, 1505c9c on `main`)

- Confirmed repo root (`ai-defense-labs/`) *is* the project root — no separate
  `project/` wrapper for the capstone tree. The existing `project/` dir is left
  alone for now (empty, untouched) per explicit instruction.
- `module-01-claude-ecosystem` deleted (was just a `hello.txt` connectivity test).
- `module-02-security-tool` flattened: its `sysmon-parser/` subfolder moved to
  `ai-defense-labs/sysmon-parser/` (top-level), and its `README.md` merged into
  a new root-level `README.md` (retitled "ai-defense-labs"). Going forward, all
  module READMEs consolidate into this one root README rather than staying
  per-folder.
- `module-05-skills` through `module-12-cross-siem-investigation` deleted
  (all were empty `.gitkeep` stubs — that future work builds fresh at root
  instead of growing out of these).

## In progress, NOT yet done: merging module-03 + module-04

The plan is to combine `module-03-mcp/mcp-hayabusa` (the Hayabusa/Chainsaw EVTX
scanner MCP server) and `module-04-mcp-detection-kb` (the Sigma-rule/ATT&CK
coverage MCP server) into **one consolidated MCP server** — apparently Module
4's assignment explicitly offered the option of building its functionality
into Module 3's server instead of a separate one, which is the road we're
taking.

**Target folder structure, given verbatim by the user:**

```
mcp-hayabusa/
├── CLAUDE.md              # Project context
├── requirements.txt       # Dependencies
├── server.py              # MCP server
├── hayabusa/              # Hayabusa binary
├── samples/               # Test EVTX files
└── .claude/
    └── settings.json      # MCP registration
```

**Confirmed decision:** all rule-related content — both Hayabusa's vendored
~5,000-rule Sigma corpus *and* module-04's 5 curated Sigma rules +
`mappings/technique_coverage.yml` — lands under `hayabusa/rules/` in the
merged folder. Plan is to keep the curated rules in a **distinct subpath**
within `hayabusa/rules/` (not mixed loose into the vendored corpus), so
`assess_coverage`/`analyze_coverage`/`suggest_rule` can find just their own 5
rules without scanning all ~5,000 Hayabusa rules. Exact subpath name not yet
decided.

**Still open — need answers before starting the actual merge:**

1. **`chainsaw/`** (the second detection engine, `scan_chainsaw` tool + native
   Chainsaw rules) — keep it, or is Chainsaw support being cut from the
   consolidated server? Not shown in the target tree above, unclear if that's
   an intentional cut or just omitted for brevity.
2. **`download_hayabusa.py` / `download_chainsaw.py`** — keep these setup
   scripts, or assume `hayabusa/` (and `chainsaw/`, if kept) arrive
   pre-populated some other way?
3. **`.mcp.json`** — today, `mcp-hayabusa` needs *both* `.claude/settings.json`
   (satisfies the assignment's literal spec) *and* a separate `.mcp.json`
   pointing at `.venv/Scripts/python.exe` (because plain `python` is a broken
   Windows Store stub on this machine, and `mcp` only lives in the venv). The
   target tree shows only `.claude/settings.json`. Keep `.mcp.json` too, or
   repoint `settings.json` itself at the venv path so `.mcp.json` isn't needed?
4. **`test_server.py`** — keep the manual smoke-test suite, or drop it?
5. **Final location of the merged folder** — genuinely ambiguous right now.
   Earlier in the conversation we discussed everything (`sysmon-parser`,
   `mcp-hayabusa`, detection-kb) eventually living under a root-level `src/`
   (i.e. `src/mcp-hayabusa/`), matching the original capstone tree
   (`project/src/CLAUDE.md`, `...`). But the tree given for *this* merge shows
   `mcp-hayabusa/` with no `src/` prefix, drawn the same way `sysmon-parser/`
   was drawn when it moved to repo root. Need to confirm: does the merged
   folder land at `ai-defense-labs/mcp-hayabusa/` (root-level sibling to
   `sysmon-parser/`), or `ai-defense-labs/src/mcp-hayabusa/`?

**Also not yet done, blocked on the above:**
- The actual code merge: combine `module-03-mcp/mcp-hayabusa/server.py` and
  `module-04-mcp-detection-kb/server.py` into one file. Both currently define
  similarly-named helpers (`RULES_DIR`, `_iter_rules()`, `_parse_rule()`) over
  *different* rule sets — plan (not yet executed) is to namespace them
  distinctly (e.g. `HAYABUSA_RULES_DIR`/`_iter_hayabusa_rules()` vs.
  `KB_RULES_DIR`/`_iter_kb_rules()`) rather than collapsing them into one.
- Moving module-04's `rules/` + `mappings/technique_coverage.yml` under
  `hayabusa/rules/`.
- Deleting `module-04-mcp-detection-kb/` and unwrapping `module-03-mcp/` once
  the merge lands in its final location.
- Nothing from this merge phase has been committed — repo is clean at commit
  `d3cd2eb` as of this handoff.

## Resuming

Pick up by getting answers to the 5 open questions above (chainsaw, download
scripts, `.mcp.json`, `test_server.py`, final folder location), then execute
the merge: combine the two `server.py`s with distinct rule namespacing, move
files into place, delete the now-empty source folders, and commit.
