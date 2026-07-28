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

## Done and pushed: directory flatten (no code merge yet)

- `module-03-mcp/mcp-hayabusa/` → `ai-defense-labs/mcp-hayabusa/` (root-level,
  no `src/` prefix — resolves open question 5 below: root, not `src/`).
- `module-04-mcp-detection-kb/` → `ai-defense-labs/mcp-detection-kb/` (resolves
  the naming question: `mcp-detection-kb` is the actual name from the
  assignment's own setup commands — `mkdir ~/mcp-detection-kb` — not a name we
  had to invent).
- Both `.mcp.json` and `.claude/settings.json` inside `mcp-hayabusa/` use
  relative paths/commands (`python server.py` etc.), so no edits were needed
  there for the move itself.
- **Mechanical note:** `module-03-mcp/mcp-hayabusa/`'s rename via `git mv`
  failed with "Permission denied" — this session's own shell has its working
  directory pinned inside that exact path (the "Primary working directory"),
  and Windows won't rename/delete a directory that's an active process's CWD.
  Worked around it with copy (`cp -r`) into the new location + `git rm
  --cached` + deleting the old files individually (file deletes are fine even
  inside a locked directory; only the directory node itself is locked).
  Leftover: two now-empty, **untracked** stray directories physically remain
  on disk — `module-03-mcp/mcp-hayabusa/` and `module-03-mcp/` — because the
  lock never released mid-session. They're harmless (git ignores empty dirs,
  `git status` is clean) but won't disappear until this session's shell
  process ends; delete them manually once you're back in a fresh terminal if
  they're still bothering you.
- Per explicit instruction, this was **directory flattening only** — no
  `server.py` code was touched or merged. The merge itself is still pending
  the user's further research into Module 4's schematics.

## Still pending: merging module-03 + module-04 code

The plan is to eventually combine `mcp-hayabusa/server.py` and
`mcp-detection-kb/server.py` (the Sigma-rule/ATT&CK coverage MCP server) into
**one consolidated MCP server** — apparently Module 4's assignment explicitly
offered the option of building its functionality into Module 3's server
instead of a separate one, which is the road we're taking. User wants to hold
off on this until they've dug further into Module 4's schematics.

**Target folder structure for the merged result, given verbatim by the user:**

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

**Confirmed:** the user gave the overall go-ahead to flatten/merge module-03 and
module-04 ("yes Module 3 and Module 4 can be flattened") before signing off for
the night. That's a green light on *direction*, not on the specifics below —
the 5 detailed questions were not answered in that message and still need
resolving before actually executing the merge (don't guess at these from the
green-light alone):

**Still open — need answers before starting the actual code merge** (question
5 from the original list, final folder location, is now resolved — root
level, no `src/` — and the naming question is resolved too, both above):

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

**Also not yet done, blocked on the above:**
- The actual code merge: combine `mcp-hayabusa/server.py` and
  `mcp-detection-kb/server.py` into one file. Both currently define
  similarly-named helpers (`RULES_DIR`, `_iter_rules()`, `_parse_rule()`) over
  *different* rule sets — plan (not yet executed) is to namespace them
  distinctly (e.g. `HAYABUSA_RULES_DIR`/`_iter_hayabusa_rules()` vs.
  `KB_RULES_DIR`/`_iter_kb_rules()`) rather than collapsing them into one.
- Moving `mcp-detection-kb/rules/` + `mappings/technique_coverage.yml` under
  `mcp-hayabusa/hayabusa/rules/` (in a distinct subpath, not mixed loose into
  the ~5,000-rule vendored corpus).
- Deleting `mcp-detection-kb/` once its content has been folded in.
- **Also needed:** the `hayabusa` MCP server (a live `.venv/Scripts/python.exe`
  process) had to be killed to free the directory lock for this flatten — it
  will need reconnecting (`/mcp`) next session, and it'll need a fresh `.venv`
  too since the old one was removed earlier this session (see repo's general
  setup: `python3.14 -m venv .venv && .venv/Scripts/python.exe -m pip install
  -r requirements.txt`).

## Resuming

Pick up by getting answers to the 4 remaining open questions above (chainsaw,
download scripts, `.mcp.json`, `test_server.py`), then execute the merge:
combine the two `server.py`s with distinct rule namespacing, move
`mcp-detection-kb`'s rules/mappings under `mcp-hayabusa/hayabusa/rules/`,
delete `mcp-detection-kb/` once folded in, recreate the venv, and commit.
