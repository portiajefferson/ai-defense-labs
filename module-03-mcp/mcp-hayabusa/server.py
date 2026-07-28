#!/usr/bin/env python3
"""MCP server wrapping the Hayabusa CLI for EVTX analysis."""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

LOCAL_HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
RULES_DIR = LOCAL_HAYABUSA_DIR / "rules"
LOCAL_CHAINSAW_DIR = Path(__file__).parent / "chainsaw"
CHAINSAW_RULES_DIR = LOCAL_CHAINSAW_DIR / "rules"
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
OUTPUT_FORMATS = ["summary", "full"]
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "RuleID"]
RULE_INDEX_DISPLAY_LIMIT = 200

_RULE_TITLE_RE = re.compile(r"^title:\s*(.+?)\s*$", re.MULTILINE)
_RULE_ID_RE = re.compile(r"^id:\s*(.+?)\s*$", re.MULTILINE)
_RULE_LEVEL_RE = re.compile(r"^level:\s*(.+?)\s*$", re.MULTILINE)
_RULE_STATUS_RE = re.compile(r"^status:\s*(.+?)\s*$", re.MULTILINE)
_RULE_TAGS_BLOCK_RE = re.compile(r"^tags:[ \t]*(.*)$\n((?:^[ \t]+-.*$\n?)*)", re.MULTILINE)
_RULE_TAGS_ITEM_RE = re.compile(r"^[ \t]+-\s*(.+?)\s*$", re.MULTILINE)

_rule_index_cache: list[dict] | None = None

mcp = FastMCP("hayabusa")


def resolve_hayabusa_binary() -> str | None:
    """Find the Hayabusa binary on PATH, or fall back to ./hayabusa/ (see download_hayabusa.py)."""
    on_path = shutil.which("hayabusa")
    if on_path:
        return on_path
    if LOCAL_HAYABUSA_DIR.is_dir():
        for candidate in sorted(LOCAL_HAYABUSA_DIR.glob("hayabusa*")):
            if candidate.is_file():
                return str(candidate)
    return None


def resolve_chainsaw_binary() -> str | None:
    """Find the Chainsaw binary on PATH, or fall back to ./chainsaw/ (see download_chainsaw.py)."""
    on_path = shutil.which("chainsaw")
    if on_path:
        return on_path
    if LOCAL_CHAINSAW_DIR.is_dir():
        for candidate in sorted(LOCAL_CHAINSAW_DIR.glob("chainsaw*")):
            if candidate.is_file():
                return str(candidate)
    return None


def _strip_yaml_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_rule_metadata(path: Path) -> dict | None:
    """Extract the handful of top-level fields we care about from a Sigma/Hayabusa rule YAML file.

    Deliberately regex-based rather than a full YAML parse: we only need a handful of
    top-level scalar/list fields for browsing, and pulling in PyYAML for that is overkill
    (see requirements.txt's existing stdlib-only stance).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    title_match = _RULE_TITLE_RE.search(text)
    if not title_match:
        return None

    tags = []
    tags_match = _RULE_TAGS_BLOCK_RE.search(text)
    if tags_match:
        inline, block = tags_match.groups()
        if inline.strip():
            tags = [_strip_yaml_quotes(t.strip()) for t in inline.strip().strip("[]").split(",") if t.strip()]
        elif block:
            tags = [_strip_yaml_quotes(m.group(1)) for m in _RULE_TAGS_ITEM_RE.finditer(block)]

    id_match = _RULE_ID_RE.search(text)
    level_match = _RULE_LEVEL_RE.search(text)
    status_match = _RULE_STATUS_RE.search(text)

    return {
        "title": _strip_yaml_quotes(title_match.group(1)),
        "id": _strip_yaml_quotes(id_match.group(1)) if id_match else None,
        "level": _strip_yaml_quotes(level_match.group(1)) if level_match else None,
        "status": _strip_yaml_quotes(status_match.group(1)) if status_match else None,
        "tags": tags,
        "path": path.relative_to(RULES_DIR).as_posix(),
        "_abs_path": path,
    }


def _load_rule_index() -> list[dict]:
    """Parse every rule file under RULES_DIR once per process and cache the result (~5s for ~5000 files)."""
    global _rule_index_cache
    if _rule_index_cache is not None:
        return _rule_index_cache

    rules = []
    for yml_path in RULES_DIR.rglob("*.yml"):
        if "config" in yml_path.parts or ".git" in yml_path.parts:
            continue
        meta = _parse_rule_metadata(yml_path)
        if meta is not None:
            rules.append(meta)

    _rule_index_cache = rules
    return rules


def _rule_matches_keyword(rule: dict, keyword: str) -> bool:
    keyword = keyword.lower()
    if keyword in rule["title"].lower():
        return True
    if keyword in rule["path"].lower():
        return True
    if rule["id"] and keyword in rule["id"].lower():
        return True
    return any(keyword in tag.lower() for tag in rule["tags"])


@mcp.tool()
def scan_evtx(
    evtx_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Run Hayabusa against an EVTX file and return structured results.

    Args:
        evtx_path: Path to the .evtx file (or a directory of .evtx files) to scan.
        min_severity: Optional minimum severity to include — one of
            informational, low, medium, high, critical.
        rule_filter: Optional keyword to restrict which detection rules run — matched
            case-insensitively against rule title, tags, and rule ID (e.g. "lateral" or
            "mimikatz"). See get_hayabusa_rules to preview which rules a keyword selects.
        output_format: "summary" (default) returns condensed per-event fields
            (Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID, RuleID).
            "full" returns Hayabusa's complete event dicts, including the Details and
            ExtraFieldInfo blocks.
        max_results: Optional cap on the number of events returned (the response still
            reports the true total via event_count).
    """
    hayabusa_bin = resolve_hayabusa_binary()
    if hayabusa_bin is None:
        return {
            "success": False,
            "error": "Hayabusa binary not found on PATH or in ./hayabusa/ (run download_hayabusa.py)",
        }

    if not Path(evtx_path).exists():
        return {"success": False, "error": f"Path not found: {evtx_path}"}

    if min_severity is not None and min_severity.lower() not in SEVERITY_LEVELS:
        return {
            "success": False,
            "error": f"min_severity must be one of {SEVERITY_LEVELS}, got '{min_severity}'",
        }

    if output_format.lower() not in OUTPUT_FORMATS:
        return {
            "success": False,
            "error": f"output_format must be one of {OUTPUT_FORMATS}, got '{output_format}'",
        }

    if max_results is not None and max_results <= 0:
        return {"success": False, "error": f"max_results must be a positive integer, got {max_results}"}

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        input_flag = "-d" if Path(evtx_path).is_dir() else "-f"

        # Flags verified against `hayabusa json-timeline --help` on v3.10.0.
        command = [
            hayabusa_bin,
            "json-timeline",
            input_flag, evtx_path,
            "-o", str(output_path),
            "-L",  # JSONL output (paired with -o, per --help)
            "-w",  # no-wizard: don't prompt interactively, scan everything
            "-q",  # quiet: suppress the launch banner
        ]
        if min_severity is not None:
            command += ["-m", min_severity.lower()]

        if rule_filter:
            if not RULES_DIR.is_dir():
                return {
                    "success": False,
                    "error": f"rule_filter requires the local rules directory at {RULES_DIR}, which was not found",
                }
            matching = [r for r in _load_rule_index() if _rule_matches_keyword(r, rule_filter)]
            if not matching:
                return {"success": False, "error": f"No rules matched rule_filter '{rule_filter}'"}

            filtered_rules_dir = Path(tmp_dir) / "rules"
            for rule in matching:
                dest = filtered_rules_dir / rule["path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(rule["_abs_path"], dest)

            command += ["-r", str(filtered_rules_dir), "-c", str(RULES_DIR / "config")]

        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Hayabusa scan timed out"}
        except OSError as e:
            return {"success": False, "error": f"Failed to run Hayabusa: {e}"}

        if proc.returncode != 0:
            return {
                "success": False,
                "error": f"Hayabusa exited with code {proc.returncode}",
                "stderr": proc.stderr.strip(),
            }

        if not output_path.exists():
            return {"success": False, "error": "Hayabusa produced no output file"}

        events = []
        try:
            with open(output_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse Hayabusa output: {e}"}

    if output_format.lower() == "summary":
        events = [{field: event.get(field) for field in SUMMARY_FIELDS} for event in events]

    total_count = len(events)
    truncated = max_results is not None and max_results < total_count
    if truncated:
        events = events[:max_results]

    return {
        "success": True,
        "event_count": total_count,
        "returned_count": len(events),
        "truncated": truncated,
        "events": events,
    }


@mcp.tool()
def get_hayabusa_rules(keyword: str | None = None) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Useful for previewing what a rule_filter value on scan_evtx would select, or for
    exploring what detections exist before running a scan.

    Args:
        keyword: Optional substring to match case-insensitively against rule title,
            tags, and rule ID (e.g. "lateral" or "mimikatz"). Omit to list all rules
            (capped — see `truncated` in the response).
    """
    if not RULES_DIR.is_dir():
        return {
            "success": False,
            "error": f"Local rules directory not found at {RULES_DIR} (run download_hayabusa.py)",
        }

    rules = _load_rule_index()
    if keyword:
        rules = [r for r in rules if _rule_matches_keyword(r, keyword)]

    total_count = len(rules)
    truncated = total_count > RULE_INDEX_DISPLAY_LIMIT
    rules = rules[:RULE_INDEX_DISPLAY_LIMIT]

    return {
        "success": True,
        "rule_count": total_count,
        "returned_count": len(rules),
        "truncated": truncated,
        "rules": [
            {"title": r["title"], "id": r["id"], "level": r["level"], "status": r["status"], "tags": r["tags"], "path": r["path"]}
            for r in rules
        ],
    }


@mcp.tool()
def scan_chainsaw(evtx_path: str, rule_type: str | None = None) -> dict:
    """Run Chainsaw against an EVTX file/directory using its native EVTX detection rules.

    Chainsaw is a second, independent EVTX hunting tool (github.com/WithSecureLabs/chainsaw) —
    useful for cross-checking scan_evtx's Hayabusa-based results with a different rule engine.

    Args:
        evtx_path: Path to the .evtx file (or a directory of .evtx files) to hunt through.
        rule_type: Optional category to restrict which native rules run, e.g.
            "credential_access", "lateral_movement", "persistence", "login_attacks".
            Omit to run all bundled categories. An invalid value returns the full list
            of available categories in the error message.
    """
    chainsaw_bin = resolve_chainsaw_binary()
    if chainsaw_bin is None:
        return {
            "success": False,
            "error": "Chainsaw binary not found on PATH or in ./chainsaw/ (run download_chainsaw.py)",
        }

    if not Path(evtx_path).exists():
        return {"success": False, "error": f"Path not found: {evtx_path}"}

    if not CHAINSAW_RULES_DIR.is_dir():
        return {
            "success": False,
            "error": f"Chainsaw native rules not found at {CHAINSAW_RULES_DIR} (run download_chainsaw.py)",
        }

    rules_path = CHAINSAW_RULES_DIR
    if rule_type is not None:
        candidate = CHAINSAW_RULES_DIR / rule_type
        if not candidate.is_dir():
            available = sorted(p.name for p in CHAINSAW_RULES_DIR.iterdir() if p.is_dir())
            return {
                "success": False,
                "error": f"Unknown rule_type '{rule_type}'. Available: {available}",
            }
        rules_path = candidate

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.json"

        # Flags verified against `chainsaw hunt --help` on v2.16.2. --no-banner is a
        # top-level flag and must precede the `hunt` subcommand.
        command = [
            chainsaw_bin,
            "--no-banner",
            "hunt",
            str(rules_path), evtx_path,
            "--json",
            "-o", str(output_path),
            "-q",  # suppress informational output
        ]

        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Chainsaw hunt timed out"}
        except OSError as e:
            return {"success": False, "error": f"Failed to run Chainsaw: {e}"}

        if proc.returncode != 0:
            return {
                "success": False,
                "error": f"Chainsaw exited with code {proc.returncode}",
                "stderr": proc.stderr.strip(),
            }

        if not output_path.exists():
            return {"success": False, "error": "Chainsaw produced no output file"}

        try:
            with open(output_path, encoding="utf-8") as f:
                events = json.load(f)
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse Chainsaw output: {e}"}

    return {"success": True, "event_count": len(events), "events": events}


if __name__ == "__main__":
    mcp.run()
