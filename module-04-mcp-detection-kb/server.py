#!/usr/bin/env python3
"""MCP server exposing a Sigma-rule-based detection engineering knowledge base."""

import json
import re
import urllib.request
from pathlib import Path

from mcp.server.fastmcp import FastMCP

RULES_DIR = Path(__file__).parent / "rules"
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

_TITLE_RE = re.compile(r"^title:\s*(.+?)\s*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:\s*(.+?)\s*$", re.MULTILINE)
_LEVEL_RE = re.compile(r"^level:\s*(.+?)\s*$", re.MULTILINE)
_STATUS_RE = re.compile(r"^status:\s*(.+?)\s*$", re.MULTILINE)
_TAGS_BLOCK_RE = re.compile(r"^tags:[ \t]*(.*)$\n((?:^[ \t]+-.*$\n?)*)", re.MULTILINE)
_TAGS_ITEM_RE = re.compile(r"^[ \t]+-\s*(.+?)\s*$", re.MULTILINE)

mcp = FastMCP("detection-kb")


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_rule(path: Path) -> dict | None:
    """Extract the handful of top-level fields needed for browsing/filtering from a
    Sigma rule YAML file, via regex rather than a full YAML parse (no PyYAML dependency,
    matching Module 3's mcp-hayabusa approach)."""
    text = path.read_text(encoding="utf-8")

    title_match = _TITLE_RE.search(text)
    if not title_match:
        return None

    tags = []
    tags_match = _TAGS_BLOCK_RE.search(text)
    if tags_match:
        inline, block = tags_match.groups()
        if inline.strip():
            tags = [_strip_quotes(t.strip()) for t in inline.strip().strip("[]").split(",") if t.strip()]
        elif block:
            tags = [_strip_quotes(m.group(1)) for m in _TAGS_ITEM_RE.finditer(block)]

    id_match = _ID_RE.search(text)
    level_match = _LEVEL_RE.search(text)
    status_match = _STATUS_RE.search(text)

    return {
        "rule_name": path.stem,
        "title": _strip_quotes(title_match.group(1)),
        "id": _strip_quotes(id_match.group(1)) if id_match else None,
        "level": _strip_quotes(level_match.group(1)) if level_match else None,
        "status": _strip_quotes(status_match.group(1)) if status_match else None,
        "tags": tags,
    }


def _iter_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        meta = _parse_rule(path)
        if meta is not None:
            rules.append(meta)
    return rules


def _resolve_rule_path(rule_name: str) -> Path | None:
    """Resolve a rule_name to a file under RULES_DIR, guarding against path traversal."""
    path = (RULES_DIR / f"{rule_name}.yml").resolve()
    try:
        path.relative_to(RULES_DIR.resolve())
    except ValueError:
        return None
    return path


def _rules_for_technique_tag(tag: str) -> list[dict]:
    """rules whose tags include an exact (case-insensitive) attack.<technique_id> tag."""
    return [r for r in _iter_rules() if tag in (t.lower() for t in r["tags"])]


def _parent_technique_id(technique_id: str) -> str | None:
    """T1003.001 -> T1003; T1003 -> None."""
    return technique_id.split(".")[0] if "." in technique_id else None


_attack_technique_index_cache: dict | None = None


def _load_attack_technique_index() -> dict:
    """Fetch the MITRE ATT&CK Enterprise STIX bundle (~53MB) and index attack-pattern
    objects by technique ID, caching the result for the life of the process -- refetching
    per-request would be far too slow (a full download takes several seconds)."""
    global _attack_technique_index_cache
    if _attack_technique_index_cache is not None:
        return _attack_technique_index_cache

    req = urllib.request.Request(ATTACK_STIX_URL, headers={"User-Agent": "mcp-detection-kb"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        bundle = json.load(resp)

    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                index[ref["external_id"]] = obj
                break

    _attack_technique_index_cache = index
    return index


@mcp.resource("detection://rules")
def list_rules() -> str:
    """List all available Sigma detection rules in the knowledge base."""
    rules = _iter_rules()
    return json.dumps({"rule_count": len(rules), "rules": rules}, indent=2)


@mcp.resource("detection://rules/{rule_name}")
def get_rule(rule_name: str) -> str:
    """Return a specific rule's raw Sigma YAML content, by filename (without .yml)."""
    path = _resolve_rule_path(rule_name)
    if path is None or not path.is_file():
        available = [p.stem for p in sorted(RULES_DIR.glob("*.yml"))]
        return json.dumps({"error": f"Rule '{rule_name}' not found", "available": available}, indent=2)
    return path.read_text(encoding="utf-8")


@mcp.resource("detection://rules/by-technique/{technique_id}")
def list_rules_by_technique(technique_id: str) -> str:
    """List rules tagged with a given ATT&CK technique ID, e.g. T1003.001."""
    matches = _rules_for_technique_tag(f"attack.{technique_id.lower()}")
    return json.dumps({"technique_id": technique_id, "rule_count": len(matches), "rules": matches}, indent=2)


@mcp.resource("detection://attack/techniques/{technique_id}")
def get_technique_coverage(technique_id: str) -> str:
    """Look up an ATT&CK technique (name + description) and assess this knowledge base's
    detection coverage for it, based on which Sigma rules are tagged with it.

    Coverage is "covered" if a rule is tagged with this exact technique ID, "partial" if
    no rule matches exactly but a related technique does (the parent technique, for a
    sub-technique ID; any sub-technique, for a parent ID), and "gap" otherwise.
    """
    technique_id = technique_id.upper()

    try:
        technique_index = _load_attack_technique_index()
    except OSError as e:
        return json.dumps({"error": f"Failed to fetch ATT&CK data: {e}"}, indent=2)

    technique = technique_index.get(technique_id)
    if technique is None:
        return json.dumps({"error": f"Unknown ATT&CK technique '{technique_id}'"}, indent=2)

    detecting_rules = _rules_for_technique_tag(f"attack.{technique_id.lower()}")

    related_coverage = None
    if detecting_rules:
        coverage = "covered"
    else:
        parent_id = _parent_technique_id(technique_id)
        if parent_id:
            related_via, related_rules = parent_id, _rules_for_technique_tag(f"attack.{parent_id.lower()}")
        else:
            child_prefix = f"attack.{technique_id.lower()}."
            related_via = f"{technique_id}.*"
            related_rules = [r for r in _iter_rules() if any(t.lower().startswith(child_prefix) for t in r["tags"])]

        coverage = "partial" if related_rules else "gap"
        if related_rules:
            related_coverage = {"via": related_via, "rules": related_rules}

    return json.dumps({
        "technique_id": technique_id,
        "name": technique.get("name"),
        "description": technique.get("description"),
        "is_subtechnique": technique.get("x_mitre_is_subtechnique", False),
        "coverage": coverage,
        "detecting_rules": detecting_rules,
        "related_coverage": related_coverage,
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
