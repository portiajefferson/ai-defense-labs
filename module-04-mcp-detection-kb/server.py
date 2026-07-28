#!/usr/bin/env python3
"""MCP server exposing a Sigma-rule-based detection engineering knowledge base."""

import json
import re
import urllib.request
import uuid
from datetime import date
from pathlib import Path

from mcp.server.fastmcp import FastMCP

RULES_DIR = Path(__file__).parent / "rules"
MAPPINGS_DIR = Path(__file__).parent / "mappings"
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


_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def _is_technique_id(identifier: str) -> bool:
    return bool(_TECHNIQUE_ID_RE.match(identifier.strip()))


def _normalize_tactic_name(name: str) -> str:
    """"Credential Access" / "credential_access" -> "credential-access", matching
    ATT&CK STIX kill_chain_phases' phase_name convention."""
    return re.sub(r"[\s_]+", "-", name.strip().lower())


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "rule"


def _techniques_for_tactic(tactic_name: str, technique_index: dict) -> list[tuple[str, dict]]:
    """All (technique_id, technique_obj) pairs whose kill_chain_phases include this tactic."""
    matches = []
    for tid, obj in technique_index.items():
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name") == tactic_name:
                matches.append((tid, obj))
                break
    return matches


def _technique_tactic(technique: dict) -> str | None:
    for phase in technique.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name")
    return None


def _assess_technique_coverage(technique_id: str, technique_index: dict) -> dict | None:
    """Shared coverage-assessment logic for one technique ID, used by both the
    detection://attack/techniques/{id} resource and the analyze_coverage/suggest_rule
    tools, so the covered/partial/gap rules stay in exactly one place."""
    technique = technique_index.get(technique_id)
    if technique is None:
        return None

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

    return {
        "technique_id": technique_id,
        "name": technique.get("name"),
        "description": technique.get("description"),
        "is_subtechnique": technique.get("x_mitre_is_subtechnique", False),
        "coverage": coverage,
        "detecting_rules": detecting_rules,
        "related_coverage": related_coverage,
    }


def _load_technique_mappings() -> list[dict]:
    """Parse mappings/technique_coverage.yml's list of technique entries.

    Purpose-built line parser rather than a general YAML parse (no PyYAML dependency,
    matching Module 3's mcp-hayabusa approach) -- tractable here because this file's
    shape (a flat `techniques:` list of small mappings) is fixed and small, unlike
    Sigma rules' more varied structure.
    """
    path = MAPPINGS_DIR / "technique_coverage.yml"
    if not path.is_file():
        return []

    entries = []
    current = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split(" #", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("- technique_id:"):
            if current is not None:
                entries.append(current)
            current = {"technique_id": stripped.split(":", 1)[1].strip(), "rules": []}
        elif current is not None and stripped.startswith("- ") and line.startswith("      "):
            current["rules"].append(stripped[2:].strip())
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            if key.strip() in ("name", "tactic"):
                current[key.strip()] = value.strip()
    if current is not None:
        entries.append(current)
    return entries


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

    result = _assess_technique_coverage(technique_id, technique_index)
    if result is None:
        return json.dumps({"error": f"Unknown ATT&CK technique '{technique_id}'"}, indent=2)
    return json.dumps(result, indent=2)


@mcp.resource("playbook://list")
def list_playbooks() -> str:
    """List available IR playbooks/procedures.

    Stub: no playbook data source exists yet in this repo. Returns an empty list with a
    `status` flag rather than an error, so a caller can distinguish "no playbooks configured"
    from a broken resource.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No playbooks/ directory exists yet in this repo.",
        "playbooks": [],
    }, indent=2)


@mcp.resource("intel://list")
def list_intel() -> str:
    """List available threat intelligence (actors, IOCs, campaigns).

    Stub: no intel data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No threat intel source configured yet in this repo.",
        "items": [],
    }, indent=2)


@mcp.resource("detection://environment/hosts")
def list_environment_hosts() -> str:
    """List known hosts and their roles in the monitored environment.

    Stub: no host inventory data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No host inventory data source exists yet in this repo.",
        "hosts": [],
    }, indent=2)


@mcp.resource("detection://environment/services")
def list_environment_services() -> str:
    """List critical services running in the monitored environment.

    Stub: no service inventory data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No service inventory data source exists yet in this repo.",
        "services": [],
    }, indent=2)


@mcp.resource("detection://environment/baselines")
def list_environment_baselines() -> str:
    """List normal-behavior baselines for the monitored environment.

    Stub: no baseline data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No baseline data source exists yet in this repo.",
        "baselines": [],
    }, indent=2)


@mcp.resource("detection://investigations")
def list_investigations() -> str:
    """List past investigation cases.

    Stub: no investigation-case data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No investigation-case data source exists yet in this repo.",
        "cases": [],
    }, indent=2)


@mcp.resource("detection://investigations/{case_id}")
def get_investigation(case_id: str) -> str:
    """Return details for a specific past investigation case, by case ID.

    Stub: no investigation-case data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "case_id": case_id,
        "note": "No investigation-case data source exists yet in this repo.",
    }, indent=2)


@mcp.resource("detection://investigations/by-technique/{technique_id}")
def list_investigations_by_technique(technique_id: str) -> str:
    """List past investigation cases involving a given ATT&CK technique ID.

    Stub: no investigation-case data source exists yet in this repo.
    """
    return json.dumps({
        "status": "not_implemented",
        "technique_id": technique_id,
        "note": "No investigation-case data source exists yet in this repo.",
        "cases": [],
    }, indent=2)


@mcp.resource("docs://list")
def list_docs() -> str:
    """List available documentation.

    Stub: no docs/ directory exists yet in this repo -- see CLAUDE.md for current
    project documentation instead.
    """
    return json.dumps({
        "status": "not_implemented",
        "note": "No docs/ directory exists yet in this repo; see CLAUDE.md.",
        "docs": [],
    }, indent=2)


@mcp.tool()
def analyze_coverage(identifier: str) -> dict:
    """Analyze detection coverage for an ATT&CK technique ID (e.g. "T1003.001") or a
    tactic name (e.g. "credential-access", "Lateral Movement").

    Looks up the matching technique(s) against the live MITRE ATT&CK data (the same
    source detection://attack/techniques/{id} uses) and cross-checks each against Sigma
    rules tagged in rules/, via the same covered/partial/gap logic that resource uses.
    This is the tool-shaped counterpart to that resource: one call that accepts either a
    single technique ID or a whole tactic and always returns a report (including a gap
    list), rather than requiring the caller to already know individual technique IDs.
    """
    identifier = identifier.strip()
    if not identifier:
        return {"success": False, "error": "identifier must be a non-empty ATT&CK technique ID or tactic name"}

    try:
        technique_index = _load_attack_technique_index()
    except OSError as e:
        return {"success": False, "error": f"Failed to fetch ATT&CK data: {e}"}

    tactic = None
    if _is_technique_id(identifier):
        technique_id = identifier.upper()
        result = _assess_technique_coverage(technique_id, technique_index)
        if result is None:
            return {"success": False, "error": f"Unknown ATT&CK technique '{technique_id}'"}
        techniques = [result]
    else:
        tactic = _normalize_tactic_name(identifier)
        matches = _techniques_for_tactic(tactic, technique_index)
        if not matches:
            return {
                "success": False,
                "error": f"No ATT&CK techniques found for tactic '{identifier}' (normalized: '{tactic}')",
            }
        techniques = [_assess_technique_coverage(tid, technique_index) for tid, _ in sorted(matches)]

    covered = [t for t in techniques if t["coverage"] == "covered"]
    partial = [t for t in techniques if t["coverage"] == "partial"]
    gap = [t for t in techniques if t["coverage"] == "gap"]

    return {
        "success": True,
        "query": identifier,
        "tactic": tactic,
        "technique_count": len(techniques),
        "covered_count": len(covered),
        "partial_count": len(partial),
        "gap_count": len(gap),
        "gap_technique_ids": [t["technique_id"] for t in gap],
        "techniques": techniques,
    }


def _render_rule_template(technique_id: str, technique: dict) -> str:
    """A placeholder Sigma rule for a coverage gap, matching this repo's existing rule
    style (see rules/kerberoasting.yml) -- deliberately incomplete (empty selection,
    status: experimental) since it's a starting point for a human to fill in, not a
    working rule."""
    tactic = _technique_tactic(technique)
    tags = [f"attack.{tactic}"] if tactic else []
    tags.append(f"attack.{technique_id.lower()}")
    tags_block = "\n".join(f"    - {t}" for t in tags)
    technique_path = technique_id.replace(".", "/")

    return f"""title: {technique.get("name") or technique_id} (suggested template)
id: {uuid.uuid4()}
status: experimental
description: |
    TODO: fill in a real detection. Generated by suggest_rule as a starting point for
    covering {technique_id} ({technique.get("name")}), which had no tagged rule yet.
references:
    - https://attack.mitre.org/techniques/{technique_path}/
author: Detection Engineering KB (generated template)
date: {date.today().isoformat()}
tags:
{tags_block}
logsource:
    product: windows
    # TODO: set service/category (e.g. security, sysmon)
detection:
    selection:
        # TODO: fill in real selection fields
    condition: selection
falsepositives:
    - Unknown -- rule not yet validated
level: medium
"""


@mcp.tool()
def suggest_rule(technique_id: str, create_template: bool = False) -> dict:
    """Check detection coverage for one ATT&CK technique ID and, if it's a gap, suggest
    a detection approach (ATT&CK's own data sources/platforms for that technique).

    If create_template is True and the technique is a gap, writes a placeholder Sigma
    rule YAML into rules/ (named after the technique, tagged attack.<technique_id>,
    status: experimental) as a starting point -- it will not overwrite an existing file,
    and does nothing if the technique already has coverage.
    """
    technique_id = technique_id.strip().upper()
    if not _is_technique_id(technique_id):
        return {
            "success": False,
            "error": f"'{technique_id}' doesn't look like an ATT&CK technique ID (expected e.g. 'T1003' or 'T1003.001')",
        }

    try:
        technique_index = _load_attack_technique_index()
    except OSError as e:
        return {"success": False, "error": f"Failed to fetch ATT&CK data: {e}"}

    result = _assess_technique_coverage(technique_id, technique_index)
    if result is None:
        return {"success": False, "error": f"Unknown ATT&CK technique '{technique_id}'"}

    if result["coverage"] == "covered":
        return {
            "success": True,
            "technique_id": technique_id,
            "coverage": "covered",
            "message": "Already covered -- no suggestion needed.",
            "detecting_rules": result["detecting_rules"],
            "template_created": False,
        }

    technique = technique_index[technique_id]
    data_sources = technique.get("x_mitre_data_sources", [])
    platforms = technique.get("x_mitre_platforms", [])

    response = {
        "success": True,
        "technique_id": technique_id,
        "coverage": result["coverage"],
        "related_coverage": result["related_coverage"],
        "suggestion": (
            f"No rule tags {technique_id} ({technique.get('name')}) directly. "
            f"Data source(s) ATT&CK associates with this technique: "
            f"{', '.join(data_sources) if data_sources else 'none listed'}. "
            f"Platform(s): {', '.join(platforms) if platforms else 'unspecified'}. "
            f"Consider a Sigma rule against those log source(s), tagged attack.{technique_id.lower()}."
        ),
        "data_sources": data_sources,
        "platforms": platforms,
        "template_created": False,
    }

    if create_template:
        rule_name = _slugify(technique.get("name") or technique_id)
        path = _resolve_rule_path(rule_name)
        if path is None:
            response["template_error"] = "Could not resolve a safe rule file path for this technique."
        elif path.exists():
            response["template_error"] = f"rules/{rule_name}.yml already exists -- not overwriting."
        else:
            path.write_text(_render_rule_template(technique_id, technique), encoding="utf-8")
            response["template_created"] = True
            response["rule_name"] = rule_name
            response["rule_path"] = str(path.relative_to(Path(__file__).parent))

    return response


@mcp.tool()
def assess_coverage() -> dict:
    """Cross-check mappings/technique_coverage.yml's tracked ATT&CK techniques against
    the Sigma rules actually tagged for them in rules/, and report per-technique
    coverage plus an overall summary.

    This is the aggregate, local-data counterpart to the detection://attack/techniques/{id}
    resource (which looks up one technique at a time against live MITRE data): it answers
    "what's our overall coverage look like" and "where are our gaps" using only this
    knowledge base's own rules + mappings, and flags drift if a technique's tracked
    `rules:` list in the mapping file no longer matches what's actually tagged in rules/.
    """
    mappings = _load_technique_mappings()
    if not mappings:
        return {"success": False, "error": f"No technique mappings found in {MAPPINGS_DIR}"}

    techniques = []
    for entry in mappings:
        technique_id = entry["technique_id"]
        expected_rules = set(entry.get("rules", []))
        actual_rules = {r["rule_name"] for r in _rules_for_technique_tag(f"attack.{technique_id.lower()}")}

        techniques.append({
            "technique_id": technique_id,
            "name": entry.get("name"),
            "tactic": entry.get("tactic"),
            "coverage": "covered" if actual_rules else "gap",
            "expected_rules": sorted(expected_rules),
            "actual_rules": sorted(actual_rules),
            "in_sync": expected_rules == actual_rules,
        })

    covered_count = sum(1 for t in techniques if t["coverage"] == "covered")
    out_of_sync = [t["technique_id"] for t in techniques if not t["in_sync"]]

    return {
        "success": True,
        "technique_count": len(techniques),
        "covered_count": covered_count,
        "gap_count": len(techniques) - covered_count,
        "out_of_sync_techniques": out_of_sync,
        "techniques": techniques,
    }


if __name__ == "__main__":
    mcp.run()
