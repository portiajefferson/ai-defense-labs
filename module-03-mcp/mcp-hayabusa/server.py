#!/usr/bin/env python3
"""MCP server wrapping the Hayabusa CLI for EVTX analysis."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

LOCAL_HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]

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


@mcp.tool()
def scan_evtx(evtx_path: str, min_severity: str | None = None) -> dict:
    """Run Hayabusa against an EVTX file and return structured results.

    Args:
        evtx_path: Path to the .evtx file (or a directory of .evtx files) to scan.
        min_severity: Optional minimum severity to include — one of
            informational, low, medium, high, critical.
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

    return {"success": True, "event_count": len(events), "events": events}


if __name__ == "__main__":
    mcp.run()
