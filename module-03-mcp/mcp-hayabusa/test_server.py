#!/usr/bin/env python3
"""Manual smoke test: call scan_evtx directly against a real sample EVTX file."""

import sys
from pathlib import Path

import server

SAMPLE = Path(__file__).parent / "samples" / "UACME_59_Sysmon.evtx"


def main():
    if not SAMPLE.exists():
        print(f"Sample file not found: {SAMPLE}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {SAMPLE} ...")
    result = server.scan_evtx(str(SAMPLE))

    if not result["success"]:
        print(f"scan_evtx failed: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"success: {result['success']}")
    print(f"event_count: {result['event_count']}")
    if result["events"]:
        print("first event keys:", sorted(result["events"][0].keys()))

    print("\n--- with min_severity='high' ---")
    result_high = server.scan_evtx(str(SAMPLE), min_severity="high")
    if not result_high["success"]:
        print(f"scan_evtx (high) failed: {result_high['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"event_count (high+): {result_high['event_count']}")

    print("\n--- error handling: nonexistent file ---")
    result_missing = server.scan_evtx(str(SAMPLE.parent / "does_not_exist.evtx"))
    print(result_missing)
    assert result_missing["success"] is False

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
