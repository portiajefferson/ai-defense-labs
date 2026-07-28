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
        print("first event keys (summary format):", sorted(result["events"][0].keys()))
        assert "Details" not in result["events"][0]

    print("\n--- with min_severity='high' ---")
    result_high = server.scan_evtx(str(SAMPLE), min_severity="high")
    if not result_high["success"]:
        print(f"scan_evtx (high) failed: {result_high['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"event_count (high+): {result_high['event_count']}")

    print("\n--- with output_format='full' ---")
    result_full = server.scan_evtx(str(SAMPLE), output_format="full")
    if not result_full["success"]:
        print(f"scan_evtx (full) failed: {result_full['error']}", file=sys.stderr)
        sys.exit(1)
    assert "Details" in result_full["events"][0]
    print("first event keys (full format):", sorted(result_full["events"][0].keys()))

    print("\n--- with max_results=2 ---")
    result_capped = server.scan_evtx(str(SAMPLE), max_results=2)
    assert result_capped["returned_count"] == 2
    assert result_capped["truncated"] is True
    assert result_capped["event_count"] == result["event_count"]
    print(f"event_count: {result_capped['event_count']}, returned_count: {result_capped['returned_count']}")

    print("\n--- with rule_filter='access' ---")
    result_filtered = server.scan_evtx(str(SAMPLE), rule_filter="access")
    if not result_filtered["success"]:
        print(f"scan_evtx (rule_filter) failed: {result_filtered['error']}", file=sys.stderr)
        sys.exit(1)
    assert all(e["RuleTitle"] == "Proc Access" for e in result_filtered["events"])
    print(f"event_count (rule_filter='access'): {result_filtered['event_count']}")

    print("\n--- with rule_filter matching nothing ---")
    result_no_match = server.scan_evtx(str(SAMPLE), rule_filter="doesnotexist_xyz")
    print(result_no_match)
    assert result_no_match["success"] is False

    print("\n--- error handling: nonexistent file ---")
    result_missing = server.scan_evtx(str(SAMPLE.parent / "does_not_exist.evtx"))
    print(result_missing)
    assert result_missing["success"] is False

    print("\n--- get_hayabusa_rules(keyword='mimikatz') ---")
    rules_result = server.get_hayabusa_rules(keyword="mimikatz")
    if not rules_result["success"]:
        print(f"get_hayabusa_rules failed: {rules_result['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"rule_count: {rules_result['rule_count']}")
    assert rules_result["rule_count"] > 0
    assert all("mimikatz" in r["title"].lower() or any("mimikatz" in t.lower() for t in r["tags"])
               or "mimikatz" in r["path"].lower() or (r["id"] and "mimikatz" in r["id"].lower())
               for r in rules_result["rules"])

    print("\n--- get_hayabusa_rules() with no keyword ---")
    all_rules_result = server.get_hayabusa_rules()
    assert all_rules_result["success"] is True
    print(f"rule_count: {all_rules_result['rule_count']}, returned_count: {all_rules_result['returned_count']}, "
          f"truncated: {all_rules_result['truncated']}")

    print("\n--- scan_chainsaw() default (all native rule categories) ---")
    chainsaw_result = server.scan_chainsaw(str(SAMPLE))
    if not chainsaw_result["success"]:
        print(f"scan_chainsaw failed: {chainsaw_result['error']}", file=sys.stderr)
        sys.exit(1)
    # This sample only contains Sysmon events; Chainsaw's native rules/evtx/ ruleset
    # mostly targets Security-log event IDs, so 0 hits here is expected (see CLAUDE.md).
    print(f"event_count: {chainsaw_result['event_count']}")

    print("\n--- scan_chainsaw(rule_type='credential_access') ---")
    chainsaw_typed = server.scan_chainsaw(str(SAMPLE), rule_type="credential_access")
    if not chainsaw_typed["success"]:
        print(f"scan_chainsaw (rule_type) failed: {chainsaw_typed['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"event_count: {chainsaw_typed['event_count']}")

    print("\n--- scan_chainsaw() with invalid rule_type ---")
    chainsaw_bad_type = server.scan_chainsaw(str(SAMPLE), rule_type="bogus_category")
    print(chainsaw_bad_type)
    assert chainsaw_bad_type["success"] is False
    assert "credential_access" in chainsaw_bad_type["error"]

    print("\n--- scan_chainsaw() error handling: nonexistent file ---")
    chainsaw_missing = server.scan_chainsaw(str(SAMPLE.parent / "does_not_exist.evtx"))
    print(chainsaw_missing)
    assert chainsaw_missing["success"] is False

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
