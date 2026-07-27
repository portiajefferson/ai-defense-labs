#!/usr/bin/env python3
"""Parse Sysmon Event ID 1 (Process Creation) XML into JSON."""

import argparse
import json
import sys
import xml.etree.ElementTree as ET

NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event(event_elem):
    system = event_elem.find("ns:System", NS)
    event_id = system.findtext("ns:EventID", namespaces=NS)
    computer = system.findtext("ns:Computer", namespaces=NS)

    data = {
        d.get("Name"): (d.text or "")
        for d in event_elem.findall("ns:EventData/ns:Data", NS)
    }

    return {
        "EventID": int(event_id) if event_id is not None else None,
        "UtcTime": data.get("UtcTime"),
        "Image": data.get("Image"),
        "CommandLine": data.get("CommandLine"),
        "User": data.get("User"),
        "IntegrityLevel": data.get("IntegrityLevel"),
        "ParentImage": data.get("ParentImage"),
        "ParentCommandLine": data.get("ParentCommandLine"),
        "Computer": computer,
        "Hashes": data.get("Hashes"),
    }


def matches_filters(record, image, user, command_line, integrity_level):
    if image and image.lower() not in (record["Image"] or "").lower():
        return False
    if user and user.lower() != (record["User"] or "").lower():
        return False
    if command_line and command_line.lower() not in (record["CommandLine"] or "").lower():
        return False
    if integrity_level and integrity_level != record["IntegrityLevel"]:
        return False
    return True


def parse_file(path):
    root = ET.parse(path).getroot()
    events = root.findall("ns:Event", NS) if root.tag.endswith("Events") else [root]

    records = []
    for event in events:
        event_id = event.findtext("ns:System/ns:EventID", namespaces=NS)
        if event_id == "1":
            records.append(parse_event(event))
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Extract key fields from Sysmon Event ID 1 (Process Creation) XML into JSON."
    )
    parser.add_argument("input", help="Path to a Sysmon XML file (single <Event> or <Events> batch)")
    parser.add_argument("-o", "--output", help="Write JSON to this file instead of stdout")
    parser.add_argument("--image", help="Only include events whose Image contains this substring (case-insensitive)")
    parser.add_argument("--user", help="Only include events with this exact User (case-insensitive)")
    parser.add_argument(
        "--command-line",
        help="Only include events whose CommandLine contains this substring (case-insensitive)",
    )
    parser.add_argument(
        "--integrity-level",
        type=str.title,
        choices=["Low", "Medium", "High", "System"],
        help="Only include events with this exact IntegrityLevel",
    )
    args = parser.parse_args()

    records = parse_file(args.input)
    records = [
        r for r in records
        if matches_filters(r, args.image, args.user, args.command_line, args.integrity_level)
    ]
    if not records:
        print("No matching records found.", file=sys.stderr)
        sys.exit(1)

    result = records[0] if len(records) == 1 else records
    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
