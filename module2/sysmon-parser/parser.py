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
    args = parser.parse_args()

    records = parse_file(args.input)
    if not records:
        print("No Event ID 1 records found.", file=sys.stderr)
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
