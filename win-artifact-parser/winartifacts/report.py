"""Output helpers shared by every artifact parser."""

import csv
import json
import sys

TIMELINE_FIELDS = ["timestamp", "artifact", "event", "description", "source_file"]


def write_csv(rows, fields, out=None):
    handle = open(out, "w", newline="", encoding="utf-8") if out else sys.stdout
    try:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if out:
            handle.close()


def write_json(rows, out=None):
    text = json.dumps(rows, indent=2, ensure_ascii=False)
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)


def print_details(parsed):
    """Readable console view of one parsed artifact, skipping empty fields."""
    width = max(len(key) for key in parsed)
    for key, value in parsed.items():
        if value not in (None, ""):
            print(f"  {key:<{width}}  {value}")
    print()
