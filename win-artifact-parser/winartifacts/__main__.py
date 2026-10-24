"""Command-line interface: python -m winartifacts lnk <file-or-folder>"""

import argparse
import sys
from pathlib import Path

from . import lnk, report


def find_files(path, pattern):
    path = Path(path)
    if path.is_dir():
        return sorted(p for p in path.rglob(pattern) if p.is_file())
    return [path]


def run_lnk(args):
    parsed_all, records = [], []
    for path in find_files(args.path, "*.lnk"):
        try:
            parsed = lnk.parse_lnk(path)
        except (lnk.LnkParseError, OSError) as exc:
            print(f"[!] skipped {exc}", file=sys.stderr)
            continue
        parsed_all.append(parsed)
        records.extend(lnk.to_timeline_records(parsed))

    if not parsed_all:
        print("No .lnk files parsed.", file=sys.stderr)
        return 1

    if args.timeline:
        records.sort(key=lambda r: r["timestamp"])
        rows, fields = records, report.TIMELINE_FIELDS
    else:
        rows, fields = parsed_all, list(parsed_all[0].keys())

    if args.format == "csv":
        report.write_csv(rows, fields, args.output)
    elif args.format == "json":
        report.write_json(rows, args.output)
    else:
        for row in rows:
            report.print_details(row)
    print(f"[+] parsed {len(parsed_all)} LNK file(s)", file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="winartifacts",
        description="Parse Windows forensic artifacts into reports and timelines.",
    )
    sub = parser.add_subparsers(dest="artifact", required=True)

    lnk_cmd = sub.add_parser("lnk", help="parse Windows shortcut (.lnk) files")
    lnk_cmd.add_argument("path", help="a .lnk file or a folder to search recursively")
    lnk_cmd.add_argument("-f", "--format", choices=["text", "csv", "json"], default="text")
    lnk_cmd.add_argument("-o", "--output", help="write to this file instead of the console")
    lnk_cmd.add_argument("-t", "--timeline", action="store_true",
                         help="output one sorted record per timestamp")
    lnk_cmd.set_defaults(func=run_lnk)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
