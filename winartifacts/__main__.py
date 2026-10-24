"""Command-line interface.

    python -m winartifacts lnk <file-or-folder>
    python -m winartifacts prefetch <file-or-folder>
"""

import argparse
import sys
from pathlib import Path

from . import lnk, prefetch, report

# name -> (file pattern, parse function, flat summary, timeline records, error type)
PARSERS = {
    "lnk": ("*.lnk", lnk.parse_lnk, lambda p: p, lnk.to_timeline_records, lnk.LnkParseError),
    "prefetch": ("*.pf", prefetch.parse_prefetch, prefetch.summary,
                 prefetch.to_timeline_records, prefetch.PrefetchParseError),
}


def find_files(path, pattern):
    path = Path(path)
    if path.is_dir():
        return sorted(p for p in path.rglob(pattern) if p.is_file())
    return [path]


def run(args):
    pattern, parse, summarize, to_records, error = PARSERS[args.artifact]
    parsed_all, records = [], []
    for path in find_files(args.path, pattern):
        try:
            parsed = parse(path)
        except (error, OSError) as exc:
            print(f"[!] skipped {exc}", file=sys.stderr)
            continue
        parsed_all.append(parsed)
        records.extend(to_records(parsed))

    if not parsed_all:
        print(f"No {pattern} files parsed.", file=sys.stderr)
        return 1

    if args.timeline:
        records.sort(key=lambda r: r["timestamp"])
        rows, full = records, records
    else:
        rows, full = [summarize(p) for p in parsed_all], parsed_all

    if args.format == "csv":
        fields = report.TIMELINE_FIELDS if args.timeline else list(rows[0].keys())
        report.write_csv(rows, fields, args.output)
    elif args.format == "json":
        report.write_json(full, args.output)  # JSON keeps nested detail
    else:
        for row in rows:
            report.print_details(row)
    print(f"[+] parsed {len(parsed_all)} {args.artifact} file(s)", file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="winartifacts",
        description="Parse Windows forensic artifacts into reports and timelines.",
    )
    sub = parser.add_subparsers(dest="artifact", required=True)
    helps = {
        "lnk": "parse Windows shortcut (.lnk) files",
        "prefetch": "parse Prefetch (.pf) files",
    }
    for name, help_text in helps.items():
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("path", help="a file or a folder to search recursively")
        cmd.add_argument("-f", "--format", choices=["text", "csv", "json"], default="text")
        cmd.add_argument("-o", "--output", help="write to this file instead of the console")
        cmd.add_argument("-t", "--timeline", action="store_true",
                         help="output one sorted record per timestamp")

    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
