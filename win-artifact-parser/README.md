# Windows Artifact Parser

A Python command-line tool that parses Windows forensic artifacts into readable
reports and a unified, sortable timeline. Written from Microsoft's published file
format specifications with **no third-party dependencies**.

| Artifact | Status | What it shows an investigator |
|---|---|---|
| LNK (shortcut) files | ✅ v0.1 | Files a user opened, where they lived, which drive, which machine |
| Prefetch | 🔜 planned | Programs that ran, how often, and when |
| Registry (UserAssist, RecentDocs) | 🔜 planned | Program execution and recently opened documents |

## Why LNK files matter

Windows creates a shortcut in `%APPDATA%\Microsoft\Windows\Recent` whenever a
user opens a file. Each one records the target's timestamps and size, its full
path, the volume serial number and drive type, and the NetBIOS name of the
machine where the link was made. That is often enough to prove a file was
opened, even after it was deleted, and to tie it to a specific USB device.

## Usage

Requires Python 3.9+.

```bash
# Readable details for one file or a whole folder (searched recursively)
python -m winartifacts lnk samples/

# Sorted timeline as CSV
python -m winartifacts lnk samples/ --timeline -f csv -o timeline.csv

# Full details as JSON
python -m winartifacts lnk samples/ -f json -o lnk_report.json
```

## Example output

```
  source_file      samples/payload_tool.exe.lnk
  target_created   2026-09-04T22:10:05+00:00
  target_accessed  2026-09-04T22:11:40+00:00
  target_modified  2026-09-04T22:10:05+00:00
  target_size      1183744
  local_path       E:\tools\payload_tool.exe
  drive_type       REMOVABLE
  drive_serial     5E77-A001
  volume_label     KINGSTON
  working_dir      E:\tools
  arguments        --silent
  machine_id       desktop-lab01
```

Timeline mode (`--timeline -f csv`):

```
timestamp,artifact,event,description,source_file
2026-09-01T14:02:11+00:00,LNK,Target file created,C:\Users\student\Documents\case_notes.docx,...
2026-09-04T22:10:05+00:00,LNK,Target file created,E:\tools\payload_tool.exe,...
2026-09-04T22:11:40+00:00,LNK,Target file accessed,E:\tools\payload_tool.exe,...
```

Reading this as an analyst: a program on a removable drive labeled `KINGSTON`
was opened with a `--silent` argument on `desktop-lab01`. The drive serial
`5E77-A001` can be matched against USB device history in the Registry.

## How it works

The parser follows [MS-SHLLINK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/):

1. **Header** (76 bytes): validates the size and CLSID, reads the link flags,
   the target's three FILETIME timestamps, and its size.
2. **LinkTargetIDList**: skipped for now using its length prefix.
3. **LinkInfo**: the volume ID (drive type, serial, label) and the local or
   network path, in ANSI or Unicode.
4. **StringData**: name, relative path, working directory, arguments, icon,
   in ANSI or UTF-16LE depending on the `IsUnicode` flag.
5. **ExtraData**: walks the block chain and reads the `TrackerDataBlock`
   (signature `0xA0000003`) for the machine ID.

Timestamps are converted from Windows FILETIME (100-nanosecond intervals since
1601-01-01 UTC) to ISO 8601 UTC. A zero FILETIME means "not set" and is
reported as empty rather than as 1601.

Every parser emits the same timeline record shape
(`timestamp, artifact, event, description, source_file`) so outputs can be
merged into one timeline.

## Testing

```bash
python -m unittest -v
```

Tests run against **synthetic LNK files** built byte by byte in
`tests/build_lnk.py`, so the repo contains no evidence from a real machine.
Regenerate the samples with `python -m tests.build_lnk samples/`.

## Validation

Results should be cross-checked against Eric Zimmerman's
[LECmd](https://ericzimmerman.github.io/), a widely used reference tool.
<!-- TODO: add a table comparing this tool's output with LECmd on the same files -->

## Roadmap

- [ ] Parse the LinkTargetIDList shell items
- [ ] Decode file attribute flags into names
- [ ] Extract the Droid volume and file IDs from the TrackerDataBlock
- [ ] Prefetch parser
- [ ] Registry parser (UserAssist, RecentDocs)
- [ ] HTML timeline report

## Disclaimer

Built for education and authorized forensic analysis. Only analyze systems and
evidence you have permission to examine.
