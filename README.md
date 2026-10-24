# Windows Artifact Parser

A Python command-line tool that parses Windows forensic artifacts into readable
reports and a unified, sortable timeline. Written from Microsoft's published file
format specifications with **no third-party dependencies**.

| Artifact | Status | What it shows an investigator |
|---|---|---|
| LNK (shortcut) files | ✅ v0.1 | Files a user opened, where they lived, which drive, which machine |
| Prefetch | ✅ v0.2 | Programs that ran, how often, when, and from which volume |
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

# Prefetch: same options
python -m winartifacts prefetch C:\Windows\Prefetch --timeline -f csv -o prefetch.csv
```

Reading `C:\Windows\Prefetch` on a live system needs an administrator
terminal. For casework, run it against a copy exported from a disk image.

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

## Why Prefetch matters

Windows records program execution in `C:\Windows\Prefetch` to speed up
launches. Each `.pf` file is named after the executable plus a hash of its
path, and stores the run count, the last run time (up to eight on Windows 8
and later), every file the program loaded in its first seconds, and the
volumes involved. It is one of the strongest pieces of evidence that a
program actually ran, not just that it existed on disk.

Example:

```
  executable         PAYLOAD_TOOL.EXE
  executable_path    \VOLUME{01dc1e2a5e77a001-5e77a001}\TOOLS\PAYLOAD_TOOL.EXE
  run_count          3
  last_run           2026-09-04T22:11:40+00:00
  previous_runs      2026-09-04T22:10:06+00:00; 2026-09-03T16:58:12+00:00
  volumes            \VOLUME{01dc1e2a5e77a001-5e77a001} (5E77-A001)
```

Reading the two artifacts together: the volume serial `5E77-A001` matches the
`KINGSTON` USB drive from the LNK sample, and the last run at `22:11:40`
matches the shortcut's access time to the second. One artifact shows the file
was opened, the other confirms the program ran, three times.

## How it works

### LNK

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

### Prefetch

Format versions 17 (XP), 23 (Vista/7), 26 (8/8.1) and 30 (10/11) are
supported. The parser checks the `SCCA` signature, then reads the
version-specific file information section for the run times and run count,
the filename strings section for loaded files, and the volume information
section for device paths, serial numbers and creation times.

Windows 10 and 11 compress Prefetch files with Xpress Huffman (a `MAM`
header). The tool decompresses them through `RtlDecompressBufferEx` in
Windows' `ntdll`, so **compressed files must be parsed on Windows 8 or
later**. Uncompressed files parse on any OS. Version 30 also has two layouts,
told apart by the metrics offset (`0x130` or `0x128`), which moves the run
count between `0xD0` and `0xC8`.

### Shared output

Every parser emits the same timeline record shape
(`timestamp, artifact, event, description, source_file`) so outputs can be
merged into one timeline.

## Testing

```bash
python -m unittest -v
```

Tests run against **synthetic files** built byte by byte in
`tests/build_lnk.py` and `tests/build_pf.py`, so the repo contains no evidence
from a real machine. Regenerate the samples with
`python -m tests.build_lnk samples/` and `python -m tests.build_pf samples/`.

## Validation

Results should be cross-checked against Eric Zimmerman's
[LECmd and PECmd](https://ericzimmerman.github.io/), widely used reference tools.
<!-- TODO: add a table comparing this tool's output with LECmd on the same files -->

## Roadmap

- [ ] Parse the LinkTargetIDList shell items
- [ ] Decode file attribute flags into names
- [ ] Extract the Droid volume and file IDs from the TrackerDataBlock
- [x] Prefetch parser
- [ ] Pure-Python Xpress Huffman decompression, so Windows 10/11 Prefetch parses on any OS
- [ ] Registry parser (UserAssist, RecentDocs)
- [ ] HTML timeline report

## Disclaimer

Built for education and authorized forensic analysis. Only analyze systems and
evidence you have permission to examine.
