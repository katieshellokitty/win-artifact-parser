# Windows Artifact Parser

A Python command-line tool that parses Windows forensic artifacts into readable
reports and a unified, sortable timeline. Written from Microsoft's published file
format specifications with **no third-party dependencies**.

| Artifact | Status | What it shows an investigator |
|---|---|---|
| LNK (shortcut) files | ✅ v0.1 | Files a user opened, where they lived, which drive, which machine |
| Prefetch | ✅ v0.2 | Programs that ran, how often, when, and from which volume |
| Registry (UserAssist, RecentDocs) | ✅ v0.3 | Programs launched through Explorer, and files and folders recently opened |

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

```bash
# Registry: UserAssist and RecentDocs from an NTUSER.DAT hive
python -m winartifacts registry NTUSER.DAT --timeline
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

## Why UserAssist and RecentDocs matter

Both live in each user's `NTUSER.DAT` hive, so they tie activity to a
specific account rather than to the machine.

- **UserAssist** records programs and shortcuts launched through Explorer
  (Start menu, desktop, taskbar): run count, how many times the window had
  focus, total focus time, and the last run time. Value names are
  ROT13-encoded, a light obfuscation Windows has used since XP.
- **RecentDocs** lists files and folders the user opened, overall and per
  extension, in most-recent-first order. Only the most recent entry in each
  list has a reliable time: the key's last-written timestamp.

Together with the other samples, the timeline reads:

```
22:09:31  RecentDocs  tools folder opened (on the USB drive)
22:09:52  UserAssist  cmd.exe launched (run count 12)
22:11:40  UserAssist  E:\tools\payload_tool.exe launched (run count 3, 95 s in focus)
22:11:40  Prefetch    PAYLOAD_TOOL.EXE executed
22:11:40  LNK         payload_tool.exe shortcut target accessed
```

Three independent artifacts agree on the same second, which is much harder
to dismiss than any one of them alone.

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

Format versions 17 (XP), 23 (Vista/7), 26 (8/8.1), 30 (10/11) and 31
(Windows 11 24H2 and later) are supported. Version 31 support was added
after validating against a real Windows 11 machine. The parser checks the `SCCA` signature, then reads the
version-specific file information section for the run times and run count,
the filename strings section for loaded files, and the volume information
section for device paths, serial numbers and creation times.

Windows 10 and 11 compress Prefetch files with Xpress Huffman (a `MAM`
header). The tool decompresses them through `RtlDecompressBufferEx` in
Windows' `ntdll`, so **compressed files must be parsed on Windows 8 or
later**. Uncompressed files parse on any OS. Version 30 also has two layouts,
told apart by the metrics offset (`0x130` or `0x128`), which moves the run
count between `0xD0` and `0xC8`.

### Registry

The hive reader walks the `regf` format directly. It reads the 4 KB base
block for the root key, then follows cells inside the hive bins: `nk` cells
for keys, `vk` cells for values, `lf`/`lh`/`li`/`ri` cells for subkey lists,
and `db` big-data cells for values over 16,344 bytes. Values of 4 bytes or
less are stored inside the value cell itself. Key lookups are
case-insensitive, like Windows.

UserAssist data is 72 bytes on Windows 7 and later (run count at offset 4,
focus count at 8, focus time in milliseconds at 12, last run FILETIME at 60)
and 16 bytes on XP. Known folder GUIDs such as
`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}` are resolved to paths like
`C:\Windows\System32`.

A hive whose two sequence numbers differ is **dirty**: its latest changes may
still be in the `.LOG1`/`.LOG2` transaction logs. The tool warns about this
but does not replay the logs yet.

### Shared output

Every parser emits the same timeline record shape
(`timestamp, artifact, event, description, source_file`) so outputs can be
merged into one timeline.

## Testing

```bash
python -m unittest -v
```

Tests run against **synthetic files** built byte by byte in
`tests/build_lnk.py`, `tests/build_pf.py` and `tests/build_hive.py` (a small
regf writer), so the repo contains no evidence from a real machine. Regenerate
the samples with `python -m tests.build_lnk samples/`,
`python -m tests.build_pf samples/` and `python -m tests.build_hive samples/`.

## Validation

Results should be cross-checked against Eric Zimmerman's
[LECmd and PECmd](https://ericzimmerman.github.io/), widely used reference tools.

Validated on a Windows 11 24H2 machine (Prefetch version 31) against PECmd 2026.10.2:

| File | Field | PECmd | winartifacts |
|---|---|---|---|
| NOTEPAD.EXE-0D1583A9.pf | Run count | 18 | 18 |
| | Last run (UTC) | 2026-10-07 01:59:01 | 2026-10-07T01:59:01.435054 |
| | Earlier run times | 7 | 7, identical |

Version 31 support was added after this check first failed on real data.
winartifacts keeps sub-second precision, which shows the two most recent
runs were 41 ms apart.

To validate the Registry parser on a live system, export your own hive with
`reg save HKCU hkcu.hiv`, run `python -m winartifacts registry hkcu.hiv`, and
compare with Registry Explorer or RECmd.

## Roadmap

- [ ] Parse the LinkTargetIDList shell items
- [ ] Decode file attribute flags into names
- [ ] Extract the Droid volume and file IDs from the TrackerDataBlock
- [x] Prefetch parser
- [ ] Pure-Python Xpress Huffman decompression, so Windows 10/11 Prefetch parses on any OS
- [x] Registry parser (UserAssist, RecentDocs)
- [ ] Replay hive transaction logs (.LOG1/.LOG2) for dirty hives
- [ ] More Registry artifacts: ShellBags, RunMRU, TypedPaths, USB device history
- [ ] HTML timeline report

## Disclaimer

Built for education and authorized forensic analysis. Only analyze systems and
evidence you have permission to examine.
