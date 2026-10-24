"""Build synthetic .lnk files for testing, following [MS-SHLLINK].

Synthetic samples mean the repo never needs evidence from a real machine.
Run directly to regenerate the sample in samples/:
    python -m tests.build_lnk samples/
"""

import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from winartifacts import lnk

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(dt):
    delta = dt - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10**7 + delta.microseconds * 10


def _string(text, unicode):
    encoded = text.encode("utf-16-le" if unicode else "cp1252")
    return struct.pack("<H", len(text)) + encoded


def build_lnk(
    local_path="C:\\Users\\student\\Documents\\case_notes.docx",
    created=datetime(2026, 9, 1, 14, 2, 11, tzinfo=timezone.utc),
    modified=datetime(2026, 9, 3, 9, 45, 0, tzinfo=timezone.utc),
    accessed=datetime(2026, 9, 5, 18, 30, 27, tzinfo=timezone.utc),
    size=24576,
    serial=0x1A2B3C4D,
    label="OS",
    drive_type=3,
    machine_id="desktop-lab01",
    working_dir="C:\\Users\\student\\Documents",
    arguments=None,
    unicode=True,
):
    flags = lnk.HAS_LINK_INFO
    if unicode:
        flags |= lnk.IS_UNICODE
    if working_dir:
        flags |= lnk.HAS_WORKING_DIR
    if arguments:
        flags |= lnk.HAS_ARGUMENTS

    header = struct.pack(
        "<I16sIIQQQIiIHHII",
        lnk.HEADER_SIZE, lnk.LNK_CLSID.bytes_le, flags, 0x20,  # 0x20 = ARCHIVE
        to_filetime(created), to_filetime(accessed), to_filetime(modified),
        size, 0, 1, 0, 0, 0, 0,
    )

    label_bytes = label.encode("cp1252") + b"\x00"
    volume_id = struct.pack("<IIII", 16 + len(label_bytes), drive_type, serial, 0x10) + label_bytes
    base_path = local_path.encode("cp1252") + b"\x00"
    volume_offset = 0x1C
    base_offset = volume_offset + len(volume_id)
    suffix_offset = base_offset + len(base_path)
    body = volume_id + base_path + b"\x00"
    link_info = struct.pack(
        "<IIIIIII", 0x1C + len(body), 0x1C, lnk.VOLUME_ID_AND_LOCAL_BASE_PATH,
        volume_offset, base_offset, 0, suffix_offset,
    ) + body

    strings = b""
    if working_dir:
        strings += _string(working_dir, unicode)
    if arguments:
        strings += _string(arguments, unicode)

    tracker = b""
    if machine_id:
        tracker = (struct.pack("<IIII", 0x60, lnk.TRACKER_DATA_SIGNATURE, 0x58, 0)
                   + machine_id.encode("ascii").ljust(16, b"\x00") + b"\x00" * 64)

    return header + link_info + strings + tracker + b"\x00\x00\x00\x00"


if __name__ == "__main__":
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "case_notes.docx.lnk").write_bytes(build_lnk())
    (out_dir / "payload_tool.exe.lnk").write_bytes(build_lnk(
        local_path="E:\\tools\\payload_tool.exe",
        created=datetime(2026, 9, 4, 22, 10, 5, tzinfo=timezone.utc),
        modified=datetime(2026, 9, 4, 22, 10, 5, tzinfo=timezone.utc),
        accessed=datetime(2026, 9, 4, 22, 11, 40, tzinfo=timezone.utc),
        size=1183744, serial=0x5E77A001, label="KINGSTON", drive_type=2,
        working_dir="E:\\tools", arguments="--silent", unicode=False,
    ))
    print(f"Wrote samples to {out_dir}/")
