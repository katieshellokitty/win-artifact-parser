"""Build synthetic, uncompressed Prefetch files for testing.

Layout follows the version 17/23/26/30 structures documented on
forensics.wiki and in libscca. Regenerate the samples with:
    python -m tests.build_pf samples/
"""

import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from winartifacts import prefetch
from tests.build_lnk import to_filetime

SECTION_START = {17: 0x98, 23: 0xF0, 26: 0x130, 30: 0x130, 31: 0x128}


def build_pf(
    version=30,
    executable="PAYLOAD_TOOL.EXE",
    prefetch_hash=0x7D3A91C2,
    run_count=3,
    run_times=(
        datetime(2026, 9, 4, 22, 11, 40, tzinfo=timezone.utc),
        datetime(2026, 9, 4, 22, 10, 6, tzinfo=timezone.utc),
        datetime(2026, 9, 3, 16, 58, 12, tzinfo=timezone.utc),
    ),
    volume_path="\\VOLUME{01dc1e2a5e77a001-5e77a001}",
    volume_created=datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc),
    volume_serial=0x5E77A001,
    loaded_files=None,
    short_variant=False,
):
    if loaded_files is None:
        loaded_files = [
            "\\VOLUME{01d9a3c4f1b2c3d4-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
            "\\VOLUME{01d9a3c4f1b2c3d4-1a2b3c4d}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
            f"{volume_path}\\TOOLS\\{executable}",
            f"{volume_path}\\TOOLS\\CONFIG.INI",
        ]

    # Section C: null-terminated UTF-16LE filenames
    names = b"".join(f.encode("utf-16-le") + b"\x00\x00" for f in loaded_files)

    # Section D: one volume entry followed by its device path
    entry_size = prefetch.VOLUME_ENTRY_SIZE[version]
    path_bytes = volume_path.encode("utf-16-le") + b"\x00\x00"
    entry = struct.pack("<IIQI", entry_size, len(volume_path),
                        to_filetime(volume_created), volume_serial)
    volumes = entry.ljust(entry_size, b"\x00") + path_bytes

    names_offset = SECTION_START[version]
    volumes_offset = names_offset + len(names)
    total = volumes_offset + len(volumes)

    info = bytearray(SECTION_START[version])
    struct.pack_into("<I4sII", info, 0, version, b"SCCA", 0x11, total)
    exe = executable.encode("utf-16-le")[:58]
    info[0x10:0x10 + len(exe)] = exe
    struct.pack_into("<I", info, 0x4C, prefetch_hash)

    # Section A offset doubles as the version 30 layout marker
    short_variant = short_variant or version == 31
    metrics_offset = 0x128 if short_variant else SECTION_START[version]
    struct.pack_into("<IIIIIIIII", info, 0x54,
                     metrics_offset, 0, 0, 0,
                     names_offset, len(names),
                     volumes_offset, 1, len(volumes))

    slots = prefetch.LAST_RUN_SLOTS[version]
    for slot, stamp in enumerate(list(run_times)[:slots]):
        struct.pack_into("<Q", info, prefetch.LAST_RUN_OFFSET[version] + slot * 8,
                         to_filetime(stamp))
    count_offset = (0xC8 if short_variant else 0xD0) if version in (30, 31) \
        else prefetch.RUN_COUNT_OFFSET[version]
    struct.pack_into("<I", info, count_offset, run_count)

    return bytes(info) + names + volumes


if __name__ == "__main__":
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "PAYLOAD_TOOL.EXE-7D3A91C2.pf").write_bytes(build_pf())
    (out_dir / "WINWORD.EXE-4C8E2B10.pf").write_bytes(build_pf(
        executable="WINWORD.EXE", prefetch_hash=0x4C8E2B10, run_count=41,
        run_times=(
            datetime(2026, 9, 5, 18, 30, 20, tzinfo=timezone.utc),
            datetime(2026, 9, 3, 9, 40, 2, tzinfo=timezone.utc),
            datetime(2026, 9, 1, 14, 1, 55, tzinfo=timezone.utc),
        ),
        volume_path="\\VOLUME{01d9a3c4f1b2c3d4-1a2b3c4d}",
        volume_created=datetime(2025, 3, 14, 10, 22, 0, tzinfo=timezone.utc),
        volume_serial=0x1A2B3C4D,
        loaded_files=[
            "\\VOLUME{01d9a3c4f1b2c3d4-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
            "\\VOLUME{01d9a3c4f1b2c3d4-1a2b3c4d}\\PROGRAM FILES\\MICROSOFT OFFICE"
            "\\ROOT\\OFFICE16\\WINWORD.EXE",
            "\\VOLUME{01d9a3c4f1b2c3d4-1a2b3c4d}\\USERS\\STUDENT\\DOCUMENTS\\CASE_NOTES.DOCX",
        ],
    ))
    print(f"Wrote samples to {out_dir}/")
