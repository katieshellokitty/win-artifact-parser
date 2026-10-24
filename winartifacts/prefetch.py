"""Parser for Windows Prefetch (.pf) files.

Windows writes a Prefetch file the first time a program runs and updates it
on later runs, recording the run count, the last run times (one on XP and
Windows 7, up to eight on Windows 8 and later), the files the program loaded
in its first seconds, and the volumes they lived on.

Supported format versions:
    17  Windows XP / Server 2003
    23  Windows Vista / 7
    26  Windows 8 / 8.1
    30  Windows 10 / 11 (stored compressed; see decompress_mam)

References: the forensics.wiki "Windows Prefetch File Format" page and
Joachim Metz's libscca format documentation.
"""

import ctypes
import struct
import sys
from pathlib import Path

from .lnk import filetime_to_iso

SIGNATURE = b"SCCA"
HEADER_SIZE = 0x54

# Version-specific layout of the file information section (absolute offsets)
LAST_RUN_OFFSET = {17: 0x78, 23: 0x80, 26: 0x80, 30: 0x80}
LAST_RUN_SLOTS = {17: 1, 23: 1, 26: 8, 30: 8}
RUN_COUNT_OFFSET = {17: 0x90, 23: 0x98, 26: 0xD0}  # version 30 varies, see below
VOLUME_ENTRY_SIZE = {17: 40, 23: 104, 26: 104, 30: 96}

COMPRESSION_FORMAT_XPRESS_HUFF = 4


class PrefetchParseError(ValueError):
    """Raised when a file is not a valid Prefetch file or cannot be read."""


def decompress_mam(data):
    """Return uncompressed SCCA bytes, decompressing Windows 10/11 files.

    Compressed files start with "MAM" plus a flags byte, then the
    uncompressed size. If the flags byte has 0x80 set, a CRC32 checksum
    follows. The body is Xpress Huffman, decompressed with ntdll's
    RtlDecompressBufferEx, so this step needs Windows 8 or later.
    """
    if data[:3] != b"MAM":
        return data
    flags = data[3]
    uncompressed_size = struct.unpack_from("<I", data, 4)[0]
    body = data[12:] if flags & 0x80 else data[8:]

    if sys.platform != "win32":
        raise PrefetchParseError(
            "compressed (Windows 10/11) Prefetch files can only be decompressed "
            "on Windows; run the tool there or decompress the files first")

    ntdll = ctypes.WinDLL("ntdll")
    ntdll.RtlGetCompressionWorkSpaceSize.restype = ctypes.c_long
    ntdll.RtlDecompressBufferEx.restype = ctypes.c_long

    workspace_size = ctypes.c_ulong()
    fragment_size = ctypes.c_ulong()
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
        ctypes.byref(workspace_size), ctypes.byref(fragment_size))
    if status != 0:
        raise PrefetchParseError(f"RtlGetCompressionWorkSpaceSize failed (0x{status & 0xFFFFFFFF:08X})")

    workspace = ctypes.create_string_buffer(workspace_size.value)
    output = ctypes.create_string_buffer(uncompressed_size)
    final_size = ctypes.c_ulong()
    status = ntdll.RtlDecompressBufferEx(
        ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
        output, ctypes.c_ulong(uncompressed_size),
        ctypes.c_char_p(body), ctypes.c_ulong(len(body)),
        ctypes.byref(final_size), workspace)
    if status != 0:
        raise PrefetchParseError(f"decompression failed (NTSTATUS 0x{status & 0xFFFFFFFF:08X})")
    return output.raw[:final_size.value]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def _run_count_offset(version, data):
    if version != 30:
        return RUN_COUNT_OFFSET[version]
    # Windows 10/11 has two layouts. When the file metrics array starts at
    # 0x128 instead of 0x130, the file information section is 8 bytes
    # shorter and the run count sits at 0xC8 rather than 0xD0.
    return 0xC8 if _u32(data, 0x54) == 0x128 else 0xD0


def _filename_strings(data):
    offset, size = _u32(data, 0x64), _u32(data, 0x68)
    raw = data[offset:offset + size]
    if len(raw) < size:
        raise struct.error("filename strings run past end of file")
    text = raw.decode("utf-16-le", errors="replace")
    return [name for name in text.split("\x00") if name]


def _volumes(data, version):
    start, count = _u32(data, 0x6C), _u32(data, 0x70)
    entry_size = VOLUME_ENTRY_SIZE[version]
    volumes = []
    for index in range(count):
        entry = start + index * entry_size
        path_offset = _u32(data, entry)
        path_chars = _u32(data, entry + 4)
        path_start = start + path_offset
        path = data[path_start:path_start + path_chars * 2].decode("utf-16-le", errors="replace")
        serial = _u32(data, entry + 0x10)
        volumes.append({
            "device_path": path,
            "created": filetime_to_iso(_u64(data, entry + 8)),
            "serial": f"{serial >> 16:04X}-{serial & 0xFFFF:04X}",
        })
    return volumes


def _parse(data, source):
    data = decompress_mam(data)
    if len(data) < HEADER_SIZE or data[4:8] != SIGNATURE:
        raise PrefetchParseError(f"{source}: not a Prefetch file (missing SCCA signature)")

    version = _u32(data, 0)
    if version not in LAST_RUN_OFFSET:
        raise PrefetchParseError(f"{source}: unsupported Prefetch version {version}")

    executable = data[0x10:0x4C].decode("utf-16-le", errors="replace").split("\x00")[0]

    run_offset = LAST_RUN_OFFSET[version]
    run_times = []
    for slot in range(LAST_RUN_SLOTS[version]):
        stamp = filetime_to_iso(_u64(data, run_offset + slot * 8))
        if stamp:  # unused slots are zero
            run_times.append(stamp)

    files = _filename_strings(data)
    # The loaded-files list includes the executable itself with its full path
    suffix = "\\" + executable.upper()
    executable_path = next((f for f in files if f.upper().endswith(suffix)), None)

    return {
        "source_file": source,
        "executable": executable,
        "executable_path": executable_path,
        "prefetch_hash": f"{_u32(data, 0x4C):08X}",
        "version": version,
        "run_count": _u32(data, _run_count_offset(version, data)),
        "last_run_times": run_times,  # most recent first
        "volumes": _volumes(data, version),
        "loaded_files": files,
    }


def parse_prefetch(path):
    """Parse one .pf file and return its forensic fields as a dict."""
    data = Path(path).read_bytes()
    try:
        return _parse(data, str(path))
    except struct.error as exc:
        raise PrefetchParseError(f"{path}: truncated or malformed ({exc})") from exc


def summary(parsed):
    """Flat version of a parsed file for CSV and console output."""
    return {
        "source_file": parsed["source_file"],
        "executable": parsed["executable"],
        "executable_path": parsed["executable_path"],
        "run_count": parsed["run_count"],
        "last_run": parsed["last_run_times"][0] if parsed["last_run_times"] else None,
        "previous_runs": "; ".join(parsed["last_run_times"][1:]),
        "volumes": "; ".join(f"{v['device_path']} ({v['serial']})" for v in parsed["volumes"]),
        "loaded_file_count": len(parsed["loaded_files"]),
        "prefetch_hash": parsed["prefetch_hash"],
        "version": parsed["version"],
    }


def to_timeline_records(parsed):
    """One timeline record per recorded run time."""
    target = parsed["executable_path"] or parsed["executable"]
    return [{
        "timestamp": stamp,
        "artifact": "Prefetch",
        "event": "Program executed",
        "description": f"{target} (run count {parsed['run_count']})",
        "source_file": parsed["source_file"],
    } for stamp in parsed["last_run_times"]]
