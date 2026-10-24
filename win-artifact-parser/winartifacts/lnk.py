"""Parser for Windows Shell Link (.lnk) files.

Implements the parts of Microsoft's [MS-SHLLINK] specification that matter
for forensics: the header timestamps, the target's local or network path,
the volume it lived on, embedded strings, and the TrackerDataBlock that
records the NetBIOS name of the machine where the link was created.

Spec: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
"""

import struct
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HEADER_SIZE = 0x4C
LNK_CLSID = uuid.UUID("00021401-0000-0000-c000-000000000046")

# LinkFlags bits (MS-SHLLINK 2.1.1)
HAS_TARGET_ID_LIST = 0x01
HAS_LINK_INFO = 0x02
HAS_NAME = 0x04
HAS_RELATIVE_PATH = 0x08
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80

# LinkInfoFlags bits (MS-SHLLINK 2.3)
VOLUME_ID_AND_LOCAL_BASE_PATH = 0x1
COMMON_NETWORK_RELATIVE_LINK = 0x2

TRACKER_DATA_SIGNATURE = 0xA0000003

DRIVE_TYPES = {
    0: "UNKNOWN", 1: "NO_ROOT_DIR", 2: "REMOVABLE", 3: "FIXED",
    4: "REMOTE", 5: "CDROM", 6: "RAMDISK",
}

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class LnkParseError(ValueError):
    """Raised when a file is not a valid shell link or is truncated."""


def filetime_to_iso(filetime):
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01 UTC) to ISO 8601."""
    if filetime == 0:
        return None  # zero means "not set", not 1601
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=filetime // 10)).isoformat()
    except OverflowError:
        return None


def _u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def _cstring(data, offset, unicode=False):
    """Read a null-terminated string (ANSI or UTF-16LE) starting at offset."""
    if unicode:
        end = offset
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode("utf-16-le", errors="replace")
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("cp1252", errors="replace")


def _parse_volume_id(link_info, offset):
    drive_type = _u32(link_info, offset + 4)
    serial = _u32(link_info, offset + 8)
    label_offset = _u32(link_info, offset + 12)
    if label_offset == 0x14:  # a Unicode label offset follows instead
        label = _cstring(link_info, offset + _u32(link_info, offset + 16), unicode=True)
    else:
        label = _cstring(link_info, offset + label_offset)
    return {
        "drive_type": DRIVE_TYPES.get(drive_type, str(drive_type)),
        # Shown the same way as `vol` on Windows, e.g. 1A2B-3C4D
        "drive_serial": f"{serial >> 16:04X}-{serial & 0xFFFF:04X}",
        "volume_label": label,
    }


def _parse_link_info(link_info):
    header_size = _u32(link_info, 4)
    flags = _u32(link_info, 8)
    volume_offset = _u32(link_info, 12)
    base_offset = _u32(link_info, 16)
    network_offset = _u32(link_info, 20)
    suffix_offset = _u32(link_info, 24)
    base_offset_u = suffix_offset_u = 0
    if header_size >= 0x24:  # optional Unicode path offsets are present
        base_offset_u = _u32(link_info, 28)
        suffix_offset_u = _u32(link_info, 32)

    if suffix_offset_u:
        suffix = _cstring(link_info, suffix_offset_u, unicode=True)
    elif suffix_offset:
        suffix = _cstring(link_info, suffix_offset)
    else:
        suffix = ""

    result = {}
    if flags & VOLUME_ID_AND_LOCAL_BASE_PATH:
        result.update(_parse_volume_id(link_info, volume_offset))
        if base_offset_u:
            base = _cstring(link_info, base_offset_u, unicode=True)
        else:
            base = _cstring(link_info, base_offset)
        result["local_path"] = base + suffix
    if flags & COMMON_NETWORK_RELATIVE_LINK:
        net_name_offset = _u32(link_info, network_offset + 8)
        net_name = _cstring(link_info, network_offset + net_name_offset)
        result["network_path"] = net_name + ("\\" + suffix if suffix else "")
    return result


def _parse(data, source):
    if len(data) < HEADER_SIZE or _u32(data, 0) != HEADER_SIZE:
        raise LnkParseError(f"{source}: not a shell link (bad header size)")
    if uuid.UUID(bytes_le=bytes(data[4:20])) != LNK_CLSID:
        raise LnkParseError(f"{source}: not a shell link (bad CLSID)")

    flags = _u32(data, 0x14)
    result = {
        "source_file": source,
        "target_created": filetime_to_iso(_u64(data, 0x1C)),
        "target_accessed": filetime_to_iso(_u64(data, 0x24)),
        "target_modified": filetime_to_iso(_u64(data, 0x2C)),
        "target_size": _u32(data, 0x34),
        "file_attributes": f"0x{_u32(data, 0x18):08X}",
        "local_path": None,
        "network_path": None,
        "drive_type": None,
        "drive_serial": None,
        "volume_label": None,
        "name": None,
        "relative_path": None,
        "working_dir": None,
        "arguments": None,
        "icon_location": None,
        "machine_id": None,
    }

    offset = HEADER_SIZE
    if flags & HAS_TARGET_ID_LIST:
        # Shell item list; skipped for now (see README roadmap)
        offset += 2 + _u16(data, offset)

    if flags & HAS_LINK_INFO:
        size = _u32(data, offset)
        result.update(_parse_link_info(data[offset:offset + size]))
        offset += size

    unicode = bool(flags & IS_UNICODE)
    for flag, key in (
        (HAS_NAME, "name"),
        (HAS_RELATIVE_PATH, "relative_path"),
        (HAS_WORKING_DIR, "working_dir"),
        (HAS_ARGUMENTS, "arguments"),
        (HAS_ICON_LOCATION, "icon_location"),
    ):
        if flags & flag:
            count = _u16(data, offset)
            offset += 2
            length = count * 2 if unicode else count
            raw = data[offset:offset + length]
            if len(raw) < length:
                raise struct.error("string data runs past end of file")
            result[key] = raw.decode("utf-16-le" if unicode else "cp1252", errors="replace")
            offset += length

    # ExtraData: a chain of blocks, ended by a block smaller than 4 bytes
    while offset + 8 <= len(data):
        block_size = _u32(data, offset)
        if block_size < 4:
            break
        if block_size >= 0x60 and _u32(data, offset + 4) == TRACKER_DATA_SIGNATURE:
            machine_id = data[offset + 16:offset + 32].split(b"\x00")[0]
            result["machine_id"] = machine_id.decode("ascii", errors="replace")
        offset += block_size

    return result


def parse_lnk(path):
    """Parse one .lnk file and return its forensic fields as a dict."""
    data = Path(path).read_bytes()
    try:
        return _parse(data, str(path))
    except struct.error as exc:
        raise LnkParseError(f"{path}: truncated or malformed ({exc})") from exc


def target_of(parsed):
    """Best available description of what the link points to."""
    return (parsed["local_path"] or parsed["network_path"]
            or parsed["relative_path"] or "(unknown target)")


def to_timeline_records(parsed):
    """Convert a parsed LNK into unified timeline records.

    Every parser in this project emits the same shape, so the output of all
    of them can be merged and sorted into a single timeline later.
    """
    target = target_of(parsed)
    records = []
    for key, event in (
        ("target_created", "Target file created"),
        ("target_modified", "Target file modified"),
        ("target_accessed", "Target file accessed"),
    ):
        if parsed[key]:
            records.append({
                "timestamp": parsed[key],
                "artifact": "LNK",
                "event": event,
                "description": target,
                "source_file": parsed["source_file"],
            })
    return records
