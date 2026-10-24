"""Parser for Windows Registry hive files, with UserAssist and RecentDocs extraction.

The hive reader walks the "regf" format directly: a 4 KB base block, then
hive bins full of cells. Keys are "nk" cells, values are "vk" cells, and
subkey lists are "lf", "lh", "li" or "ri" cells. Large values (over 16,344
bytes) are split across "db" big-data cells.

Two user-activity artifacts from NTUSER.DAT are extracted:

UserAssist  Programs and shortcuts launched through Explorer (Start menu,
            desktop, taskbar), with run count, focus count, focus time and
            last run time. Value names are ROT13-encoded.
RecentDocs  Files and folders the user recently opened, per extension, in
            most-recent-first order from the MRUListEx value.

Reference: Joachim Metz's libregf "Windows NT Registry File (REGF) format".
"""

import codecs
import struct
import sys
from pathlib import Path

from .lnk import filetime_to_iso

HBIN_START = 0x1000
BIG_DATA_SEGMENT = 16344
KEY_COMP_NAME = 0x20
VALUE_COMP_NAME = 0x01
NO_LIST = 0xFFFFFFFF

USERASSIST_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
RECENTDOCS_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"

USERASSIST_TYPES = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
}

# Known folder GUIDs that prefix many UserAssist paths
KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "C:\\Windows\\System32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "C:\\Windows\\SysWOW64",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "C:\\Windows",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "C:\\Program Files",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "C:\\Program Files (x86)",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%AppData%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
}


class RegistryParseError(ValueError):
    """Raised when a file is not a valid hive or a cell is malformed."""


def _u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


class Hive:
    def __init__(self, data, source):
        if len(data) < HBIN_START or data[:4] != b"regf":
            raise RegistryParseError(f"{source}: not a registry hive (missing regf signature)")
        self.data = data
        self.source = source
        # Primary and secondary sequence numbers differ when the hive was not
        # cleanly written; recent changes may still be in the .LOG1/.LOG2 files
        self.dirty = _u32(data, 4) != _u32(data, 8)
        self.minor_version = _u32(data, 0x18)
        self.root = Key(self, _u32(data, 0x24))

    def cell(self, offset):
        position = HBIN_START + offset
        size = abs(struct.unpack_from("<i", self.data, position)[0])
        if size < 8 or position + size > len(self.data):
            raise RegistryParseError(f"{self.source}: bad cell at offset 0x{offset:X}")
        return self.data[position + 4:position + size]


class Key:
    def __init__(self, hive, offset):
        cell = hive.cell(offset)
        if cell[:2] != b"nk":
            raise RegistryParseError(f"{hive.source}: expected key cell at 0x{offset:X}")
        self.hive = hive
        flags = _u16(cell, 2)
        self.last_written = filetime_to_iso(_u64(cell, 4))
        self._subkey_count = _u32(cell, 20)
        self._subkey_list = _u32(cell, 28)
        self._value_count = _u32(cell, 36)
        self._value_list = _u32(cell, 40)
        raw_name = cell[76:76 + _u16(cell, 72)]
        if flags & KEY_COMP_NAME:
            self.name = raw_name.decode("latin-1")
        else:
            self.name = raw_name.decode("utf-16-le", errors="replace")

    def _list_offsets(self, offset):
        cell = self.hive.cell(offset)
        kind, count = cell[:2], _u16(cell, 2)
        if kind in (b"lf", b"lh"):  # offset + 4-byte hint or hash
            return [_u32(cell, 4 + i * 8) for i in range(count)]
        if kind == b"li":  # offsets only
            return [_u32(cell, 4 + i * 4) for i in range(count)]
        if kind == b"ri":  # index of other lists, used by very large keys
            offsets = []
            for i in range(count):
                offsets.extend(self._list_offsets(_u32(cell, 4 + i * 4)))
            return offsets
        raise RegistryParseError(f"{self.hive.source}: unknown subkey list type {kind!r}")

    def subkeys(self):
        if self._subkey_count == 0 or self._subkey_list == NO_LIST:
            return []
        return [Key(self.hive, o) for o in self._list_offsets(self._subkey_list)]

    def subkey(self, name):
        name = name.lower()  # registry names are case-insensitive
        return next((k for k in self.subkeys() if k.name.lower() == name), None)

    def find(self, path):
        key = self
        for part in path.split("\\"):
            key = key.subkey(part)
            if key is None:
                return None
        return key

    def values(self):
        if self._value_count == 0 or self._value_list == NO_LIST:
            return []
        offsets = self.hive.cell(self._value_list)
        return [Value(self.hive, _u32(offsets, i * 4)) for i in range(self._value_count)]

    def value(self, name):
        name = name.lower()
        return next((v for v in self.values() if v.name.lower() == name), None)


class Value:
    def __init__(self, hive, offset):
        cell = hive.cell(offset)
        if cell[:2] != b"vk":
            raise RegistryParseError(f"{hive.source}: expected value cell at 0x{offset:X}")
        name_length = _u16(cell, 2)
        size = _u32(cell, 4)
        data_offset = _u32(cell, 8)
        self.type = _u32(cell, 12)
        flags = _u16(cell, 16)
        raw_name = cell[20:20 + name_length]
        if not name_length:
            self.name = "(default)"
        elif flags & VALUE_COMP_NAME:
            self.name = raw_name.decode("latin-1")
        else:
            self.name = raw_name.decode("utf-16-le", errors="replace")

        if size & 0x80000000:
            # Data of 4 bytes or less is stored in the offset field itself
            self.data = cell[8:8 + (size & 0x7FFFFFFF)]
        elif size == 0:
            self.data = b""
        else:
            data_cell = hive.cell(data_offset)
            if size > BIG_DATA_SEGMENT and hive.minor_version >= 4 and data_cell[:2] == b"db":
                count = _u16(data_cell, 2)
                segments = hive.cell(_u32(data_cell, 4))
                chunks = b"".join(hive.cell(_u32(segments, i * 4))[:BIG_DATA_SEGMENT]
                                  for i in range(count))
                self.data = chunks[:size]
            else:
                self.data = data_cell[:size]


def _resolve_known_folder(path):
    for guid, folder in KNOWN_FOLDERS.items():
        if path.upper().startswith(guid):
            return folder + path[len(guid):]
    return path


def userassist(hive):
    """Decode every UserAssist entry in an NTUSER.DAT hive."""
    root = hive.root.find(USERASSIST_PATH)
    if root is None:
        return []
    entries = []
    for guid_key in root.subkeys():
        count_key = guid_key.subkey("Count")
        if count_key is None:
            continue
        for value in count_key.values():
            name = codecs.decode(value.name, "rot_13")
            if name.startswith("UEME_"):  # session bookkeeping, not a program
                continue
            data = value.data
            if len(data) >= 72:  # Windows 7 and later
                run_count, focus_count, focus_ms = _u32(data, 4), _u32(data, 8), _u32(data, 12)
                last_run = filetime_to_iso(_u64(data, 60))
            elif len(data) == 16:  # Windows XP: counts start at 5
                run_count = max(_u32(data, 4) - 5, 0)
                focus_count = focus_ms = None
                last_run = filetime_to_iso(_u64(data, 8))
            else:
                continue
            entries.append({
                "entry": _resolve_known_folder(name),
                "raw_name": name,
                "type": USERASSIST_TYPES.get(guid_key.name.upper(), guid_key.name),
                "run_count": run_count,
                "focus_count": focus_count,
                "focus_seconds": round(focus_ms / 1000, 1) if focus_ms is not None else None,
                "last_run": last_run,
            })
    return entries


def _mru_order(key):
    value = key.value("MRUListEx")
    if value is None:
        return []
    order = []
    for offset in range(0, len(value.data) - 3, 4):
        index = _u32(value.data, offset)
        if index == NO_LIST:  # end of list marker
            break
        order.append(index)
    return order


def _utf16_prefix(data):
    end = 0
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[:end].decode("utf-16-le", errors="replace")


def recentdocs(hive):
    """List RecentDocs entries in most-recent-first order for every subkey.

    Only the key's last-written time is recorded, and it corresponds to the
    entry at MRU position 0, so only that entry gets a timestamp.
    """
    root = hive.root.find(RECENTDOCS_PATH)
    if root is None:
        return []
    entries = []
    for key in [root] + root.subkeys():
        label = "RecentDocs" if key is root else f"RecentDocs\\{key.name}"
        values = {v.name: v for v in key.values()}
        for position, index in enumerate(_mru_order(key)):
            value = values.get(str(index))
            if value is None:
                continue
            entries.append({
                "key": label,
                "entry": _utf16_prefix(value.data),
                "mru_position": position,
                "last_opened": key.last_written if position == 0 else None,
            })
    return entries


def parse_registry(path):
    """Parse an NTUSER.DAT hive (or a `reg save` copy) for user activity."""
    data = Path(path).read_bytes()
    try:
        hive = Hive(data, str(path))
        result = {
            "source_file": str(path),
            "dirty": hive.dirty,
            "userassist": userassist(hive),
            "recentdocs": recentdocs(hive),
        }
    except struct.error as exc:
        raise RegistryParseError(f"{path}: truncated or malformed ({exc})") from exc
    if hive.dirty:
        print(f"[!] {path}: hive is dirty; recent changes may only be in its "
              ".LOG1/.LOG2 transaction logs, which are not replayed", file=sys.stderr)
    return result


ROW_FIELDS = ["source_file", "artifact", "key", "entry", "run_count", "focus_count",
              "focus_seconds", "mru_position", "timestamp"]


def summary_rows(parsed):
    """One flat row per UserAssist or RecentDocs entry."""
    rows = []
    for item in parsed["userassist"]:
        rows.append({
            "source_file": parsed["source_file"], "artifact": "UserAssist",
            "key": item["type"], "entry": item["entry"], "run_count": item["run_count"],
            "focus_count": item["focus_count"], "focus_seconds": item["focus_seconds"],
            "mru_position": None, "timestamp": item["last_run"],
        })
    for item in parsed["recentdocs"]:
        rows.append({
            "source_file": parsed["source_file"], "artifact": "RecentDocs",
            "key": item["key"], "entry": item["entry"], "run_count": None,
            "focus_count": None, "focus_seconds": None,
            "mru_position": item["mru_position"], "timestamp": item["last_opened"],
        })
    return rows


def to_timeline_records(parsed):
    records = [{
        "timestamp": item["last_run"],
        "artifact": "UserAssist",
        "event": "Program launched via Explorer",
        "description": f"{item['entry']} (run count {item['run_count']})",
        "source_file": parsed["source_file"],
    } for item in parsed["userassist"] if item["last_run"]]

    seen = set()  # the same file often heads both RecentDocs and its extension subkey
    for item in parsed["recentdocs"]:
        if item["last_opened"] and (item["last_opened"], item["entry"]) not in seen:
            seen.add((item["last_opened"], item["entry"]))
            records.append({
                "timestamp": item["last_opened"],
                "artifact": "RecentDocs",
                "event": "Recent file or folder opened",
                "description": f"{item['entry']} ({item['key']})",
                "source_file": parsed["source_file"],
            })
    return records
