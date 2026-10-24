"""Build synthetic registry hives for testing, following the regf format.

Regenerate the sample with:
    python -m tests.build_hive samples/
"""

import codecs
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from winartifacts import registry
from tests.build_lnk import to_filetime

REG_BINARY = 3
REG_DWORD = 4
EXECUTABLE_GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
SHORTCUT_GUID = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
EPOCH_KEY_TIME = datetime(2026, 9, 1, tzinfo=timezone.utc)


def key(name, values=(), subkeys=(), last_written=EPOCH_KEY_TIME):
    return {"name": name, "values": list(values), "subkeys": list(subkeys),
            "last_written": last_written}


class HiveWriter:
    def __init__(self):
        self.cells = bytearray(32)  # room for the hbin header

    def alloc(self, payload):
        size = (4 + len(payload) + 7) // 8 * 8
        offset = len(self.cells)
        self.cells += struct.pack("<i", -size) + payload + b"\x00" * (size - 4 - len(payload))
        return offset

    def value(self, name, value_type, data):
        name_bytes = name.encode("latin-1")
        if len(data) <= 4:
            size, offset_field = len(data) | 0x80000000, data.ljust(4, b"\x00")
        elif len(data) > registry.BIG_DATA_SEGMENT:
            chunks = [data[i:i + registry.BIG_DATA_SEGMENT]
                      for i in range(0, len(data), registry.BIG_DATA_SEGMENT)]
            segments = b"".join(struct.pack("<I", self.alloc(c)) for c in chunks)
            big = self.alloc(b"db" + struct.pack("<HII", len(chunks), self.alloc(segments), 0))
            size, offset_field = len(data), struct.pack("<I", big)
        else:
            size, offset_field = len(data), struct.pack("<I", self.alloc(data))
        payload = (b"vk" + struct.pack("<HI", len(name_bytes), size) + offset_field
                   + struct.pack("<IHH", value_type, registry.VALUE_COMP_NAME, 0) + name_bytes)
        return self.alloc(payload)

    def key(self, spec, root=False):
        value_offsets = [self.value(*v) for v in spec["values"]]
        value_list = (self.alloc(b"".join(struct.pack("<I", o) for o in value_offsets))
                      if value_offsets else registry.NO_LIST)
        subkey_offsets = [self.key(child) for child in spec["subkeys"]]
        subkey_list = (self.alloc(b"lf" + struct.pack("<H", len(subkey_offsets)) + b"".join(
            struct.pack("<I4s", o, b"\x00" * 4) for o in subkey_offsets))
            if subkey_offsets else registry.NO_LIST)
        name = spec["name"].encode("latin-1")
        flags = registry.KEY_COMP_NAME | (0x0C if root else 0)  # root: HIVE_ENTRY | NO_DELETE
        payload = struct.pack(
            "<2sHQ" + "I" * 15 + "HH", b"nk", flags, to_filetime(spec["last_written"]),
            0, 0, len(subkey_offsets), 0, subkey_list, registry.NO_LIST,
            len(value_offsets), value_list, NO_SECURITY, registry.NO_LIST,
            0, 0, 0, 0, 0, len(name), 0) + name
        return self.alloc(payload)

    def build(self, root_spec, dirty=False):
        root_offset = self.key(root_spec, root=True)
        bins = self.cells.ljust((len(self.cells) + 4095) // 4096 * 4096, b"\x00")
        struct.pack_into("<4sII", bins, 0, b"hbin", 0, len(bins))

        base = bytearray(4096)
        struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", 2, 1 if dirty else 2,
                         to_filetime(EPOCH_KEY_TIME), 1, 5, 0, 1, root_offset, len(bins), 1)
        checksum = 0
        for i in range(0, 508, 4):
            checksum ^= struct.unpack_from("<I", base, i)[0]
        struct.pack_into("<I", base, 508, checksum)
        return bytes(base) + bytes(bins)


NO_SECURITY = registry.NO_LIST


def userassist_data(run_count, last_run, focus_count=1, focus_ms=60000):
    data = bytearray(72)
    struct.pack_into("<IIII", data, 0, 0, run_count, focus_count, focus_ms)
    for i in range(16, 56, 4):
        struct.pack_into("<f", data, i, -1.0)
    struct.pack_into("<Q", data, 60, to_filetime(last_run))
    return bytes(data)


def userassist_value(path, run_count, last_run, **kwargs):
    return (codecs.encode(path, "rot_13"), REG_BINARY,
            userassist_data(run_count, last_run, **kwargs))


def recentdoc_data(name):
    # UTF-16 name, then shell item data and the .lnk name, which the parser skips
    return (name.encode("utf-16-le") + b"\x00\x00" + b"\x14\x00\x32\x00" + b"\x00" * 16
            + (name + ".lnk").encode("latin-1") + b"\x00")


def mru(*indexes):
    return ("MRUListEx", REG_BINARY,
            b"".join(struct.pack("<I", i) for i in indexes) + b"\xff\xff\xff\xff")


def sample_tree(extra_values=()):
    utc = timezone.utc
    userassist_key = key("UserAssist", subkeys=[
        key(EXECUTABLE_GUID, subkeys=[key("Count", values=[
            (codecs.encode("UEME_CTLSESSION", "rot_13"), REG_BINARY, b"\x00" * 1612),
            userassist_value("E:\\tools\\payload_tool.exe", 3,
                             datetime(2026, 9, 4, 22, 11, 40, tzinfo=utc),
                             focus_count=3, focus_ms=95000),
            userassist_value("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe", 12,
                             datetime(2026, 9, 4, 22, 9, 52, tzinfo=utc)),
            *extra_values,
        ])]),
        key(SHORTCUT_GUID, subkeys=[key("Count", values=[
            userassist_value("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\\Word.lnk", 41,
                             datetime(2026, 9, 5, 18, 30, 15, tzinfo=utc),
                             focus_count=38, focus_ms=7_380_000),
        ])]),
    ])
    recentdocs_key = key("RecentDocs", values=[
        mru(1, 0),
        ("0", REG_BINARY, recentdoc_data("tools")),
        ("1", REG_BINARY, recentdoc_data("case_notes.docx")),
    ], subkeys=[
        key(".docx", values=[mru(0), ("0", REG_BINARY, recentdoc_data("case_notes.docx"))],
            last_written=datetime(2026, 9, 5, 18, 30, 27, tzinfo=utc)),
        key("Folder", values=[mru(0), ("0", REG_BINARY, recentdoc_data("tools"))],
            last_written=datetime(2026, 9, 4, 22, 9, 31, tzinfo=utc)),
    ], last_written=datetime(2026, 9, 5, 18, 30, 27, tzinfo=utc))

    explorer = key("Explorer", subkeys=[userassist_key, recentdocs_key])
    path_down = key("Software", subkeys=[key("Microsoft", subkeys=[key("Windows", subkeys=[
        key("CurrentVersion", subkeys=[explorer])])])])
    return key("ROOT", subkeys=[path_down, key("Console", values=[
        ("QuickEdit", REG_DWORD, struct.pack("<I", 1))])])


def build_hive(dirty=False, extra_values=()):
    return HiveWriter().build(sample_tree(extra_values), dirty=dirty)


if __name__ == "__main__":
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "NTUSER_SYNTHETIC.DAT").write_bytes(build_hive())
    print(f"Wrote samples to {out_dir}/")
