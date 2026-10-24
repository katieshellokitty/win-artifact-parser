import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from winartifacts import registry
from tests.build_hive import REG_BINARY, build_hive, userassist_value


def parse_bytes(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "NTUSER.DAT"
        path.write_bytes(data)
        return registry.parse_registry(path)


def hive_from_bytes(data):
    return registry.Hive(data, "test")


class TestHiveReader(unittest.TestCase):
    def test_navigates_keys_case_insensitively(self):
        hive = hive_from_bytes(build_hive())
        key = hive.root.find("software\\MICROSOFT\\Windows\\CurrentVersion\\Explorer")
        self.assertIsNotNone(key)
        self.assertEqual(sorted(k.name for k in key.subkeys()), ["RecentDocs", "UserAssist"])

    def test_inline_dword_value(self):
        value = hive_from_bytes(build_hive()).root.find("Console").value("QuickEdit")
        self.assertEqual(value.data, b"\x01\x00\x00\x00")

    def test_big_data_value(self):
        big = ("BigValue", REG_BINARY, bytes(range(256)) * 100)  # 25,600 bytes
        hive = hive_from_bytes(build_hive(extra_values=[big]))
        count = hive.root.find(registry.USERASSIST_PATH).subkeys()[0].subkey("Count")
        self.assertEqual(count.value("BigValue").data, big[2])

    def test_rejects_non_hive(self):
        with self.assertRaises(registry.RegistryParseError):
            parse_bytes(b"\x00" * 8192)

    def test_dirty_hive_flagged(self):
        self.assertFalse(parse_bytes(build_hive())["dirty"])
        self.assertTrue(parse_bytes(build_hive(dirty=True))["dirty"])


class TestUserAssist(unittest.TestCase):
    def setUp(self):
        self.entries = {e["raw_name"]: e for e in parse_bytes(build_hive())["userassist"]}

    def test_rot13_names_decoded_and_session_skipped(self):
        self.assertIn("E:\\tools\\payload_tool.exe", self.entries)
        self.assertFalse(any(name.startswith("UEME_") for name in self.entries))

    def test_counts_and_last_run(self):
        entry = self.entries["E:\\tools\\payload_tool.exe"]
        self.assertEqual(entry["run_count"], 3)
        self.assertEqual(entry["focus_count"], 3)
        self.assertEqual(entry["focus_seconds"], 95.0)
        self.assertEqual(entry["last_run"], "2026-09-04T22:11:40+00:00")
        self.assertEqual(entry["type"], "Executable")

    def test_known_folder_resolved(self):
        entry = self.entries["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"]
        self.assertEqual(entry["entry"], "C:\\Windows\\System32\\cmd.exe")

    def test_shortcut_type(self):
        word = next(e for e in self.entries.values() if e["entry"].endswith("Word.lnk"))
        self.assertEqual(word["type"], "Shortcut")
        self.assertEqual(word["run_count"], 41)


class TestRecentDocs(unittest.TestCase):
    def setUp(self):
        self.entries = parse_bytes(build_hive())["recentdocs"]

    def test_mru_order(self):
        top = [e["entry"] for e in self.entries if e["key"] == "RecentDocs"]
        self.assertEqual(top, ["case_notes.docx", "tools"])

    def test_only_most_recent_gets_timestamp(self):
        top = [e for e in self.entries if e["key"] == "RecentDocs"]
        self.assertEqual(top[0]["last_opened"], "2026-09-05T18:30:27+00:00")
        self.assertIsNone(top[1]["last_opened"])

    def test_extension_subkeys(self):
        docx = [e for e in self.entries if e["key"] == "RecentDocs\\.docx"]
        self.assertEqual(docx[0]["entry"], "case_notes.docx")


class TestTimeline(unittest.TestCase):
    def test_records_are_deduplicated(self):
        records = registry.to_timeline_records(parse_bytes(build_hive()))
        recent = [r for r in records if r["artifact"] == "RecentDocs"]
        self.assertEqual(len(recent), 2)  # case_notes.docx once, tools folder once
        self.assertEqual(len([r for r in records if r["artifact"] == "UserAssist"]), 3)


if __name__ == "__main__":
    unittest.main()
