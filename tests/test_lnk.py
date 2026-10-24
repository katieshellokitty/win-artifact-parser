import tempfile
import unittest
from pathlib import Path

from winartifacts import lnk
from tests.build_lnk import build_lnk


def parse_bytes(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "test.lnk"
        path.write_bytes(data)
        return lnk.parse_lnk(path)


class TestLnkParser(unittest.TestCase):
    def test_header_timestamps_and_size(self):
        result = parse_bytes(build_lnk())
        self.assertEqual(result["target_created"], "2026-09-01T14:02:11+00:00")
        self.assertEqual(result["target_modified"], "2026-09-03T09:45:00+00:00")
        self.assertEqual(result["target_accessed"], "2026-09-05T18:30:27+00:00")
        self.assertEqual(result["target_size"], 24576)

    def test_volume_and_path(self):
        result = parse_bytes(build_lnk())
        self.assertEqual(result["local_path"], "C:\\Users\\student\\Documents\\case_notes.docx")
        self.assertEqual(result["drive_type"], "FIXED")
        self.assertEqual(result["drive_serial"], "1A2B-3C4D")
        self.assertEqual(result["volume_label"], "OS")

    def test_machine_id_from_tracker_block(self):
        self.assertEqual(parse_bytes(build_lnk())["machine_id"], "desktop-lab01")

    def test_string_data_unicode_and_ansi(self):
        for unicode in (True, False):
            result = parse_bytes(build_lnk(arguments="--silent", unicode=unicode))
            self.assertEqual(result["working_dir"], "C:\\Users\\student\\Documents")
            self.assertEqual(result["arguments"], "--silent")

    def test_zero_timestamp_is_none(self):
        self.assertIsNone(lnk.filetime_to_iso(0))

    def test_rejects_non_lnk(self):
        with self.assertRaises(lnk.LnkParseError):
            parse_bytes(b"MZ" + b"\x00" * 200)

    def test_rejects_truncated_file(self):
        with self.assertRaises(lnk.LnkParseError):
            parse_bytes(build_lnk()[:90])

    def test_timeline_records(self):
        records = lnk.to_timeline_records(parse_bytes(build_lnk()))
        self.assertEqual(len(records), 3)
        self.assertTrue(all(r["artifact"] == "LNK" for r in records))


if __name__ == "__main__":
    unittest.main()
