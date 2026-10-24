import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from winartifacts import prefetch
from tests.build_pf import build_pf


def parse_bytes(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "TEST.EXE-00000000.pf"
        path.write_bytes(data)
        return prefetch.parse_prefetch(path)


class TestPrefetchParser(unittest.TestCase):
    def test_header_fields(self):
        result = parse_bytes(build_pf())
        self.assertEqual(result["executable"], "PAYLOAD_TOOL.EXE")
        self.assertEqual(result["prefetch_hash"], "7D3A91C2")
        self.assertEqual(result["version"], 30)

    def test_run_count_and_times_win10(self):
        result = parse_bytes(build_pf())
        self.assertEqual(result["run_count"], 3)
        self.assertEqual(result["last_run_times"], [
            "2026-09-04T22:11:40+00:00",
            "2026-09-04T22:10:06+00:00",
            "2026-09-03T16:58:12+00:00",
        ])

    def test_win10_short_layout_variant(self):
        result = parse_bytes(build_pf(short_variant=True, run_count=7))
        self.assertEqual(result["run_count"], 7)

    def test_older_versions_keep_one_run_time(self):
        for version in (17, 23):
            result = parse_bytes(build_pf(version=version, run_count=12))
            self.assertEqual(result["run_count"], 12)
            self.assertEqual(result["last_run_times"], ["2026-09-04T22:11:40+00:00"])

    def test_win8_keeps_eight_run_times(self):
        result = parse_bytes(build_pf(version=26))
        self.assertEqual(len(result["last_run_times"]), 3)

    def test_executable_path_and_loaded_files(self):
        result = parse_bytes(build_pf())
        self.assertEqual(result["executable_path"],
                         "\\VOLUME{01dc1e2a5e77a001-5e77a001}\\TOOLS\\PAYLOAD_TOOL.EXE")
        self.assertEqual(len(result["loaded_files"]), 4)

    def test_volume_information(self):
        for version in (17, 23, 26, 30):
            volume = parse_bytes(build_pf(version=version))["volumes"][0]
            self.assertEqual(volume["device_path"], "\\VOLUME{01dc1e2a5e77a001-5e77a001}")
            self.assertEqual(volume["serial"], "5E77-A001")
            self.assertEqual(volume["created"], "2026-08-30T12:00:00+00:00")

    def test_rejects_non_prefetch(self):
        with self.assertRaises(prefetch.PrefetchParseError):
            parse_bytes(b"\x00" * 300)

    def test_rejects_unknown_version(self):
        data = bytearray(build_pf())
        data[0] = 99
        with self.assertRaises(prefetch.PrefetchParseError):
            parse_bytes(bytes(data))

    def test_rejects_truncated_file(self):
        with self.assertRaises(prefetch.PrefetchParseError):
            parse_bytes(build_pf()[:0x140])

    def test_compressed_file_needs_windows(self):
        compressed = b"MAM\x04" + (5000).to_bytes(4, "little") + b"\x00" * 64
        with mock.patch.object(sys, "platform", "linux"):
            with self.assertRaisesRegex(prefetch.PrefetchParseError, "only be decompressed on Windows"):
                parse_bytes(compressed)

    def test_timeline_records(self):
        records = prefetch.to_timeline_records(parse_bytes(build_pf()))
        self.assertEqual(len(records), 3)
        self.assertTrue(all(r["event"] == "Program executed" for r in records))


if __name__ == "__main__":
    unittest.main()
