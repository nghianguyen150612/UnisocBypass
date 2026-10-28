import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools.inspect_uboot_ums9620 import (
    InspectionError,
    decode_aarch64,
    inspect_bytes,
    main,
)


def synthetic_image(payload: bytes | None = None) -> bytes:
    payload = payload if payload is not None else struct.pack("<4I", 0x14000002,
                                                              0xD503201F,
                                                              0x35000160,
                                                              0xD65F03C0)
    header = bytearray(0x200)
    header[:4] = b"DHTB"
    struct.pack_into("<I", header, 4, 1)
    header[8:0x28] = hashlib.sha256(payload).digest()
    struct.pack_into("<I", header, 0x30, len(payload))
    footer = bytearray(0x60)
    footer[:8] = b"SIMGHDR\x00"
    struct.pack_into("<Q", footer, 0x18, 0x200)
    return bytes(header) + payload + bytes(footer)


class InspectorTests(unittest.TestCase):
    def test_hash_partition_and_instruction_report(self):
        data = synthetic_image()
        report = inspect_bytes(data, partition_size=0x1000,
                               code_ranges=[(0, 4)], load_base=0x100000)
        self.assertEqual(report["input"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(report["dhtb"]["payload_hash_matches_header"])
        self.assertTrue(report["partition"]["file_fits"])
        self.assertTrue(report["partition"]["declared_payload_and_footer_fit"])
        self.assertEqual(report["aarch64_instructions"][0]["assembly_subset"], "b 0x100008")
        self.assertEqual(report["aarch64_instructions"][1]["assembly_subset"], "nop")
        self.assertEqual(report["target"]["offset_compatibility"],
                         "unverified; no Nubia offsets are assumed")

    def test_read_only_compatibility_signal_and_no_load_base_default(self):
        data = synthetic_image()
        before = bytes(data)
        report = inspect_bytes(data)
        self.assertEqual(data, before)
        self.assertIsNone(report["load_base"])
        self.assertEqual(report["aarch64_instructions"], [])
        self.assertFalse(report["simghdr"]["signature_verified"])

    def test_cli_emits_json_and_keeps_synthetic_input_unchanged(self):
        data = synthetic_image()
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "synthetic-uboot.bin"
            image_path.write_bytes(data)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--disasm", "0:2", str(image_path)])
            report = json.loads(stdout.getvalue())
            self.assertEqual(result, 0)
            self.assertTrue(report["ok"])
            self.assertEqual(report["aarch64_instructions"][1]["assembly_subset"], "nop")
            self.assertEqual(image_path.read_bytes(), data)

    def test_hash_mismatch_is_reported_without_claiming_compatibility(self):
        data = bytearray(synthetic_image())
        data[8] ^= 0xFF
        report = inspect_bytes(bytes(data))
        self.assertFalse(report["dhtb"]["payload_hash_matches_header"])

    def test_reject_short_header_and_non_dhtb_input(self):
        with self.assertRaisesRegex(InspectionError, "shorter"):
            inspect_bytes(b"DHTB")
        malformed = bytearray(synthetic_image())
        malformed[:4] = b"NOPE"
        with self.assertRaisesRegex(InspectionError, "DHTB magic"):
            inspect_bytes(bytes(malformed))

    def test_reject_unsupported_version_and_zero_payload(self):
        malformed = bytearray(synthetic_image())
        struct.pack_into("<I", malformed, 4, 2)
        with self.assertRaisesRegex(InspectionError, "unsupported DHTB version"):
            inspect_bytes(bytes(malformed))
        malformed = bytearray(synthetic_image())
        struct.pack_into("<I", malformed, 0x30, 0)
        with self.assertRaisesRegex(InspectionError, "zero"):
            inspect_bytes(bytes(malformed))

    def test_reject_truncated_payload_and_missing_footer(self):
        malformed = bytearray(synthetic_image())
        struct.pack_into("<I", malformed, 0x30, len(malformed))
        with self.assertRaisesRegex(InspectionError, "exceeds file size"):
            inspect_bytes(bytes(malformed))
        with self.assertRaisesRegex(InspectionError, "SIMGHDR marker missing"):
            inspect_bytes(synthetic_image()[:-0x60])

    def test_reject_bad_classic_simghdr_bounds_and_inconsistent_size(self):
        data = bytearray(synthetic_image())
        payload_end = 0x200 + struct.unpack_from("<I", data, 0x30)[0]
        classic = bytearray(0x494)
        classic[:8] = b"SIMGHDR\x00"
        struct.pack_into("<Q", classic, 0x10, 999)
        struct.pack_into("<Q", classic, 0x18, 0x200)
        data[payload_end:payload_end + 0x60] = classic[:0x60]
        data.extend(classic[0x60:])
        with self.assertRaisesRegex(InspectionError, "payload sizes disagree"):
            inspect_bytes(bytes(data))

        truncated = bytearray(synthetic_image())
        payload_end = 0x200 + struct.unpack_from("<I", truncated, 0x30)[0]
        struct.pack_into("<Q", truncated, payload_end + 0x20, 0x254)
        with self.assertRaisesRegex(InspectionError, "extends past end of file"):
            inspect_bytes(bytes(truncated))

    def test_reject_partition_overflow_and_invalid_disassembly_range(self):
        data = synthetic_image()
        with self.assertRaisesRegex(InspectionError, "exceeds supplied partition size"):
            inspect_bytes(data, partition_size=len(data) - 1)
        with self.assertRaisesRegex(InspectionError, "not 4-byte aligned"):
            inspect_bytes(data, code_ranges=[(2, 1)])
        with self.assertRaisesRegex(InspectionError, "exceeds declared payload"):
            inspect_bytes(data, code_ranges=[(16, 1)])
        malformed = bytearray(data)
        payload_end = 0x200 + struct.unpack_from("<I", malformed, 0x30)[0]
        struct.pack_into("<Q", malformed, payload_end + 0x18, 0x300)
        with self.assertRaisesRegex(InspectionError, "unsupported vendor footer"):
            inspect_bytes(bytes(malformed))

    def test_aarch64_decoder_returns_raw_words_for_unhandled_instruction(self):
        self.assertEqual(decode_aarch64(0xFFFFFFFF), ".word 0xffffffff")
        self.assertEqual(decode_aarch64(0x94000001, 0x1000), "bl 0x1004")
        self.assertEqual(decode_aarch64(0x35000160, 0x1000), "cbnz w0, 0x102c")


if __name__ == "__main__":
    unittest.main()
