import hashlib
import struct
import unittest

from tools.p005_unlock_trace import analyze_image, scan_direct_bl


def image_with_payload(payload: bytes) -> bytes:
    header = bytearray(0x200)
    header[:4] = b"DHTB"
    struct.pack_into("<I", header, 4, 1)
    header[8:0x28] = hashlib.sha256(payload).digest()
    struct.pack_into("<I", header, 0x30, len(payload))
    footer = bytearray(0x60)
    footer[:8] = b"SIMGHDR\0"
    struct.pack_into("<Q", footer, 0x18, 0x200)
    return bytes(header) + payload + bytes(footer)


class P005ReadOnlyTraceTests(unittest.TestCase):
    def test_bl_sign_extended_direct_target(self):
        payload = bytearray(0x100)
        # BL +0x60 (from 0x20 to 0x80), BL -0x20 (0xa0 to 0x80)
        struct.pack_into("<I", payload, 0x20, 0x94000018)
        struct.pack_into("<I", payload, 0xA0, 0x97FFFFF8)
        report = scan_direct_bl(bytes(payload), {"target": 0x80})
        self.assertEqual(report["target"]["caller_payload_offsets"], ["0x20", "0xa0"])
        self.assertEqual(report["target"]["total_syntactic_bl_matches"], 2)

    def test_synthetic_image_is_read_only_and_offsets_are_reported(self):
        payload = bytearray(0x200)
        struct.pack_into("<I", payload, 0x20, 0x94000018)
        struct.pack_into("<I", payload, 0x24, 0xD503201F)
        struct.pack_into("<I", payload, 0x80, 0xD65F03C0)
        image = image_with_payload(bytes(payload))
        pristine = bytes(image)
        report = analyze_image(
            image,
            windows={"synthetic": (0x20, 0x10)},
            targets={"test_helper": 0x80},
        )
        self.assertEqual(image, pristine)
        self.assertTrue(report["dhtb_payload_hash_matches"])
        self.assertEqual(report["windows"]["synthetic"]["instructions"][0]["file_offset"], "0x220")
        self.assertEqual(report["direct_bl_caller_candidates"]["test_helper"]["caller_payload_offsets"], ["0x20"])
        self.assertIsNone(report["load_base"])

    def test_refuses_tampered_header_hash(self):
        payload = bytes(0x100)
        image = bytearray(image_with_payload(payload))
        image[8] ^= 1
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            analyze_image(bytes(image), windows={"small": (0, 0x10)}, targets={})

    def test_reject_invalid_windows_and_targets(self):
        image = image_with_payload(bytes(0x100))
        with self.assertRaisesRegex(ValueError, "invalid bounded code window"):
            analyze_image(image, windows={"bad": (3, 0x20)}, targets={})
        with self.assertRaisesRegex(ValueError, "target outside payload"):
            analyze_image(image, windows={}, targets={"bad": 0x200})


if __name__ == "__main__":
    unittest.main()
