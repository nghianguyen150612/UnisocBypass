"""Synthetic AArch64 semantic analysis regression tests."""
import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.aarch64_semantics import DEFAULT_LIMITS, SCHEMA, analyze, disassemble, main


def words(*values):
    return b"".join(v.to_bytes(4, "little") for v in values)


def b(at, target, link=False):
    return (0x94000000 if link else 0x14000000) | (((target - at) // 4) & 0x03ffffff)


def cbz(at, target, base=0x34000000):
    return base | ((((target - at) // 4) & 0x7ffff) << 5)


def report(code, entries=(0,), ranges=None, **kw):
    return analyze(code, file_sha256=hashlib.sha256(code).hexdigest(),
                   payload_file_offset=0x200, ranges=ranges or [(0, len(code))],
                   entries=list(entries), **kw)


class DecodeTests(unittest.TestCase):
    def test_supported_direct_and_indirect_transfers(self):
        sequence = words(b(0, 8), b(4, 0), b(8, 20, True), 0x54000040,
                         cbz(16, 24), cbz(20, 28, 0x35000000),
                         0x36000040, 0x37000040, 0xD61F0000,
                         0xD63F0000, 0xD65F03C0)
        ins = disassemble(sequence, 0, len(sequence))
        self.assertEqual([ins[n]["classification"] for n in range(4)],
                         ["branch", "branch", "call", "conditional_branch"])
        self.assertEqual([ins[n]["direct_target_payload_offset"] for n in range(6)],
                         [8, 0, 20, 20, 24, 28])
        self.assertEqual([ins[n]["mnemonic"] for n in range(4, 8)], ["cbz", "cbnz", "tbz", "tbnz"])
        self.assertTrue(ins[8]["unresolved_target"])
        self.assertTrue(ins[9]["unresolved_target"])
        self.assertEqual(ins[10]["classification"], "return")

    def test_invalid_and_address_observations(self):
        code = words(0xffffffff, 0xd65f03c0)
        ins = disassemble(code, 0, 8, payload_file_offset=0x200, load_base=0x100000)
        self.assertIsNone(ins[0]["mnemonic"])
        self.assertEqual(ins[1]["file_offset"], 0x204)
        self.assertEqual(ins[1]["runtime_address"], 0x100004)
        self.assertIsNone(disassemble(code, 0, 4)[0]["runtime_address"])

    def test_range_and_overflow_rejected(self):
        code = words(0xd65f03c0)
        for start, size in [(1, 4), (0, 3), (0, -4), (0, 8)]:
            with self.assertRaises(ValueError):
                disassemble(code, start, size)
        with self.assertRaises(ValueError):
            disassemble(code, 0, 4, load_base=(1 << 64) - 1)


class GraphTests(unittest.TestCase):
    def test_conditional_forks_shared_target_and_split(self):
        # cbz at 0 targets 12; fallthrough at 4 branches to 12. 8 branches into 16.
        code = words(cbz(0, 12), b(4, 12), b(8, 16), 0xd503201f, 0xd65f03c0)
        r = report(code)
        types = {e["type"] for e in r["control_flow_edges"]}
        self.assertIn("conditional_taken", types)
        self.assertIn("conditional_fallthrough", types)
        self.assertIn(16, {x["start"] for x in r["basic_blocks"]})

    def test_call_preserves_continuation_and_candidate(self):
        code = words(b(0, 12, True), 0xd65f03c0, 0xd503201f, 0xd65f03c0)
        r = report(code)
        types = {e["type"] for e in r["control_flow_edges"]}
        self.assertIn("direct_call", types)
        self.assertIn("call_continuation", types)
        self.assertEqual([c["entry_payload_offset"] for c in r["function_candidates"]], [0, 12])
        self.assertEqual(r["function_candidates"][1]["discovery_reason"], "direct_BL_target")

    def test_loops_returns_and_indirect_targets_terminate(self):
        code = words(b(0, 0), 0xd61f0000, 0xd63f0000, 0xd65f03c0)
        r = report(code)
        self.assertLessEqual(len(r["control_flow_edges"]), 8)
        self.assertEqual(len(r["unresolved_references"]), 2)
        self.assertTrue(any(e["type"] == "return" for e in r["control_flow_edges"]))

    def test_out_of_range_and_limits(self):
        r = report(words(b(0, 0x100)))
        self.assertEqual(r["control_flow_edges"][0]["resolution"], "external_or_out_of_range")
        with self.assertRaisesRegex(ValueError, "work limit"):
            report(words(b(0, 0)), limits={"work": 1})
        with self.assertRaisesRegex(ValueError, "entry"):
            report(words(0xd65f03c0), entries=(0, 4))

    def test_multiple_callers_and_overlapping_ownership(self):
        code = words(b(0, 16, True), b(4, 16, True), 0xd65f03c0,
                     0xd503201f, 0xd65f03c0)
        r = report(code, entries=(0, 4))
        callee = next(c for c in r["function_candidates"] if c["entry_payload_offset"] == 16)
        self.assertEqual(callee["direct_callers"], [0, 4])


    def test_unknown_word_stops_flow_and_downgrades_confidence(self):
        # Treat undecodable bytes as a boundary, not an ordinary instruction.
        code = words(0xffffffff, 0xd65f03c0)
        r = report(code)
        self.assertEqual(r["instructions"][0]["classification"], "unknown")
        self.assertFalse(any(
            e["source_block"] == 0 and e["destination_payload_offset"] == 4
            for e in r["control_flow_edges"]))
        self.assertEqual(r["function_candidates"][0]["confidence"], "UNKNOWN")
        self.assertTrue(any(u["type"] == "unknown" for u in r["unresolved_references"]))

    def test_eret_is_unsupported_control_transfer_not_fallthrough(self):
        code = words(0xd69f03e0, 0xd65f03c0)
        r = report(code)
        self.assertEqual(r["instructions"][0]["classification"], "unsupported_control_transfer")
        self.assertFalse(r["instructions"][0]["fallthrough"])
        self.assertFalse(any(
            e["source_block"] == 0 and e["destination_payload_offset"] == 4
            for e in r["control_flow_edges"]))
        self.assertEqual(r["function_candidates"][0]["confidence"], "LOW")

    def test_incomplete_direct_call_candidate_is_low_confidence(self):
        code = words(b(0, 8, True), 0xd65f03c0, 0xffffffff)
        r = report(code)
        callee = next(c for c in r["function_candidates"] if c["entry_payload_offset"] == 8)
        self.assertEqual(callee["confidence"], "UNKNOWN")
        self.assertTrue(callee["unresolved_outgoing_transfers"])
        self.assertEqual(r["function_candidates"][0]["confidence"], "HIGH")

    def test_direct_call_to_lower_address_is_not_a_loop(self):
        # Entry at 4 calls a callee at 0, and returns via continuation at 8.
        code = words(0xd65f03c0, b(4, 0, True), 0xd65f03c0)
        r = report(code, entries=(4,))
        call = next(e for e in r["control_flow_edges"] if e["type"] == "direct_call")
        self.assertTrue(call["backward_edge"])
        self.assertFalse(call["loop"])

    def test_backward_jump_without_cycle_is_not_a_loop(self):
        # Jump back to a separate return block: no path returns to the jump.
        code = words(0xd65f03c0, 0xd503201f, b(8, 0))
        r = report(code, entries=(8,))
        jump = next(e for e in r["control_flow_edges"] if e["type"] == "unconditional_branch")
        self.assertTrue(jump["backward_edge"])
        self.assertFalse(jump["loop"])

    def test_real_self_cycle_is_marked_loop(self):
        r = report(words(b(0, 0)))
        loop = next(e for e in r["control_flow_edges"] if e["type"] == "unconditional_branch")
        self.assertTrue(loop["backward_edge"])
        self.assertTrue(loop["loop"])

    def test_blr_has_unresolved_call_and_continuation_xref(self):
        r = report(words(0xd63f0000, 0xd65f03c0))
        self.assertTrue(any(
            x["type"] == "fallthrough" and x["source_payload_offset"] == 0
            and x["destination_payload_offset"] == 4
            for x in r["direct_xrefs"]))
        self.assertTrue(any(x["type"] == "indirect_transfer_unresolved"
                            for x in r["direct_xrefs"]))
        self.assertEqual(r["function_candidates"][0]["confidence"], "LOW")

    def test_configured_byte_limit_overrides_decoder_default(self):
        code = words(0xd503201f, 0xd503201f, 0xd65f03c0)
        with patch.dict(DEFAULT_LIMITS, {"bytes": 8}):
            with self.assertRaisesRegex(ValueError, "byte limit"):
                report(code)
            r = report(code, limits={"bytes": 12})
        self.assertEqual(len(r["instructions"]), 3)


class ReportTests(unittest.TestCase):
    def test_schema_hash_determinism_and_input_immutability(self):
        code = words(0x94000002, 0xd65f03c0, 0xd65f03c0)
        before = bytes(code)
        a = report(code)
        b_report = report(code)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b_report, sort_keys=True))
        self.assertEqual(a["schema"], SCHEMA)
        self.assertEqual(a["input"]["sha256"], hashlib.sha256(code).hexdigest())
        self.assertEqual(code, before)
        self.assertEqual(set(a), {"schema", "input", "configuration", "address_model", "code_ranges",
            "instructions", "basic_blocks", "control_flow_edges", "direct_xrefs", "function_candidates",
            "unresolved_references", "evidence", "limitations"})

    def test_xrefs_and_no_security_semantics(self):
        r = report(words(b(0, 8, True), b(4, 8), 0xd65f03c0))
        self.assertTrue(any(x["type"] == "direct_call" for x in r["direct_xrefs"]))
        self.assertTrue(all("name" not in c for c in r["function_candidates"]))
        self.assertTrue(all(x["runtime_address"] is None for x in r["instructions"]))

    def test_p001_cli_and_json_without_changing_input(self):
        payload = words(0xd65f03c0)
        header = bytearray(0x200)
        header[:4] = b"DHTB"
        struct.pack_into("<I", header, 4, 1)
        header[8:0x28] = hashlib.sha256(payload).digest()
        struct.pack_into("<I", header, 0x30, len(payload))
        footer = bytearray(0x60)
        footer[:8] = b"SIMGHDR\0"
        struct.pack_into("<Q", footer, 0x18, 0x200)
        image = bytes(header) + payload + bytes(footer)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic.bin"
            path.write_bytes(image)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main([str(path), "--range", "0:4", "--entry", "0"])
            parsed = json.loads(output.getvalue())
            self.assertEqual(rc, 0)
            self.assertEqual(parsed["schema"], SCHEMA)
            self.assertEqual(parsed["instructions"][0]["file_offset"], 0x200)
            self.assertEqual(path.read_bytes(), image)

    def test_multiple_ranges_and_entry_must_be_valid(self):
        code = words(0xd503201f, 0xd65f03c0, 0xd503201f, 0xd65f03c0)
        r = report(code, ranges=[(0, 8), (8, 8)], entries=(0, 8))
        self.assertEqual(len(r["code_ranges"]), 2)
        with self.assertRaisesRegex(ValueError, "decoded"):
            report(code, entries=(2,))


if __name__ == "__main__":
    unittest.main()
