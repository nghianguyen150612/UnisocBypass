from __future__ import annotations

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from tools.fdl_qualify import analyze, classify_log, main

ROOT = Path(__file__).parent / "fixtures" / "fdl_qualification"


class FdlQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.loaders = self.root / "loaders"
        self.loaders.mkdir()

    def make_pair(self) -> None:
        (self.loaders / "fdl1-sign.bin").write_bytes(b"synthetic FDL1-like opaque image" + bytes(range(64)))
        (self.loaders / "fdl2-sign.bin").write_bytes(b"synthetic FDL2-like opaque image" + bytes(range(64)))

    def settings(self, fixture: str = "valid_settings.ini") -> Path:
        return ROOT / fixture

    def test_inventory_reports_hashes_addresses_and_never_claims_compatibility(self) -> None:
        self.make_pair()
        report = analyze(self.loaders, self.settings())
        self.assertEqual(report["compatibility_status"], "unverified")
        self.assertEqual(report["target"]["model"], "Z2352N")
        self.assertEqual(report["profiles_referenced"], ["ZTE/Z2352N"])
        self.assertEqual(report["loader_addresses"]["FDL1"]["known"][0]["address"], "0x5500")
        self.assertEqual(report["loader_addresses"]["FDL2"]["known"][0]["address"], "0x9efffe00")
        self.assertTrue(all(len(item["sha256"]) == 64 for item in report["files"]))
        self.assertIn("do not prove", report["compatibility_limit"])

    def test_malformed_settings_is_insufficient_evidence(self) -> None:
        self.make_pair()
        report = analyze(self.loaders, self.settings("malformed_settings.ini"))
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        self.assertTrue(report["settings_issues"])
        self.assertTrue(report["loader_addresses"]["FDL1"]["unknown"])

    def test_missing_loader_file_is_reported_and_not_compatible(self) -> None:
        (self.loaders / "fdl1-sign.bin").write_bytes(b"synthetic loader image" + bytes(range(64)))
        report = analyze(self.loaders, self.settings())
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        missing = [ref for ref in report["settings_references"] if not ref["exists"]]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["stage"], "FDL2")

    def test_ambiguous_loader_reference_is_insufficient_evidence(self) -> None:
        config = self.root / "ambiguous.ini"
        config.write_text("[Loader]\nFDL=loader.bin\n", encoding="utf-8")
        (self.loaders / "loader.bin").write_bytes(b"synthetic opaque image" + bytes(range(64)))
        report = analyze(self.loaders, config)
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        self.assertEqual(report["settings_references"][0]["stage"], "ambiguous")

    def test_wrong_file_structure_is_reported(self) -> None:
        (self.loaders / "fdl1-sign.bin").write_text("<?xml version='1.0'?><PAC/>", encoding="utf-8")
        (self.loaders / "fdl2-sign.bin").write_bytes(b"")
        report = analyze(self.loaders, self.settings())
        self.assertEqual(report["compatibility_status"], "structurally incompatible")
        issues = {item["structural_issue"] for item in report["files"]}
        self.assertIn("text_or_container_not_loader_image", issues)
        self.assertIn("empty_file", issues)

    def test_no_loader_files_is_insufficient_evidence(self) -> None:
        report = analyze(self.loaders, self.settings())
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        self.assertEqual(report["files"], [])

    def test_check_baud_timeout_does_not_imply_authentication_failure(self) -> None:
        log = (ROOT / "check_baud_timeout.log").read_text(encoding="utf-8")
        report = classify_log(log)
        labels = {item["classification"] for item in report["matches"]}
        self.assertIn("check_baud_timeout", labels)
        self.assertIn("root_cause_undetermined", labels)
        self.assertNotIn("security_or_authentication_rejection", labels)
        self.assertFalse(report["conclusive_root_cause"])

    def test_usb_timeout_classification_is_nonconclusive(self) -> None:
        report = classify_log((ROOT / "usb_timeout.log").read_text(encoding="utf-8"))
        self.assertIn("usb_transport_timeout", {item["classification"] for item in report["matches"]})
        self.assertFalse(report["conclusive_root_cause"])

    def test_other_diagnostic_classes_are_distinguished(self) -> None:
        self.assertEqual(classify_log("FDL2 DRAM initialization failed")["matches"][0]["classification"], "fdl2_initialization_failure")
        self.assertEqual(classify_log("invalid loader image format")["matches"][0]["classification"], "loader_format_mismatch")
        self.assertEqual(classify_log("signature verification failed")["matches"][0]["classification"], "security_or_authentication_rejection")

    def test_cli_json_inventory_emits_parseable_report(self) -> None:
        self.make_pair()
        previous = sys.stdout
        capture = StringIO()
        sys.stdout = capture
        try:
            result = main(["inventory", "--loader-dir", str(self.loaders), "--settings", str(self.settings()), "--json"])
        finally:
            sys.stdout = previous
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(capture.getvalue())["compatibility_status"], "unverified")


if __name__ == "__main__":
    unittest.main()
