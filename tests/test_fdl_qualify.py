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

    def write_settings(self, *, fdl1: str | None = None, fdl2: str | None = None) -> Path:
        lines = ["[Device]", "Profile=ZTE/Z2352N", "", "[Download]"]
        if fdl1 is not None:
            lines.append(f"FDL1={fdl1}")
        if fdl2 is not None:
            lines.append(f"FDL2={fdl2}")
        path = self.root / "settings.ini"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

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

    def test_profile_linked_pair_is_unverified_not_compatible(self) -> None:
        self.make_pair()
        report = analyze(self.loaders, self.settings())
        self.assertEqual(report["compatibility_status"], "unverified")
        self.assertEqual({ref["stage"] for ref in report["settings_references"]}, {"FDL1", "FDL2"})
        self.assertTrue(all(ref["candidate_match"] and ref["role_match"] for ref in report["settings_references"]))

    def test_filename_pair_without_settings_references_is_insufficient(self) -> None:
        self.make_pair()
        report = analyze(self.loaders, self.write_settings())
        self.assertEqual(report["settings_references"], [])
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        self.assertEqual(
            {issue["stage"] for issue in report["evidence_issues"] if issue["type"] == "missing_stage_reference"},
            {"FDL1", "FDL2"},
        )

    def test_each_partial_settings_reference_is_insufficient(self) -> None:
        self.make_pair()
        cases = (("fdl1-sign.bin", None, "FDL2"), (None, "fdl2-sign.bin", "FDL1"))
        for fdl1, fdl2, missing_stage in cases:
            with self.subTest(fdl1=fdl1, fdl2=fdl2):
                report = analyze(self.loaders, self.write_settings(fdl1=fdl1, fdl2=fdl2))
                self.assertEqual(report["compatibility_status"], "insufficient evidence")
                self.assertIn(
                    {"type": "missing_stage_reference", "stage": missing_stage},
                    report["evidence_issues"],
                )

    def test_settings_metadata_supports_unusual_names_without_filename_override(self) -> None:
        (self.loaders / "stage-a.data").write_bytes(b"synthetic opaque stage A" + bytes(range(64)))
        (self.loaders / "stage-b.data").write_bytes(b"synthetic opaque stage B" + bytes(range(64)))
        report = analyze(self.loaders, self.write_settings(fdl1="stage-a.data", fdl2="stage-b.data"))
        self.assertEqual(report["compatibility_status"], "unverified")
        roles = {item["path"]: item["candidate_roles"] for item in report["files"]}
        self.assertEqual(roles, {"stage-a.data": ["FDL1"], "stage-b.data": ["FDL2"]})

    def test_settings_role_filename_mismatches_are_explicit(self) -> None:
        self.make_pair()
        report = analyze(
            self.loaders,
            self.write_settings(fdl1="fdl2-sign.bin", fdl2="fdl1-sign.bin"),
        )
        mismatches = [issue for issue in report["evidence_issues"] if issue["type"] == "role_mismatch"]
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        self.assertEqual({(issue["stage"], issue["filename_role"]) for issue in mismatches}, {("FDL1", "FDL2"), ("FDL2", "FDL1")})
        roles = {item["path"]: item["candidate_roles"] for item in report["files"]}
        self.assertEqual(roles["fdl1-sign.bin"], ["FDL1"])
        self.assertEqual(roles["fdl2-sign.bin"], ["FDL2"])
        self.assertTrue(all(not ref["role_match"] for ref in report["settings_references"]))
        self.assertTrue(all(ref["structural_issue"] is None for ref in report["settings_references"]))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in report["files"]))

    def test_same_file_for_both_stages_is_ambiguous_and_roles_are_not_appended(self) -> None:
        (self.loaders / "loader.bin").write_bytes(b"synthetic opaque loader" + bytes(range(64)))
        report = analyze(self.loaders, self.write_settings(fdl1="loader.bin", fdl2="loader.bin"))
        self.assertEqual(report["compatibility_status"], "insufficient evidence")
        self.assertIn(
            {"type": "same_file_for_multiple_stages", "stages": ["FDL1", "FDL2"], "path": str((self.loaders / "loader.bin").resolve())},
            report["evidence_issues"],
        )
        self.assertEqual(report["files"][0]["candidate_roles"], [])

    def test_referenced_bad_fdl1_is_not_masked_by_unreferenced_plausible_fdl1(self) -> None:
        (self.loaders / "fdl1-broken.bin").write_text("<?xml version='1.0'?><PAC/>", encoding="utf-8")
        (self.loaders / "fdl1-unrelated.bin").write_bytes(b"synthetic opaque FDL1" + bytes(range(64)))
        (self.loaders / "fdl2-sign.bin").write_bytes(b"synthetic opaque FDL2" + bytes(range(64)))
        report = analyze(
            self.loaders,
            self.write_settings(fdl1="fdl1-broken.bin", fdl2="fdl2-sign.bin"),
        )
        self.assertEqual(report["compatibility_status"], "structurally incompatible")
        broken_ref = next(ref for ref in report["settings_references"] if ref["stage"] == "FDL1")
        self.assertEqual(broken_ref["structural_issue"], "text_or_container_not_loader_image")
        unrelated = next(item for item in report["files"] if item["path"] == "fdl1-unrelated.bin")
        self.assertIsNone(unrelated["structural_issue"])

    def test_referenced_bad_fdl2_is_not_masked_by_unreferenced_plausible_fdl2(self) -> None:
        (self.loaders / "fdl1-sign.bin").write_bytes(b"synthetic opaque FDL1" + bytes(range(64)))
        (self.loaders / "fdl2-broken.bin").write_bytes(b"")
        (self.loaders / "fdl2-unrelated.bin").write_bytes(b"synthetic opaque FDL2" + bytes(range(64)))
        report = analyze(
            self.loaders,
            self.write_settings(fdl1="fdl1-sign.bin", fdl2="fdl2-broken.bin"),
        )
        self.assertEqual(report["compatibility_status"], "structurally incompatible")
        broken_ref = next(ref for ref in report["settings_references"] if ref["stage"] == "FDL2")
        self.assertEqual(broken_ref["structural_issue"], "empty_file")
        unrelated = next(item for item in report["files"] if item["path"] == "fdl2-unrelated.bin")
        self.assertIsNone(unrelated["structural_issue"])

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

    def test_fdl2_incompatible_partition_is_independent_classification(self) -> None:
        report = classify_log("FDL2: incompatible partition")
        labels = {item["classification"] for item in report["matches"]}
        self.assertEqual(labels, {"fdl2_incompatible_partition"})
        self.assertFalse(report["conclusive_root_cause"])

    def test_combined_log_preserves_independent_diagnostic_categories(self) -> None:
        report = classify_log("CHECK_BAUD timeout; USB bulk transfer timed out; FDL2: incompatible partition")
        labels = {item["classification"] for item in report["matches"]}
        self.assertTrue({"check_baud_timeout", "root_cause_undetermined", "usb_transport_timeout", "fdl2_incompatible_partition"} <= labels)
        self.assertNotIn("fdl2_initialization_failure", labels)
        self.assertNotIn("security_or_authentication_rejection", labels)
        self.assertFalse(report["conclusive_root_cause"])

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
        report = json.loads(capture.getvalue())
        self.assertEqual(report["compatibility_status"], "unverified")
        for field in (
            "schema_version", "purpose", "target", "settings_ini", "loader_directory",
            "settings_issues", "profiles_referenced", "files", "settings_references",
            "loader_addresses", "compatibility_status", "compatibility_limit",
        ):
            self.assertIn(field, report)


if __name__ == "__main__":
    unittest.main()
