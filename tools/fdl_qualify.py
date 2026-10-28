"""Offline inventory and diagnostic classification for externally supplied FDLs.

This module intentionally never connects to a device and never modifies inputs.
It reports structural observations only; it cannot establish loader compatibility.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

EXPECTED_DEVICE = {
    "model": "Z2352N",
    "platform": "P820F03",
    "soc": "UNISOC T820 / UMS9620",
}

FDL1_NAME = re.compile(r"(?:^|[^a-z0-9])(?:fdl\s*[_-]?\s*1|fdl1|first[_-]?fdl)(?:[^a-z0-9]|$)", re.IGNORECASE)
FDL2_NAME = re.compile(r"(?:^|[^a-z0-9])(?:fdl\s*[_-]?\s*2|fdl2|second[_-]?fdl)(?:[^a-z0-9]|$)", re.IGNORECASE)
ADDRESS = re.compile(r"(?i)(?:0x)?([0-9a-f]{4,16})\b")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def observe_format(path: Path) -> tuple[list[str], str | None]:
    """Return format observations and a definite structural problem, if any."""
    size = path.stat().st_size
    if size == 0:
        return ["empty file"], "empty_file"
    with path.open("rb") as stream:
        head = stream.read(4096)
    observations: list[str] = [f"first bytes: {head[:16].hex(' ')}"]
    if head.startswith(b"\x7fELF"):
        observations.append("ELF executable header")
    if head.startswith((b"PK\x03\x04", b"MZ")):
        observations.append("archive or executable wrapper header")
    if head.lstrip().startswith((b"<?xml", b"<PAC", b"<pac")):
        observations.append("XML/PAC text header")
    for marker in (b"FDL1", b"FDL2", b"SIMGHDR", b"DHTB", b"SPRD"):
        if marker.lower() in head.lower():
            observations.append(f"contains ASCII marker {marker.decode('ascii')}")

    try:
        decoded = head.decode("utf-8")
    except UnicodeDecodeError:
        decoded = ""
    if decoded and sum(char.isprintable() or char in "\r\n\t" for char in decoded) / len(decoded) > 0.95:
        observations.append("mostly printable UTF-8 text")
        if path.suffix.lower() in {".xml", ".ini", ".txt", ".pac"} or decoded.lstrip().startswith(("<", "[")):
            return observations, "text_or_container_not_loader_image"
    if path.suffix.lower() == ".pac":
        observations.append("PAC container extension; not treated as extracted FDL")
        return observations, "pac_container_not_extracted_loader"
    if size < 64:
        observations.append("very small file; likely not a complete loader image")
        return observations, "implausibly_small"
    if not observations[1:]:
        observations.append("opaque binary; no known loader structure identified")
    return observations, None


def _role_for_name(name: str) -> str | None:
    if FDL1_NAME.search(name):
        return "FDL1"
    if FDL2_NAME.search(name):
        return "FDL2"
    return None


def _parse_ini(path: Path) -> tuple[configparser.ConfigParser | None, list[str], str]:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    try:
        text = path.read_text(encoding="utf-8-sig")
        parser.read_string(text, source=str(path))
        return parser, [], text
    except (OSError, UnicodeError, configparser.Error) as exc:
        return None, [f"settings.ini could not be parsed: {exc}"], ""


def _references(
    parser: configparser.ConfigParser | None,
    loader_dir: Path,
    settings_path: Path,
) -> list[dict[str, Any]]:
    if parser is None:
        return []
    refs: list[dict[str, Any]] = []
    for section in parser.sections():
        for key, value in parser.items(section):
            key_l = key.lower()
            role = _role_for_name(key_l)
            value_clean = value.strip().strip("\"'")
            value_path = Path(value_clean.replace("\\", "/"))
            value_role = _role_for_name(value_path.name)
            has_file_extension = bool(re.search(r"\.(?:bin|fdl|elf|img|pac)$", value_clean, re.IGNORECASE))
            is_address = bool(ADDRESS.fullmatch(value_clean))
            is_pathish = bool(value_role or has_file_extension or "/" in value_clean or "\\" in value_clean)
            metadata_key_is_path = role in {"FDL1", "FDL2"} and (
                key_l == role.lower() or any(word in key_l for word in ("file", "path", "loader", "image", "bin"))
            )
            if metadata_key_is_path and value_clean and not is_address:
                is_pathish = True
            if role is None and value_role is not None:
                role = value_role
            if role is None and ("fdl" in key_l or "loader" in key_l) and is_pathish:
                role = "ambiguous"
            if role is None or not is_pathish:
                continue
            if value_path.is_absolute():
                resolved = value_path
            else:
                settings_relative = settings_path.parent / value_path
                loader_relative = loader_dir / value_path
                resolved = settings_relative if settings_relative.is_file() else loader_relative
            refs.append({
                "section": section,
                "key": key,
                "value": value,
                "stage": role,
                "filename_role": value_role,
                "resolved_path": os.path.abspath(resolved),
                "exists": resolved.is_file(),
            })

    return refs


def _addresses(parser: configparser.ConfigParser | None) -> dict[str, Any]:
    result: dict[str, Any] = {"FDL1": [], "FDL2": []}
    if parser is None:
        return {key: {"known": [], "unknown": True} for key in result}
    for section in parser.sections():
        for key, value in parser.items(section):
            role = _role_for_name(key)
            if role not in result:
                continue
            if any(term in key.lower() for term in ("base", "addr", "address", "load")):
                match = ADDRESS.search(value)
                if match:
                    result[role].append({"section": section, "key": key, "value": value, "address": f"0x{int(match.group(1), 16):x}"})
    return {key: {"known": values, "unknown": not bool(values)} for key, values in result.items()}


def analyze(loader_dir: Path, settings_path: Path) -> dict[str, Any]:
    loader_dir = loader_dir.expanduser().resolve()
    settings_path = settings_path.expanduser().resolve()
    parser, settings_issues, _ = _parse_ini(settings_path)
    files: list[dict[str, Any]] = []
    if loader_dir.is_dir():
        for path in sorted(loader_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            role = _role_for_name(path.name)
            if role is None and path.suffix.lower() not in {".bin", ".fdl", ".elf", ".img", ".pac"}:
                continue
            observations, structural_issue = observe_format(path)
            files.append({
                "path": str(path.relative_to(loader_dir)),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "candidate_roles": [role] if role else [],
                "format_observations": observations,
                "structural_issue": structural_issue,
            })
    else:
        settings_issues.append(f"loader directory does not exist: {loader_dir}")

    references = _references(parser, loader_dir, settings_path)
    inventory_by_abs = {str((loader_dir / item["path"]).resolve()): item for item in files}
    for ref in references:
        referenced_path = Path(ref["resolved_path"])
        inventory_key = os.path.abspath(referenced_path)
        entry = inventory_by_abs.get(inventory_key)
        referenced_inside_loader_dir = referenced_path.is_relative_to(loader_dir)
        has_symlink_component = False
        if referenced_inside_loader_dir:
            component = loader_dir
            for part in referenced_path.relative_to(loader_dir).parts:
                component = component / part
                if component.is_symlink():
                    has_symlink_component = True
                    break
        if (
            entry is None
            and ref["exists"]
            and loader_dir.is_dir()
            and not has_symlink_component
            and referenced_inside_loader_dir
        ):
            observations, structural_issue = observe_format(referenced_path)
            entry = {
                "path": str(referenced_path.relative_to(loader_dir)),
                "size_bytes": referenced_path.stat().st_size,
                "sha256": sha256_file(referenced_path),
                "candidate_roles": [],
                "format_observations": observations,
                "structural_issue": structural_issue,
            }
            files.append(entry)
            inventory_by_abs[inventory_key] = entry

        ref["inventory_path"] = entry["path"] if entry else None
        ref["candidate_match"] = bool(entry and ref["stage"] in {"FDL1", "FDL2"})
        ref["role_match"] = bool(
            ref["candidate_match"]
            and (ref["filename_role"] is None or ref["filename_role"] == ref["stage"])
        )
        ref["structural_issue"] = entry["structural_issue"] if entry else None

    # Infer a role from explicit settings metadata only for a generic filename
    # referenced by exactly one stage. Never overwrite a contradictory filename.
    references_by_path: dict[str, list[dict[str, Any]]] = {}
    for ref in references:
        if ref["candidate_match"]:
            references_by_path.setdefault(ref["resolved_path"], []).append(ref)
    for path_references in references_by_path.values():
        stages = {ref["stage"] for ref in path_references if ref["stage"] in {"FDL1", "FDL2"}}
        if len(stages) == 1:
            ref = next(ref for ref in path_references if ref["stage"] in stages)
            entry = inventory_by_abs[str(Path(ref["resolved_path"]).resolve())]
            if ref["filename_role"] is None and next(iter(stages)) not in entry["candidate_roles"]:
                entry["candidate_roles"].append(next(iter(stages)))

    profile_text = " ".join([str(settings_path), str(loader_dir), *[ref["section"] for ref in references]])
    profile_mentions: list[str] = []
    # Also preserve every matching literal in the settings content.
    if parser is not None:
        raw = settings_path.read_text(encoding="utf-8-sig", errors="replace")
        profile_text = f"{profile_text} {raw}"
    for profile in ("ZTE/Z2352N", "ZTE/8150N"):
        family, model = profile.lower().split("/")
        if family in profile_text.lower() and model in profile_text.lower() and profile not in profile_mentions:
            profile_mentions.append(profile)

    evidence_issues: list[dict[str, Any]] = []
    for issue in settings_issues:
        evidence_issues.append({"type": "settings_error", "message": issue})
    for ref in references:
        if ref["stage"] == "ambiguous":
            evidence_issues.append({
                "type": "ambiguous_reference",
                "section": ref["section"],
                "key": ref["key"],
                "value": ref["value"],
            })
        elif ref["stage"] in {"FDL1", "FDL2"}:
            if not ref["exists"]:
                evidence_issues.append({
                    "type": "missing_reference_file",
                    "stage": ref["stage"],
                    "path": ref["resolved_path"],
                })
            elif not ref["candidate_match"]:
                evidence_issues.append({
                    "type": "unresolved_reference",
                    "stage": ref["stage"],
                    "path": ref["resolved_path"],
                    "message": "The referenced file is outside the inventoried loader directory or could not be inventoried.",
                })
            elif not ref["role_match"]:
                evidence_issues.append({
                    "type": "role_mismatch",
                    "stage": ref["stage"],
                    "filename_role": ref["filename_role"],
                    "path": ref["resolved_path"],
                })

    for stage in ("FDL1", "FDL2"):
        stage_references = [ref for ref in references if ref["stage"] == stage]
        target_paths = {ref["resolved_path"] for ref in stage_references if ref["candidate_match"]}
        if not stage_references:
            evidence_issues.append({"type": "missing_stage_reference", "stage": stage})
        elif len(target_paths) > 1:
            evidence_issues.append({
                "type": "multiple_files_for_stage",
                "stage": stage,
                "paths": sorted(target_paths),
            })

    for path, path_references in references_by_path.items():
        stages = sorted({ref["stage"] for ref in path_references if ref["stage"] in {"FDL1", "FDL2"}})
        if len(stages) > 1:
            evidence_issues.append({"type": "same_file_for_multiple_stages", "stages": stages, "path": path})

    # A definite defect in an explicitly referenced required file is the only
    # condition that outranks incomplete or contradictory reference metadata.
    structurally_invalid_required = any(
        ref["candidate_match"] and ref["stage"] in {"FDL1", "FDL2"} and ref["structural_issue"]
        for ref in references
    )
    if structurally_invalid_required:
        status = "structurally incompatible"
    elif evidence_issues:
        status = "insufficient evidence"
    else:
        status = "unverified"

    return {
        "schema_version": 1,
        "purpose": "offline inventory only; no loader is declared compatible",
        "target": EXPECTED_DEVICE,
        "settings_ini": str(settings_path),
        "loader_directory": str(loader_dir),
        "settings_issues": settings_issues,
        "evidence_issues": evidence_issues,
        "profiles_referenced": profile_mentions,
        "files": files,
        "settings_references": references,
        "loader_addresses": _addresses(parser),
        "compatibility_status": status,
        "compatibility_limit": "SoC match, filename, profile label, binary appearance, and address metadata do not prove device compatibility or successful initialization.",
    }


CLASSIFICATION_HINTS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("security_or_authentication_rejection", re.compile(r"signature.{0,30}(?:reject|invalid|fail)|auth(?:entication)?\s*(?:reject|fail)|secure boot.{0,30}(?:reject|fail)|verification failed", re.IGNORECASE), "An explicit security/authentication rejection phrase is present."),
    ("loader_format_mismatch", re.compile(r"(?:invalid|unsupported|bad|unknown).{0,24}(?:loader|fdl|image).{0,24}(?:format|header)|(?:format|header).{0,24}(?:invalid|unsupported|bad)", re.IGNORECASE), "The log explicitly mentions an invalid or unsupported loader/image format."),
    ("fdl2_incompatible_partition", re.compile(r"fdl\s*2\s*:?\s*incompatible\s+partition", re.IGNORECASE), "The log reports FDL2's incompatible-partition response; this does not establish storage access or loader compatibility."),
    ("fdl2_initialization_failure", re.compile(r"fdl\s*2.{0,60}(?:init(?:ializ\w*)?|dram|nand|storage).{0,40}(?:fail|error|timeout)|(?:init(?:ializ\w*)?|dram|nand|storage).{0,40}(?:fail|error|timeout).{0,60}fdl\s*2", re.IGNORECASE), "The log associates an initialization-related failure with FDL2."),
    ("check_baud_timeout", re.compile(r"check[_ ]?baud.{0,80}(?:timeout|timed out|no response|no reply)|(?:timeout|timed out|no response|no reply).{0,80}check[_ ]?baud", re.IGNORECASE), "CHECK_BAUD did not receive an observed response; this alone does not identify why."),
    ("usb_transport_timeout", re.compile(r"(?:usb|libusb|bulk transfer|read|write).{0,60}(?:timeout|timed out)|(?:timeout|timed out).{0,60}(?:usb|libusb|bulk transfer)", re.IGNORECASE), "A USB/read/write timeout is present; this does not identify whether enumeration, cabling, host setup, or device state caused it."),
    ("transport_failure", re.compile(r"(?:no device|device not found|permission denied|failed to open usb|failed to claim|disconnect(?:ed)?|i/o error)", re.IGNORECASE), "A transport or device-access error is present."),
)


def classify_log(text: str) -> dict[str, Any]:
    matches = [{"classification": name, "observation": description} for name, pattern, description in CLASSIFICATION_HINTS if pattern.search(text)]
    if not matches:
        matches = [{"classification": "unclassified", "observation": "No supported diagnostic phrase was recognized."}]
    if any(item["classification"] == "check_baud_timeout" for item in matches):
        matches.append({"classification": "root_cause_undetermined", "observation": "A CHECK_BAUD timeout is not evidence by itself of a signature or authentication failure."})
    return {"matches": matches, "conclusive_root_cause": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("inventory", help="inventory an external loader directory against settings.ini")
    inventory.add_argument("--loader-dir", required=True, type=Path)
    inventory.add_argument("--settings", required=True, type=Path)
    inventory.add_argument("--json", action="store_true", help="emit the report as JSON")
    classify = sub.add_parser("classify-log", help="classify diagnostic text without claiming a root cause")
    classify.add_argument("log", nargs="?", type=Path, help="log path; read stdin when omitted")
    classify.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)
    if args.command == "inventory":
        report = analyze(args.loader_dir, args.settings)
    else:
        try:
            log_text = args.log.read_text(encoding="utf-8", errors="replace") if args.log else sys.stdin.read()
        except OSError as exc:
            parser.error(str(exc))
        report = classify_log(log_text)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if args.command == "inventory":
            print(f"Compatibility status: {report['compatibility_status']}")
            print(f"Target: {report['target']['model']} / {report['target']['platform']} / {report['target']['soc']}")
            for item in report["files"]:
                roles = ", ".join(item["candidate_roles"]) or "unclassified file"
                print(f"{item['path']}: {roles}; {item['size_bytes']} bytes; SHA-256 {item['sha256']}")
            for stage, detail in report["loader_addresses"].items():
                print(f"{stage} addresses: {detail['known'] or 'unknown'}")
            print(report["compatibility_limit"])
        else:
            for item in report["matches"]:
                print(f"{item['classification']}: {item['observation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
