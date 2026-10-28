"""Offline inventory and diagnostic classification for externally supplied FDLs.

This module intentionally never connects to a device and never modifies inputs.
It reports structural observations only; it cannot establish loader compatibility.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
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
    text: str,
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
            is_pathish = bool(value_role) or bool(re.search(r"\.(?:bin|fdl|elf|img|pac)$", value_clean, re.IGNORECASE))
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
                "resolved_path": str(resolved),
                "exists": resolved.is_file(),
            })

    # Retain profile/device references as metadata without guessing their meaning.
    _ = text
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

    references = _references(parser, "", loader_dir, settings_path)
    # Resolve references to inventory entries and expose a candidate match when unambiguous.
    inventory_by_abs = {str((loader_dir / item["path"]).resolve()): item for item in files}
    for ref in references:
        entry = inventory_by_abs.get(str(Path(ref["resolved_path"]).resolve()))
        ref["inventory_path"] = entry["path"] if entry else None
        ref["candidate_match"] = bool(entry and ref["stage"] in {"FDL1", "FDL2"})
        if ref["candidate_match"] and ref["stage"] not in entry["candidate_roles"]:
            entry["candidate_roles"].append(ref["stage"])

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

    referenced_missing = any(not ref["exists"] for ref in references)
    ambiguous = any(ref["stage"] == "ambiguous" for ref in references)
    malformed = bool(settings_issues)
    structural_bad = any(item["structural_issue"] for item in files if item["candidate_roles"])
    has_fdl1 = any("FDL1" in item["candidate_roles"] and not item["structural_issue"] for item in files)
    has_fdl2 = any("FDL2" in item["candidate_roles"] and not item["structural_issue"] for item in files)
    linked_roles = {ref["stage"] for ref in references if ref["candidate_match"] and ref["stage"] in {"FDL1", "FDL2"}}
    if structural_bad and not (has_fdl1 and has_fdl2):
        status = "structurally incompatible"
    elif malformed or referenced_missing or ambiguous or not (has_fdl1 and has_fdl2) or linked_roles and linked_roles != {"FDL1", "FDL2"}:
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
