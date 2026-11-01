"""P005: read-only Z2352N U-Boot lock/fastboot static evidence collector.

This tool does not identify function boundaries or establish unlock viability.
It does not modify firmware or send any commands to a device.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

from tools.inspect_uboot_ums9620 import InspectionError, inspect_bytes

DEFAULT_WINDOWS = {
    "lock_state_decision": (0xB4A0, 0x120),
    "skip_verify_jump_table": (0xB740, 0x120),
    "fastboot_unlock_dispatch": (0x125C0, 0x380),
    "compare_helper_candidate": (0x36D40, 0x100),
    "androidboot_flash_locked": (0x3A500, 0x100),
}
DEFAULT_CALL_TARGETS = {
    "string_compare_candidate": 0x36D78,
    "message_output_candidate": 0x35E0C,
    "secondary_message_candidate": 0x87F4C,
    "delay_candidate": 0xB364,
}
EXPECTED_Z2352N_UBOOT_SHA256 = (
    "030a0e3ef446360bdb5b7c43ff7d57c311cf83f6c63db3c5c67ccd64e39080aa"
)
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_WINDOW_BYTES = 0x4000
MAX_WINDOWS = 16
MAX_TARGETS = 16
MAX_CALLERS_PER_TARGET = 100


def scan_direct_bl(payload: bytes, targets: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Find 4-byte-aligned AArch64 BL encodings (syntactic candidates only)."""
    matches = {name: [] for name in targets}
    target_to_names: dict[int, list[str]] = {}
    for name, target in targets.items():
        target_to_names.setdefault(target, []).append(name)
    totals = {name: 0 for name in targets}
    for off in range(0, len(payload) - 3, 4):
        word = struct.unpack_from("<I", payload, off)[0]
        if word & 0xFC000000 != 0x94000000:
            continue
        imm26 = word & 0x03FFFFFF
        if imm26 & (1 << 25):
            imm26 -= 1 << 26
        destination = off + imm26 * 4
        for name in target_to_names.get(destination, ()):
            totals[name] += 1
            if len(matches[name]) < MAX_CALLERS_PER_TARGET:
                matches[name].append(f"0x{off:x}")
    return {
        name: {
            "target_payload_offset": f"0x{target:x}",
            "total_syntactic_bl_matches": totals[name],
            "caller_payload_offsets": matches[name],
            "results_truncated": totals[name] > MAX_CALLERS_PER_TARGET,
            "confidence": "candidate_only_code_data_not_distinguished",
        }
        for name, target in targets.items()
    }


def analyze_image(
    data: bytes,
    *,
    windows: dict[str, tuple[int, int]] | None = None,
    targets: dict[str, int] | None = None,
) -> dict[str, Any]:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds offline size limit")
    parsed = inspect_bytes(data)
    if not parsed["dhtb"]["payload_hash_matches_header"]:
        raise ValueError("DHTB payload hash mismatch; analysis blocked")
    payload_start = parsed["dhtb"]["payload_start"]
    payload_size = parsed["dhtb"]["payload_size"]
    payload = data[payload_start:payload_start + payload_size]
    selected_windows = DEFAULT_WINDOWS if windows is None else windows
    selected_targets = DEFAULT_CALL_TARGETS if targets is None else targets
    if len(selected_windows) > MAX_WINDOWS or len(selected_targets) > MAX_TARGETS:
        raise ValueError("too many windows or targets")
    from tools.aarch64_semantics import disassemble

    window_reports = {}
    for name, (start, length) in selected_windows.items():
        if (
            not name or start < 0 or length <= 0 or start % 4 or length % 4
            or length > MAX_WINDOW_BYTES or start + length > len(payload)
        ):
            raise ValueError(f"invalid bounded code window {name!r}")
        instructions = disassemble(
            payload, start, length, payload_file_offset=payload_start,
            max_instructions=MAX_WINDOW_BYTES // 4,
            max_bytes=MAX_WINDOW_BYTES,
        )
        window_reports[name] = {
            "start_payload_offset": f"0x{start:x}",
            "end_payload_offset_exclusive": f"0x{start + length:x}",
            "instructions": [
                {
                    "payload_offset": f"0x{ins['payload_offset']:x}",
                    "file_offset": f"0x{ins['file_offset']:x}",
                    "mnemonic": ins["mnemonic"],
                    "operands": ins["operands"],
                    "classification": ins["classification"],
                    "branch_target_payload_offset": (
                        None if ins["direct_target_payload_offset"] is None
                        else f"0x{ins['direct_target_payload_offset']:x}"
                    ),
                    "registers_read": ins["registers_read"],
                    "registers_written": ins["registers_written"],
                }
                for ins in instructions
            ],
        }
    if any(addr < 0 or addr >= len(payload) or addr % 4 for addr in selected_targets.values()):
        raise ValueError("caller scan target outside payload or unaligned")
    return {
        "schema": "unisoc-z2352n-unlock-trace/v1",
        "ok": True,
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "dhtb_payload_hash_matches": True,
        "payload_size": payload_size,
        "load_base": None,
        "windows": window_reports,
        "direct_bl_caller_candidates": scan_direct_bl(payload, selected_targets),
        "limitations": [
            "All offsets are payload-relative unless marked file_offset.",
            "Windows are analyst-selected and not validated function boundaries.",
            "A syntactically valid BL can occur in data; no executable region proof.",
            "Disassembly is static; indirect targets and jump table entries unresolved.",
            "No bootloader unlockability, secure boot bypass, or signature validity established.",
            "Read-only: input image is never modified or executed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument(
        "--expected-sha256", default=EXPECTED_Z2352N_UBOOT_SHA256,
        help="expected original image SHA-256; pass 'none' for synthetic fixtures",
    )
    args = parser.parse_args(argv)
    try:
        if args.image.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("input exceeds offline size limit")
        data = args.image.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if args.expected_sha256.lower() != "none" and digest != args.expected_sha256.lower():
            raise ValueError("image SHA-256 differs from expected Z2352N OTA U-Boot")
        report = analyze_image(data)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, InspectionError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
