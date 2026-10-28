#!/usr/bin/env python3
"""Read-only structural inspector for a raw UMS9620-family U-Boot dump.

This tool reports observations, not device compatibility or patch readiness. It
never writes to its input or emits a modified image. No UMS9620/Nubia offsets
or load address are assumed; instruction offsets and a load base are optional
operator-supplied values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

DHTB_MAGIC = b"DHTB"
HEADER_SIZE = 0x200
SIMGHDR_MAGIC = b"SIMGHDR\x00"
ANBERNIC_FOOTER_SIZE = 0x60
CLASSIC_SIMGHDR_SIZE = 0x494
MAX_DISASSEMBLY_WORDS = 256


class InspectionError(ValueError):
    """Raised when an input cannot be safely interpreted as this image layout."""


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise InspectionError(f"32-bit field at 0x{offset:x} is out of bounds")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise InspectionError(f"64-bit field at 0x{offset:x} is out of bounds")
    return struct.unpack_from("<Q", data, offset)[0]


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_aarch64(word: int, pc: int | None = None) -> str:
    """Decode a small, explicit subset of AArch64 instructions; unknown words stay raw."""
    if word == 0xD503201F:
        return "nop"
    if word & 0x7C000000 == 0x14000000:
        name = "bl" if word & 0x80000000 else "b"
        delta = _sign_extend(word & 0x03FFFFFF, 26) << 2
        return f"{name} 0x{pc + delta:x}" if pc is not None else f"{name} {delta:+#x}"
    if word & 0xFF000010 == 0x54000000:
        cond = word & 0xF
        names = ("eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                 "hi", "ls", "ge", "lt", "gt", "le", "al", "nv")
        delta = _sign_extend((word >> 5) & 0x7FFFF, 19) << 2
        dest = f"0x{pc + delta:x}" if pc is not None else f"{delta:+#x}"
        return f"b.{names[cond]} {dest}"
    if word & 0x7E000000 == 0x34000000:
        is_64 = bool(word & 0x80000000)
        nonzero = bool(word & 0x01000000)
        reg = word & 0x1F
        delta = _sign_extend((word >> 5) & 0x7FFFF, 19) << 2
        dest = f"0x{pc + delta:x}" if pc is not None else f"{delta:+#x}"
        return f"{'cbnz' if nonzero else 'cbz'} {'x' if is_64 else 'w'}{reg}, {dest}"
    if word & 0xFFFFFC1F == 0xD65F0000:
        reg = (word >> 5) & 0x1F
        return "ret" if reg == 30 else f"ret x{reg}"
    if word & 0xFFFFFC1F == 0xD61F0000:
        return f"br x{(word >> 5) & 0x1F}"
    return f".word 0x{word:08x}"


def _parse_footer(data: bytes, offset: int, payload_size: int,
                  dhtb_hash: bytes) -> dict[str, Any]:
    if offset < HEADER_SIZE or offset > len(data):
        raise InspectionError("SIMGHDR offset is outside the input image")
    if offset + 8 > len(data) or data[offset:offset + 7] != b"SIMGHDR":
        raise InspectionError(f"SIMGHDR marker missing at declared payload end 0x{offset:x}")

    classic_marker = data[offset:offset + 8] == SIMGHDR_MAGIC
    if classic_marker and offset + 0x30 <= len(data):
        classic_data_size = _u64(data, offset + 0x10)
        classic_header_size = _u64(data, offset + 0x18)
        classic_struct_size = _u64(data, offset + 0x20)

        # The classic structure is identified by its own size fields, never by
        # how much partition padding happens to follow the footer. Individual
        # classic markers also make a malformed candidate fail closed instead
        # of falling back to the shorter vendor interpretation.
        classic_candidate = (
            classic_struct_size == 0x254
            or classic_data_size == payload_size
            or (classic_data_size != 0 and classic_header_size == HEADER_SIZE)
        )
    else:
        classic_data_size = classic_header_size = classic_struct_size = None
        classic_candidate = False

    if classic_marker and classic_candidate:
        if classic_data_size != payload_size:
            raise InspectionError("DHTB and classic SIMGHDR payload sizes disagree")
        if classic_header_size != HEADER_SIZE:
            raise InspectionError("classic SIMGHDR header_size is not 0x200")
        if classic_struct_size != 0x254:
            raise InspectionError("classic SIMGHDR signature_structure_size is not 0x254")
        if offset + CLASSIC_SIMGHDR_SIZE > len(data):
            raise InspectionError("classic 0x494-byte SIMGHDR extends past end of file")

        block = data[offset:offset + CLASSIC_SIMGHDR_SIZE]
        exponent = struct.unpack_from(">I", block, 0x68)[0]
        data_hash_copy = block[0x16C:0x18C]
        if exponent != 0x10001:
            raise InspectionError("classic SIMGHDR RSA exponent is not 65537")
        if data_hash_copy != dhtb_hash:
            raise InspectionError("classic SIMGHDR payload hash does not match DHTB hash")
        return {
            "layout": "classic_0x494",
            "size": CLASSIC_SIMGHDR_SIZE,
            "declared_payload_size": _u64(block, 0x10),
            "header_size": _u64(block, 0x18),
            "signature_structure_size": _u64(block, 0x20),
            "total_offset": _u64(block, 0x28),
            "exponent": exponent,
            "data_hash_copy": data_hash_copy.hex(),
            "signature_present": any(block[0x1B4:0x2B4]),
            "signature_verified": False,
        }

    if offset + ANBERNIC_FOOTER_SIZE > len(data):
        raise InspectionError("0x60-byte SIMGHDR footer extends past end of file")
    footer = data[offset:offset + ANBERNIC_FOOTER_SIZE]
    return {
        "layout": "sprd_signed_image_footer_0x60_unisoc_vendor_layout",
        "size": ANBERNIC_FOOTER_SIZE,
        "payload_offset": _u64(footer, 0x18),
        "offset_fields": {
            f"0x{field:02x}": _u64(footer, field)
            for field in (0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58)
        },
        "signature_verified": False,
    }


def inspect_bytes(data: bytes, *, partition_size: int | None = None,
                  code_ranges: list[tuple[int, int]] | None = None,
                  load_base: int | None = None) -> dict[str, Any]:
    """Inspect bytes in memory without modifying them."""
    if len(data) < HEADER_SIZE:
        raise InspectionError(f"file is shorter than the 0x{HEADER_SIZE:x}-byte DHTB header")
    if data[:4] != DHTB_MAGIC:
        raise InspectionError("input does not start with DHTB magic")
    if partition_size is not None and partition_size <= 0:
        raise InspectionError("partition size must be a positive integer")
    if load_base is not None and not 0 <= load_base <= 0xFFFFFFFFFFFFFFFF:
        raise InspectionError("load base must fit an unsigned 64-bit address")
    if partition_size is not None and len(data) > partition_size:
        raise InspectionError(
            f"file size 0x{len(data):x} exceeds supplied partition size 0x{partition_size:x}"
        )

    version = _u32(data, 4)
    if version != 1:
        raise InspectionError(f"unsupported DHTB version {version}; expected 1")
    stored_hash = data[8:0x28]
    payload_size = _u32(data, 0x30)
    payload_start = HEADER_SIZE
    payload_end = payload_start + payload_size
    if payload_size == 0:
        raise InspectionError("declared payload size is zero")
    if payload_end < payload_start or payload_end > len(data):
        raise InspectionError(
            f"declared payload [0x{payload_start:x}, 0x{payload_end:x}) exceeds file size 0x{len(data):x}"
        )

    footer = _parse_footer(data, payload_end, payload_size, stored_hash)
    footer_end = payload_end + footer["size"]
    if footer_end > len(data):
        raise InspectionError("declared payload and SIMGHDR exceed file bounds")
    if footer["layout"] == "classic_0x494":
        if footer["declared_payload_size"] != payload_size:
            raise InspectionError("DHTB and classic SIMGHDR payload sizes disagree")
        if footer["header_size"] != HEADER_SIZE:
            raise InspectionError("classic SIMGHDR header_size is not 0x200")
    else:
        payload_offset = footer["payload_offset"]
        if payload_offset not in (HEADER_SIZE, HEADER_SIZE + 0x10):
            raise InspectionError(
                f"unsupported vendor footer payload_offset 0x{payload_offset:x}"
            )

    payload = data[payload_start:payload_end]
    computed_hash = hashlib.sha256(payload).hexdigest()
    expected_partition_end = partition_size if partition_size is not None else None
    partition_bounds_ok = None
    if partition_size is not None:
        partition_bounds_ok = footer_end <= partition_size
        if not partition_bounds_ok:
            raise InspectionError(
                f"payload plus footer ends at 0x{footer_end:x}, beyond partition size 0x{partition_size:x}"
            )

    instructions: list[dict[str, Any]] = []
    for start, count in code_ranges or []:
        if start < 0 or count <= 0 or count > MAX_DISASSEMBLY_WORDS:
            raise InspectionError(
                f"instruction range must have a nonnegative offset and 1..{MAX_DISASSEMBLY_WORDS} words"
            )
        if start % 4:
            raise InspectionError(f"payload code offset 0x{start:x} is not 4-byte aligned")
        if start + count * 4 > payload_size:
            raise InspectionError(f"instruction range at 0x{start:x} exceeds declared payload")
        for index in range(count):
            code_offset = start + index * 4
            file_offset = payload_start + code_offset
            word = _u32(data, file_offset)
            pc = load_base + code_offset if load_base is not None else None
            instructions.append({
                "payload_offset": code_offset,
                "file_offset": file_offset,
                "runtime_address": pc,
                "word_le": f"0x{word:08x}",
                "assembly_subset": decode_aarch64(word, pc),
            })

    return {
        "schema": "unisoc-uboot-inspection/v1",
        "input": {
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "target": {
            "device": "nubia Neo 2 5G",
            "model": "Z2352N",
            "board": "P820F03",
            "soc": "UNISOC T820 / UMS9620",
            "offset_compatibility": "unverified; no Nubia offsets are assumed",
            "boot_chain_compatibility": "not established by SoC or header similarity",
        },
        "dhtb": {
            "magic": "DHTB",
            "version": version,
            "header_size": HEADER_SIZE,
            "payload_size": payload_size,
            "payload_start": payload_start,
            "payload_end": payload_end,
            "stored_payload_sha256": stored_hash.hex(),
            "computed_payload_sha256": computed_hash,
            "payload_hash_matches_header": stored_hash.hex() == computed_hash,
            "size_field_interpretation": "little-endian 32-bit mImgSize at file offset 0x30",
        },
        "simghdr": {
            "file_offset": payload_end,
            **footer,
        },
        "partition": {
            "size_bytes": expected_partition_end,
            "file_fits": True if partition_size is not None else None,
            "declared_payload_and_footer_fit": partition_bounds_ok,
            "file_equals_partition_size": len(data) == partition_size if partition_size is not None else None,
        },
        "load_base": f"0x{load_base:x}" if load_base is not None else None,
        "aarch64_instructions": instructions,
        "interpretation_limits": [
            "A valid structure or hash is not proof that SPL accepts this image.",
            "Signature presence is reported only; RSA signature verification is not performed.",
            "No Nubia Z2352N load base, offsets, partition size, or boot-chain behavior is known here.",
            "Instruction decoding covers a small AArch64 subset; unrecognized words remain raw .word values.",
        ],
    }


def _parse_code_range(value: str) -> tuple[int, int]:
    offset_text, separator, count_text = value.partition(":")
    try:
        return int(offset_text, 0), int(count_text, 0) if separator else 1
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected OFFSET[:WORD_COUNT] in decimal or 0x-prefixed form") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="raw U-Boot dump to inspect (opened read-only)")
    parser.add_argument("--partition-size", type=lambda v: int(v, 0),
                        help="known partition size in bytes (decimal or 0x-prefixed); no device default")
    parser.add_argument("--load-base", type=lambda v: int(v, 0),
                        help="externally established runtime load base; no platform default")
    parser.add_argument("--disasm", action="append", type=_parse_code_range, default=[],
                        metavar="OFFSET[:WORDS]",
                        help="decode AArch64 words at payload-relative offset(s), up to 256 per range")
    args = parser.parse_args(argv)
    try:
        with args.image.open("rb") as image_file:
            image_data = image_file.read()
        report = inspect_bytes(image_data, partition_size=args.partition_size,
                               code_ranges=args.disasm, load_base=args.load_base)
    except (OSError, InspectionError) as exc:
        print(json.dumps({
            "schema": "unisoc-uboot-inspection/v1",
            "ok": False,
            "error": str(exc),
            "input_path": str(args.image),
        }, indent=2))
        return 2
    report["ok"] = True
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
