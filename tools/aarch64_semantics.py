"""Read-only, bounded AArch64 semantic observations for explicit code ranges."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_OP_IMM

from tools.inspect_uboot_ums9620 import InspectionError, inspect_bytes

SCHEMA = "unisoc-aarch64-semantics/v1"
MAX_U64 = (1 << 64) - 1
MAX_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_LIMITS = {"bytes": 1 << 20, "instructions": 65536, "blocks": 4096,
                  "edges": 16384, "entries": 256, "work": 65536}


def _runtime(base: int | None, payload_offset: int) -> int | None:
    if base is None:
        return None
    value = base + payload_offset
    if not 0 <= value <= MAX_U64:
        raise ValueError("runtime address exceeds unsigned 64-bit bounds")
    return value


def _kind(insn: Any) -> str:
    m = insn.mnemonic.lower()
    direct = {"b": "branch", "bl": "call", "br": "indirect_branch",
              "blr": "indirect_call", "ret": "return"}
    if m in direct:
        return direct[m]
    if m in {"retaa", "retab"}:
        return "return"
    if m in {"braa", "brab", "braaz", "brabz"}:
        return "indirect_branch"
    if m in {"blraa", "blrab", "blraaz", "blrabz"}:
        return "indirect_call"
    if m.startswith("b.") or m in {"cbz", "cbnz", "tbz", "tbnz"}:
        return "conditional_branch"
    if m in {"eret", "eretaa", "eretab", "drps", "brk", "hlt", "svc",
             "hvc", "smc", "dcps1", "dcps2", "dcps3", "udf"}:
        # Exception/privilege transfers have no proven sequential successor.
        return "unsupported_control_transfer"
    return "ordinary"


def disassemble(code: bytes, start: int, length: int, *, payload_file_offset: int = 0,
                load_base: int | None = None, max_instructions: int = 65536,
                max_bytes: int = DEFAULT_LIMITS["bytes"]) -> list[dict[str, Any]]:
    """Decode a supplied bounded byte range. Offsets refer to the input buffer."""
    if not isinstance(code, bytes):
        raise TypeError("code must be immutable bytes")
    if start < 0 or length < 0 or start % 4 or length % 4 or payload_file_offset < 0:
        raise ValueError("offsets and length must be nonnegative and four-byte aligned")
    if max_bytes <= 0 or max_instructions <= 0:
        raise ValueError("resource limits must be positive")
    if length > max_bytes or start > len(code) or length > len(code) - start:
        raise ValueError("range exceeds buffer or byte limit")
    if length // 4 > max_instructions:
        raise ValueError("instruction limit exceeded")
    if load_base is not None and (not 0 <= load_base <= MAX_U64 or
            (length and load_base + start + length - 1 > MAX_U64)):
        raise ValueError("runtime address range exceeds unsigned 64-bit bounds")
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    result = []
    for offset in range(start, start + length, 4):
        raw = code[offset:offset + 4]
        p = offset
        file_offset = payload_file_offset + p
        pc = _runtime(load_base, p)
        insn = next(decoder.disasm(raw, pc if pc is not None else p, count=1), None)
        target = None
        kind = "unknown"
        if insn:
            kind = _kind(insn)
            if kind in {"branch", "call", "conditional_branch"} and insn.operands:
                immediates = [op for op in insn.operands if op.type == ARM64_OP_IMM]
                if immediates:
                    target = int(immediates[-1].imm)
                if load_base is not None and target is not None:
                    target -= load_base
        fallthrough = None if not insn else kind not in {
            "branch", "return", "indirect_branch", "unsupported_control_transfer"
        }
        result.append({"file_offset": file_offset, "payload_offset": p,
            "runtime_address": pc, "raw_word": f"0x{int.from_bytes(raw, 'little'):08x}",
            "bytes": raw.hex(), "mnemonic": insn.mnemonic if insn else None,
            "operands": insn.op_str if insn else None, "instruction_id": insn.id if insn else None,
            "classification": kind, "direct_target_payload_offset": target,
            "registers_read": [insn.reg_name(r) for r in insn.regs_access()[0]] if insn else [],
            "registers_written": [insn.reg_name(r) for r in insn.regs_access()[1]] if insn else [],
            "fallthrough": fallthrough,
            "unresolved_target": kind in {"indirect_branch", "indirect_call"} or insn is None})
    return result


def analyze(code: bytes, *, file_sha256: str, payload_file_offset: int,
            ranges: list[tuple[int, int]], entries: list[int], load_base: int | None = None,
            limits: dict[str, int] | None = None, hash_scope: str = "analysis buffer") -> dict[str, Any]:
    """Build bounded disassembly, CFG, direct XREFs, and conservative candidates.

    Ranges are (payload-relative start, byte length), and entries are payload offsets.
    """
    lim = dict(DEFAULT_LIMITS)
    if limits:
        if set(limits) - set(lim) or any(v <= 0 for v in limits.values()):
            raise ValueError("limits must be positive known resource limits")
        lim.update(limits)
    if not isinstance(code, bytes) or payload_file_offset < 0:
        raise ValueError("immutable code bytes and valid payload file offset required")
    if len(entries) > lim["entries"] or not entries:
        raise ValueError("entry count must be 1..entry limit")
    if load_base is not None and not 0 <= load_base <= MAX_U64:
        raise ValueError("load base must fit unsigned 64-bit bounds")
    instructions: dict[int, dict[str, Any]] = {}
    range_reports = []
    total = 0
    prior_end = -1
    for start, size in sorted(ranges):
        if start < 0 or size <= 0 or start % 4 or size % 4 or start > len(code) or size > len(code) - start:
            raise ValueError("code ranges must be aligned, positive, and contained in payload")
        if start < prior_end:
            raise ValueError("code ranges must not overlap")
        prior_end = start + size
        total += size
        if total > lim["bytes"]:
            raise ValueError("total byte limit exceeded")
        ins = disassemble(code, start, size, payload_file_offset=payload_file_offset,
                          load_base=load_base, max_instructions=lim["instructions"],
                          max_bytes=lim["bytes"])
        if len(instructions) + len(ins) > lim["instructions"]:
            raise ValueError("instruction limit exceeded")
        instructions.update({i["payload_offset"]: i for i in ins})
        range_reports.append({"start_payload_offset": start, "end_payload_offset": start + size,
                              "length": size})
    if any(e not in instructions for e in entries):
        raise ValueError("each entry must point to a decoded instruction")

    # Split linear decoded ranges at entries, internal branch targets, and after terminators.
    leaders = set(entries)
    incoming: dict[int, set[str]] = {}
    for off, ins in instructions.items():
        dest = ins["direct_target_payload_offset"]
        if dest is not None:
            if dest in instructions:
                leaders.add(dest)
            else:
                incoming.setdefault(dest, set()).add("external")
        if ins["classification"] in {"branch", "conditional_branch", "call", "return",
                                     "indirect_branch", "indirect_call", "unknown",
                                     "unsupported_control_transfer"}:
            nxt = off + 4
            if nxt in instructions:
                leaders.add(nxt)
    sorted_offsets = sorted(instructions)
    blocks: list[dict[str, Any]] = []
    current = []
    for off in sorted_offsets:
        if current and (off in leaders or off != current[-1] + 4):
            blocks.append({"start": current[0], "instructions": current}); current = []
        current.append(off)
    if current:
        blocks.append({"start": current[0], "instructions": current})
    if len(blocks) > lim["blocks"]:
        raise ValueError("basic block limit exceeded")
    by_start = {b["start"]: b for b in blocks}
    block_for = {o: b["start"] for b in blocks for o in b["instructions"]}
    edges = []
    xrefs = []
    unresolved = []

    def edge(src: int, dst: int | None, typ: str, status: str):
        dest_block = dst if dst in by_start else None
        edges.append({"source_block": src, "destination_payload_offset": dst,
                      "destination_block": dest_block,
                      "type": typ, "resolution": status})

    for b in blocks:
        lastoff = b["instructions"][-1]
        ins = instructions[lastoff]
        k, dest = ins["classification"], ins["direct_target_payload_offset"]
        nextoff = lastoff + 4
        if k in {"branch", "conditional_branch", "call"}:
            typ = {"branch": "unconditional_branch", "call": "direct_call",
                   "conditional_branch": "conditional_taken"}[k]
            status = "internal" if dest in instructions else "external_or_out_of_range"
            edge(b["start"], dest, typ, status)
            if dest is not None:
                xrefs.append(_xref(ins, typ, dest, status))
            if k in {"conditional_branch", "call"}:
                status_next = "internal" if nextoff in instructions else "external_or_out_of_range"
                edge(b["start"], nextoff, "conditional_fallthrough" if k == "conditional_branch" else "call_continuation", status_next)
                xrefs.append(_xref(ins, "fallthrough", nextoff, status_next))
        elif k == "return":
            edge(b["start"], None, "return", "terminal")
        elif k in {"indirect_branch", "indirect_call"}:
            typ = "indirect_transfer_unresolved"
            edge(b["start"], None, typ, "unresolved")
            unresolved.append({"source_payload_offset": lastoff, "type": typ, "reason": "register target not propagated"})
            xrefs.append(_xref(ins, typ, None, "unresolved"))
            if k == "indirect_call":
                status_next = "internal" if nextoff in instructions else "external_or_out_of_range"
                edge(b["start"], nextoff, "call_continuation", status_next)
                xrefs.append(_xref(ins, "fallthrough", nextoff, status_next))
        elif k in {"unknown", "unsupported_control_transfer"}:
            edge(b["start"], None, "unresolved_control_flow", "unresolved")
            unresolved.append({"source_payload_offset": lastoff, "type": k,
                               "reason": "instruction semantics or successor not established"})
            xrefs.append(_xref(ins, "unresolved_control_flow", None, "unresolved"))
        elif nextoff in instructions:
            edge(b["start"], nextoff, "fallthrough", "internal")
            xrefs.append(_xref(ins, "fallthrough", nextoff, "internal"))
        else:
            edge(b["start"], nextoff, "range_exit", "external_or_out_of_range")
    if len(edges) > lim["edges"]:
        raise ValueError("edge limit exceeded")

    # Compute actual cycles in the non-call CFG. An address-backward jump,
    # including a BL into an earlier function, is not itself a loop.
    successors = {n: set() for n in by_start}
    predecessors = {n: set() for n in by_start}
    for graph_edge in edges:
        dst = graph_edge["destination_block"]
        src = graph_edge["source_block"]
        if dst is not None and graph_edge["type"] != "direct_call":
            successors[src].add(dst)
            predecessors[dst].add(src)

    visited: set[int] = set()
    finish_order: list[int] = []
    for first in sorted(successors):
        if first in visited:
            continue
        visited.add(first)
        pending_dfs = [(first, iter(sorted(successors[first])))]
        while pending_dfs:
            node, children = pending_dfs[-1]
            child = next(children, None)
            if child is None:
                finish_order.append(node)
                pending_dfs.pop()
            elif child not in visited:
                visited.add(child)
                pending_dfs.append((child, iter(sorted(successors[child]))))

    components: dict[int, int] = {}
    component_sizes: dict[int, int] = {}
    for first in reversed(finish_order):
        if first in components:
            continue
        component = len(component_sizes)
        pending_reverse = [first]
        components[first] = component
        count = 0
        while pending_reverse:
            node = pending_reverse.pop()
            count += 1
            for previous in sorted(predecessors[node]):
                if previous not in components:
                    components[previous] = component
                    pending_reverse.append(previous)
        component_sizes[component] = count

    for graph_edge in edges:
        src, dst = graph_edge["source_block"], graph_edge["destination_block"]
        graph_edge["backward_edge"] = dst is not None and dst <= src
        graph_edge["loop"] = bool(
            dst is not None and graph_edge["type"] != "direct_call"
            and components[src] == components[dst]
            and (component_sizes[components[src]] > 1 or src == dst)
        )
    edges.sort(key=lambda x: (x["source_block"], x["type"], -1 if x["destination_payload_offset"] is None else x["destination_payload_offset"]))
    xrefs.sort(key=lambda x: (x["source_payload_offset"], x["type"], -1 if x["destination_payload_offset"] is None else x["destination_payload_offset"]))

    callers: dict[int, set[int]] = {}
    callees: dict[int, set[int]] = {}
    for off, ins in instructions.items():
        dst = ins["direct_target_payload_offset"]
        if ins["classification"] == "call" and dst in instructions:
            callers.setdefault(dst, set()).add(off)
            callees.setdefault(block_for[off], set()).add(dst)
    roots = sorted(set(entries) | set(callers))
    edges_by_source: dict[int, list[dict[str, Any]]] = {}
    for graph_edge in edges:
        edges_by_source.setdefault(graph_edge["source_block"], []).append(graph_edge)
    candidates = []
    ownership: dict[int, list[int]] = {}
    work = 0
    for idx, root in enumerate(roots):
        pending = [block_for[root]]
        seen = set()
        while pending:
            work += 1
            if work > lim["work"]:
                raise ValueError("CFG traversal work limit exceeded")
            node = pending.pop(0)
            if node in seen:
                continue
            seen.add(node)
            ownership.setdefault(node, []).append(root)
            for e in edges_by_source.get(node, []):
                if e["destination_block"] is not None and e["type"] != "direct_call":
                    pending.append(e["destination_block"])
        own_blocks = sorted(seen)
        returns = [o for n in own_blocks for o in by_start[n]["instructions"] if instructions[o]["classification"] == "return"]
        unresolved_out = [u for u in unresolved if block_for[u["source_payload_offset"]] in seen]
        external_out = [e for e in edges if e["source_block"] in seen and
                        e["resolution"] == "external_or_out_of_range"]
        is_explicit = root in entries
        incomplete = bool(unresolved_out or external_out or not returns)
        if instructions[root]["classification"] == "unknown":
            conf = "UNKNOWN"
        elif incomplete:
            conf = "LOW"
        else:
            conf = "HIGH" if is_explicit else "MEDIUM"
        candidates.append({"id": f"candidate-{idx:04d}", "entry_payload_offset": root,
            "entry_file_offset": payload_file_offset + root, "runtime_entry": _runtime(load_base, root),
            "discovery_reason": "explicit_entry" if is_explicit else "direct_BL_target",
            "reachable_blocks": own_blocks, "direct_callers": sorted(callers.get(root, set())),
            "direct_callees": sorted({d for n in own_blocks for d in callees.get(n, set())}),
            "return_observations": sorted(returns), "unresolved_outgoing_transfers": unresolved_out + external_out,
            "shared_blocks": [], "confidence": conf,
            "limitations": ["static candidate boundary; not a proven complete function"]})
    for c in candidates:
        c["shared_blocks"] = sorted(n for n in c["reachable_blocks"] if len(ownership[n]) > 1)
        if c["shared_blocks"] and c["confidence"] != "UNKNOWN":
            c["confidence"] = "LOW"
    for b in blocks:
        b["end"] = b["instructions"][-1] + 4
        b["file_offset"] = payload_file_offset + b["start"]
        b["runtime_address"] = _runtime(load_base, b["start"])
        b["instruction_count"] = len(b.pop("instructions"))
    evidence = [{"kind": "observation", "source_payload_offset": o,
                 "instruction": i["mnemonic"], "confidence": "HIGH" if i["mnemonic"] else "UNKNOWN"}
                for o, i in sorted(instructions.items())]
    evidence.extend({"kind": "inference", "source_block": e["source_block"],
        "destination_payload_offset": e["destination_payload_offset"], "relationship": e["type"],
        "confidence": "HIGH" if e["resolution"] == "internal" else "LOW",
        "supporting_instruction_offsets": [by_start[e["source_block"]]["end"] - 4],
        "unsupported_assumptions": ["no indirect target propagation"],
        "unresolved_dependencies": [] if e["resolution"] == "internal" else ["destination outside analyzed range"]}
        for e in edges)
    return {"schema": SCHEMA, "input": {"sha256": file_sha256, "hash_scope": hash_scope},
        "configuration": {"ranges": range_reports, "entries": sorted(entries), "limits": lim},
        "address_model": {"payload_file_offset": payload_file_offset,
            "load_base": None if load_base is None else f"0x{load_base:x}",
            "runtime_addresses_are_external": True},
        "code_ranges": range_reports,
        "instructions": [instructions[o] for o in sorted(instructions)],
        "basic_blocks": blocks, "control_flow_edges": edges, "direct_xrefs": xrefs,
        "function_candidates": candidates, "unresolved_references": unresolved,
        "evidence": evidence,
        "limitations": ["Static observations only; no firmware authenticity or device compatibility established.",
            "No data references, indirect-target propagation, or semantic security-function identification.",
            "Explicit code ranges are assumed executable by the analyst; arbitrary payload bytes are not scanned."]}


def _xref(ins: dict[str, Any], typ: str, dest: int | None, status: str) -> dict[str, Any]:
    return {"source_file_offset": ins["file_offset"], "source_payload_offset": ins["payload_offset"],
        "source_runtime_address": ins["runtime_address"], "destination_payload_offset": dest,
        "destination_runtime_address": (
            None if dest is None or ins["runtime_address"] is None or
            not 0 <= ins["runtime_address"] - ins["payload_offset"] + dest <= MAX_U64 else
            ins["runtime_address"] - ins["payload_offset"] + dest),
        "type": typ, "resolution": status, "evidence_origin": "Capstone direct operand or sequential instruction"}


def _parse_range(value: str) -> tuple[int, int]:
    try:
        a, b = value.split(":", 1)
        return int(a, 0), int(b, 0)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("expected PAYLOAD_OFFSET:BYTE_LENGTH") from exc


def _parse_entries(value: str) -> list[int]:
    try:
        return [int(part, 0) for part in value.split(",") if part]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated payload offsets") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="DHTB image, opened read-only")
    parser.add_argument("--range", action="append", required=True, type=_parse_range,
                        metavar="OFFSET:LENGTH", help="explicit payload-relative byte range")
    parser.add_argument("--entry", action="append", required=True, type=_parse_entries,
                        metavar="OFFSET[,OFFSET...]", help="explicit payload-relative entry points")
    parser.add_argument("--load-base", type=lambda v: int(v, 0), help="externally established runtime base")
    for name, value in DEFAULT_LIMITS.items():
        parser.add_argument(f"--max-{name}", type=int, default=value)
    args = parser.parse_args(argv)
    try:
        if args.image.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"input exceeds {MAX_INPUT_BYTES}-byte limit")
        data = args.image.read_bytes()
        parsed = inspect_bytes(data)
        pstart = parsed["dhtb"]["payload_start"]
        psize = parsed["dhtb"]["payload_size"]
        payload = data[pstart:pstart + psize]
        entries = [x for group in args.entry for x in group]
        limits = {name: getattr(args, f"max_{name}") for name in DEFAULT_LIMITS}
        report = analyze(payload, file_sha256=hashlib.sha256(data).hexdigest(),
                         payload_file_offset=pstart, ranges=args.range, entries=entries,
                         load_base=args.load_base, limits=limits, hash_scope="whole input image")
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (OSError, InspectionError, ValueError) as exc:
        print(json.dumps({"schema": SCHEMA, "ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
