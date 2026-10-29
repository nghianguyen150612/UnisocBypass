# P004A: Read-only AArch64 semantic analysis tooling

P004A adds a bounded offline semantic analyzer for analyst-selected AArch64 code ranges. It accepts immutable bytes, does not execute instructions, and does not write the input. There is no authenticated Z2352N U-Boot image in the repository; outputs from synthetic inputs are tool validation only.

## Architecture and Capstone

`tools/aarch64_semantics.py` uses Capstone 5.0.3 in little-endian AArch64 mode with structured instruction operands. Invalid words remain observations with null mnemonic/ID and unknown classification. The existing P001 decoder and JSON schema are unchanged. The CLI calls P001 `inspect_bytes()` first, then uses its validated DHTB payload start and size to choose the payload window.

Local setup and tests:

```sh
python3 -m pip install -r requirements-research.txt
python3 -m pip install ruff
python3 -m unittest discover -s tests -v
python3 -m ruff check tools/aarch64_semantics.py tools/inspect_uboot_ums9620.py tools/fdl_qualify.py tests/
```

## CLI

The input must be a P001-recognized DHTB image. Ranges and entries are payload-relative byte offsets. A code range is `OFFSET:LENGTH`; range bytes and offsets must be four-byte aligned. Supply at least one explicit range and entry.

```sh
python3 tools/aarch64_semantics.py authorized-copy.bin \
  --range 0x1000:0x400 --range 0x2800:0x100 \
  --entry 0x1000 --entry 0x2800 \
  > semantics.json
```

For runtime addresses, add `--load-base 0x...` only when the caller has independently established it. There is no platform default. Resource options are `--max-bytes`, `--max-instructions`, `--max-blocks`, `--max-edges`, `--max-entries`, and `--max-work`. Defaults are 1 MiB, 65,536 instructions, 4,096 blocks, 16,384 edges, 256 entries, and 65,536 worklist operations. Invalid image/range/limit input exits nonzero with a JSON error on stderr. Output goes to stdout; input is opened read-only.

## Address coordinates

The analyzer keeps payload offsets, corresponding file offsets (`P001 payload_file_offset + payload_offset`), and runtime addresses separate. Direct branch destinations are derived from Capstone's structured immediate and retain payload-relative coordinates even without a load base. Runtime addresses are null unless an explicit base is supplied. Address arithmetic is checked against unsigned 64-bit bounds. No synthetic decoding address is presented as a hardware address.

## Instructions and control flow

Direct B and BL, B.cond, CBZ/CBNZ, and TBZ/TBNZ targets are decoded from immediate operands. BR and BLR stay unresolved; RET terminates a path. Known exception/trap transfers such as ERET and BRK have `unsupported_control_transfer` classification and no asserted successor. Invalid/undecodable words have `unknown` classification and likewise terminate a confidently followed path, rather than silently falling through. Calls have a direct-call edge and a separate continuation edge; BLR additionally records its continuation XREF. Conditional branches retain taken and fallthrough edges. Targets outside analyzed ranges remain external/out-of-range edges and are never followed. Blocks split at entry points, in-range direct destinations, terminators, and their continuations. `backward_edge` records address order only; `loop` is true only when the non-call CFG contains a real directed cycle (strongly connected component), never simply because BL targets a lower address. Traversal is bounded by a visited set and work limit.

All bytes in an explicitly supplied range are disassembled, because the analyst selected the range as code. The tool does not scan arbitrary payload regions looking for code. Blocks can still include undecodable words; these appear explicitly in the instruction list.

## XREF and candidate model

XREFs cover direct calls, direct branches, conditional taken edges, sequential fallthrough/continuations, and unresolved indirect transfers. Each carries source file/payload/runtime coordinates, destination payload/runtime coordinates where known, resolution, and a short evidence origin. No data references are inferred from constants, ADR/ADRP, strings, or patterns.

Candidates start from explicit entries and direct BL destinations within decoded ranges. A direct call creates a candidate; it does not prove a full function boundary. Reachability follows non-call CFG edges, preserving caller continuation and not entering callees. Shared reachable blocks are reported. Tail calls and indirect jumps can make boundaries incomplete. Names and security roles are never inferred.

Confidence concerns static candidate boundary evidence only: HIGH is an explicit entry with observed returns and no unresolved/external outgoing path; MEDIUM is a direct-call target with observed returns and similarly complete bounded flow; LOW denotes shared ownership, incomplete flow, no observed return, or unresolved/unknown instruction successors; UNKNOWN applies when the candidate entry itself is undecodable. No confidence level establishes a complete function boundary. These labels do not express security meaning or device applicability. Candidate limitations explicitly state that a complete function boundary is not proven.

## JSON evidence schema

The deterministic top-level schema is `unisoc-aarch64-semantics/v1`: `schema`, `input`, `configuration`, `address_model`, `code_ranges`, `instructions`, `basic_blocks`, `control_flow_edges`, `direct_xrefs`, `function_candidates`, `unresolved_references`, `evidence`, and `limitations`. Input SHA-256 is over the whole image when using the CLI. Observations record decoded instructions; edges/XREFs record bounded static relationships; candidates are static inferences; unresolved transfers remain explicit. IDs and arrays are stable and sorted. Null runtime fields mean no runtime mapping was supplied or established.

P001's `unisoc-uboot-inspection/v1` output is not changed. Semantic output is standalone.

## Limits and limitations

Limits are configurable and enforced for bytes, instructions, blocks, edges, entries, and traversal work. The analyzer passes an explicitly overridden byte limit through to the decoder; the standalone decoder keeps its default 1 MiB budget unless its caller passes a different limit. The analyzer does not reconstruct data flow, resolve register-indirect branches, find code ranges, prove function boundaries, or classify security behavior. Its CFG reflects only the selected bytes and direct control flow. P001 structural recognition and hashes do not prove firmware provenance, signature validity, verifier acceptance, or execution.

P004A outputs are static analysis observations. They are not proof of firmware authenticity, cryptographic signature validity, successful boot, AVB enforcement changes, device compatibility, or root access. No unlock is claimed or verified.

## P004B prerequisites

P004B target-specific analysis remains blocked until an authorized provenance-linked Z2352N U-Boot image and matching build context are available, with whole-file hashes and chain of custody. Runtime address claims additionally need independently established mapping evidence. P003 requires format and verification boundaries, target code context, and evidence for any security interpretation. P004A does not authorize hardware access, image modification, flashing, or restore operations.

## P004A1 correctness review

P004A1 adds synthetic tests for unsupported exception transfers, undecodable instruction termination, downgrade of incomplete function candidates, true directed cycles versus backward edges/calls, BLR continuation XREFs, and configured decoder byte limits. These are tool behavior checks only; they do not establish Z2352N semantics or authenticate firmware.
