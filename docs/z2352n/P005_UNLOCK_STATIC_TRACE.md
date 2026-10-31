# P005 — Z2352N U-Boot read-only unlock / Fastboot trace

Status: static hypothesis gathering only; no image patching, device execution, FDL upload, or flashing.

## Input qualification

- Input: original U-Boot OTA for Z2352N/P820F03 (AS build 20241209.113647).
- Expected whole-image SHA-256: `030a0e3ef446360bdb5b7c43ff7d57c311cf83f6c63db3c5c67ccd64e39080aa`.
- Validate the whole-file checksum and the DHTB payload hash before disassembly.
- All addresses in tool output are payload-relative. File offset = payload offset + `0x200`. Runtime load base is not known.

## Observed anchors (candidate hypotheses, not authenticated function symbols)

| Region | Payload code window | Interpretation to test |
| --- | --- | --- |
| lock state | `0xB4A0:0x120` | zero/one state selects LOCK / UNLOCK messages |
| skip-verify jump table | `0xB740:0x120` | computed branch; indirect target unresolved |
| Fastboot dispatch | `0x125C0:0x380` | command string comparison, branch into handlers |
| comparison helper | `0x36D40:0x100` | `BL 0x36D78` followed by `CBZ` suggests strcmp-like behavior |
| Android lock flag | `0x3A500:0x100` | bootargs `androidboot.flash.locked` logic |

Candidate BL callers to `0x36D78`, `0x35E0C`, `0x87F4C`, and `0xB364` are scanned by **instruction encoding only**. Bytes in data can resemble BL instructions; these are not guaranteed executable call sites.

## Read-only run on Arch

Use local worktree `~/Downloads/Z2352N_AS_20241209/UnisocBypass-P005-readonly`, with Capstone already installed in `.venv`.

    ROOT="$HOME/Downloads/Z2352N_AS_20241209"
    WT="$ROOT/UnisocBypass-P005-readonly"
    git -C "$WT" fetch origin research/p005-z2352n-unlock-static-trace
    git -C "$WT" show FETCH_HEAD:tools/p005_unlock_trace.py > "$WT/tools/p005_unlock_trace.py"
    ( cd "$WT" && .venv/bin/python -m tools.p005_unlock_trace "$ROOT/uboot.img" > "$ROOT/P005_unlock_trace.json" )

Use Python to print `windows.compare_helper_candidate.instructions`, conditional branches in `windows.fastboot_unlock_dispatch.instructions`, and `direct_bl_caller_candidates` from the resulting JSON. Do not upload proprietary U-Boot bytes into the GitHub repo.

## Acceptance gates

- Synthetic regression tests pass; GitHub CI passes.
- Operator executes read-only tool on original SHA-256-matched U-Boot; actual offsets and branch behavior reviewed.
- Confirm helper semantics and handler references using control-flow analysis, not string presence alone.
- Jump table reconstruction, real function boundaries, lock-state source, nonce/authorization and AVB/RSA signature verification are **still unproven**.
- No firmware changes, bypass instructions or write operations in P005.
