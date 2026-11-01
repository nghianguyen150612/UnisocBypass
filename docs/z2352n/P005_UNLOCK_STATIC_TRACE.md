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

## External FDL / recovery evidence triage (2026-11-01)

These public records were checked for the same model and must not be confused:

| Record | Identified hardware | What it supports | What it does NOT establish |
| --- | --- | --- | --- |
| [Martview thread](https://www.martview-forum.com/threads/zte-nubia-neo-2-5g-z2352n-unisoc-t820-frp-remove.127020/) | Despite the thread title `Z2352N`, the pasted successful CM2SP3 log identifies **nubia 8150N / P720F03_A**, `eMMC`, and `ZTE/8150N` loaders | 8150N-specific FDL1/FDL2 execution and backup were reported | **No Z2352N/P820F03 FDL success**. Sharing the T820/UMS9620 SoC does not qualify those loaders for the Nubia Neo 2 |
| [GSMVN service report](https://gsmvn.net/threads/nubia-neo-2-z2352n-frp-one-click.3002/) | Explicit **Z2352N / P820F03 / UMS9620**, with `Storage type: UFS` and MyOS13.0.4_Z2352N_VN | A third-party service log reports preloader/mainloader execution, UFS detection, partition reads, and a backup | No downloadable, hash-qualified FDL pair, host command sequence, independent reproduction, or owner-controlled recovery path; it is not unlock evidence |
| [Lionrome package listing](https://www.lionrome.com/index.php?a=downloads&b=tags&tag=P820F03+Firmware) | Advertises `Z2352N_GEN_NEEA_P820F03V1.0.0B11_MyOS13.0.4_Z2352N_AS.PAC` (4.30 GB) | Another potential stock PAC provenance lead | No inspected archive, loader extraction or verified free download; merchant licensing applies |
| [FirmwareWorld listing](https://firmwareworld.com/index.php?a=downloads&b=tags&tag=emergency+firmware) | Z2352N-SA PAC (paid) and SD-card software (listed Featured) | Region/build-specific firmware leads | SD-card/OTA update is not proof that FDL1/FDL2 are bundled, and paid PAC contents remain uninspected |

### Consequences for the project

- P002/P002A candidate FDL states remain **UNVERIFIED**; 8150N loaders are not promoted to Z2352N-compatible because of a thread title or SoC match.
- There is **no public, source-proven, downloadable Z2352N signed FDL pair** verified by these records. No FDL upload, execution, device command, UFS write or flash was performed.
- Even a reported UFS connection does not demonstrate that a locally available loader will operate safely on the owner's handset or that modified bootloader images will pass secure boot.
- Preserve `P005` as Draft until the original owner-held OTA U-Boot is analyzed by the SHA-gated collector and the complete read-only output is reviewed. The expected U-Boot SHA in this document is a **previously recorded value**, not a fresh download or device hash in this run.
- To share evidence without exposing firmware, redact locally produced JSON output and provide SHA-256, the bounded windows and caller candidates. Do not commit firmware or device identifiers.

### Qualification record (current)

- P005 synthetic validation: GitHub Actions on the branch; tests must be checked at final commit.
- P005 real-OTA execution from this review environment: **NOT PERFORMED** (owner's original `uboot.img` not mounted here).
- Original image hash checked in this environment: **NOT PERFORMED**.
- Z2352N FDL1/FDL2 run on owner's hardware: **UNVERIFIED**.
- Z2352N UFS backup/recovery under owner's control: **UNVERIFIED**.
- Z2352N unlock policy transition, magic64 compatibility, AVB relaxation: **UNVERIFIED**.
