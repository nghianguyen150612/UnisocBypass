# P004B — Z2352N real-firmware SIMGHDR certificate qualification

Status: offline structural classification only. **No image modification, loader
upload, boot-chain authentication, signature verification, or device testing.**

## Evidence source and applicability

The operator extracted the following images with `payload-dumper-go` from
`update_5g_nubia-neo-2.zip`, an Android 13 A/B OTA reporting
`MyOS13.0.9_Z2352N_AS` / `P820F03`, build `20241209.113647`.

| Image | SHA-256 (whole image, operator reported) | Prefix | Certificate size | Header candidate fields |
| --- | --- | --- | --- | --- |
| uboot | `030a0e3ef446360bdb5b7c43ff7d57c311cf83f6c63db3c5c67ccd64e39080aa` | DHTB + SIMGHDR | 0x458 | 1, 4096, 65537 |
| sml | `2b79d94fffd6a98ceff48e8208b5a4e6d18fa00535b23dd49d0ed8a2e5acce4f` | DHTB + SIMGHDR | 0x438 | 0, 4096, 65537 |
| trustos | `58778f63312b6bff7dbb706cf2fc0a362a12d73f2ab746b363649d1a7a6a241b` | DHTB + SIMGHDR | 0x438 | 0, 4096, 65537 |

These are user-reported on-device-project observations; no redistributable
firmware is committed to this repository. Local tests use synthetic fixtures
only. A passing synthetic test does **not** constitute validation against
the real firmware files or hardware.

## Observed U-Boot layout

```text
0x000000 .. 0x000200: DHTB header
0x000200 .. 0x114460: U-Boot payload
0x114460 .. 0x1144c0: SIMGHDR prefix (0x60 bytes)
0x1144c0 .. 0x114918: candidate RSA-4096 certificate (0x458 bytes)
0x114918 .. 0x115000: all-zero trailing padding (0x6e8 bytes)
```

The DHTB payload SHA-256 matches its recorded header hash. The SIMGHDR
prefix exposes data size, header size, certificate size, and absolute certificate
offset; the first 12 certificate bytes suggest a 32-bit version or type field
(0 or 1), key width 4096 bits, and RSA public exponent 65537.

This is **format evidence**, not proof of certificate authenticity. A 4096-bit
key-width field is not an RSA signature verification. The inspector does not
identify complete modulus/signature boundaries and cannot establish whether
the boot chain will accept a modified image.

## Parser policy

- Keep the existing classic SIMGHDR `0x254` / inline `0x494` layout intact.
- Classify `0x438` and `0x458` only when the declared DHTB payload size,
  SIMGHDR header size (`0x200`), certificate offset (immediately after the
  `0x60` prefix), certificate bounds, and candidate key fields are consistent.
- A structurally recognized image still reports `signature_verified: false`
  and `certificate_format_verified: false`.
- Report trailing length and whether all bytes are zero; nonzero trailing
  bytes are observable evidence, not automatically assumed to be padding.
- Unknown structures and contradictory fields fail closed; do not guess that
  different device/SoC layouts are interchangeable.
- No firmware input is modified. Original image, partition sizes, and hashes
  remain the authoritative local qualification evidence.

## Local qualification (operator action, optional)

```bash
python3 tools/inspect_uboot_ums9620.py ~/Downloads/Z2352N_AS_20241209/uboot.img
python3 tools/inspect_uboot_ums9620.py ~/Downloads/Z2352N_AS_20241209/sml.img
python3 tools/inspect_uboot_ums9620.py ~/Downloads/Z2352N_AS_20241209/trustos.img
```

These commands read files on the host; they cannot verify signatures, bootloader
unlock feasibility, load addresses, FDL compatibility, or flash safety.

## Next research gates

1. Operator-side read-only reports for all three original images and SHA-256
   comparison to the recorded artifacts.
2. Independently establish certificate field boundaries and cryptographic
   verification rules before interpreting RSA signature validity.
3. Use P004A read-only AArch64 disassembly with explicitly bounded code
   ranges to investigate lock-state and AVB functions. Do not assume offsets
   or addresses derived from Anbernic or other UMS9620 devices.
4. FDL1/FDL2 and UFS backup/recovery remain separate blockers before any
   attempt at modifying the phone.
