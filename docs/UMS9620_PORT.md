# UMS9620 research status: Nubia Neo 2 5G (Z2352N)

This document defines an offline research and validation workflow for the
nubia Neo 2 5G, model **Z2352N**, board **P820F03**, reported SoC **UNISOC T820 /
UMS9620**. There is no Z2352N U-Boot dump or hardware validation in this
repository. Its boot chain, image layout, offsets, runtime addresses, partition
sizes, signature policy, and unlock behavior are **unknown**.

**A matching SoC is not evidence of a matching boot chain.** No Anbernic
offset, base address, signing behavior, SPL assumption, or packaging result in
this repository is approved for Nubia. Do not patch, repack, or flash a Z2352N
image based on these materials.

## Offline inspector

`tools/inspect_uboot_ums9620.py` reads one image with `rb`, does not change it,
does not make a second image, and prints a JSON report to standard output. The
report includes the file SHA-256, DHTB payload bounds and hash, recognized
SIMGHDR/footer fields, optional partition-size checks, and optional AArch64
instruction decoding. It sets no default load base, partition size, or Nubia
code offset. Signature presence is not signature verification, and a
structurally valid image is not proof of boot-chain compatibility.

Example against a separately acquired dump (the partition size is optional,
and should only be supplied when known):

```sh
python3 tools/inspect_uboot_ums9620.py uboot_dump.bin > inspection.json
```

Only supply `--partition-size`, `--load-base`, or `--disasm OFFSET[:WORDS]`
when those values have been established from Z2352N evidence. Payload-relative
code offsets are distinct from file offsets: in the examined UMS9620 tools,
payload offset 0 begins at file offset `0x200`. The inspector decodes a limited
AArch64 subset; other words are preserved as raw `.word` values. Do not treat
the report's SoC label or its parsed fields as a compatibility verdict.

The inspector accepts the following layouts only as structural formats, not as
device profiles:

* A `DHTB` header of `0x200` bytes, version 1, with a little-endian 32-bit
  `mImgSize` at file offset `0x30` and payload beginning at `0x200`. This is
  the field width used by the UMS9620-specific packer code in this repository.
* A classic `SIMGHDR\0` block of `0x494` bytes, or the distinct `0x60`-byte
  vendor footer layout expected by the UMS9620 magic packer. Footer bounds,
  classic declared sizes, header-size/signature-structure markers, exponent
  and copied hash, and the vendor footer payload-offset field are checked. The
  classic layout is selected from its fields before its `0x494` bound is
  evaluated, so partition zero-padding cannot select it by length alone.

The general [DHTB format note](DHTB_FORMAT.md) and
[SIMGHDR format note](SIMGHDR_FORMAT.md) describe a different, older image
profile and use a 64-bit size at `0x30` / a `0x494`-byte signature structure.
That format description must not be silently combined with the assumptions in
the UMS9620 packer. Confirm field widths and footer meaning against an actual
Z2352N dump before changing this inspector's accepted format.

## Audit of existing UMS9620 files

The following files encode Anbernic-oriented runtime patch and packaging
assumptions; they are not a Nubia workflow.

| File | What it assumes or does | Z2352N status |
|---|---|---|
| `tools/patch_uboot_unlock_ums9620.py` | Reads the `DHTB` magic and a 32-bit size at `0x30`, checks four payload-relative instruction words at `0x604c0`, `0xafe8`, `0xb2a4`, and `0xb2ac`, then delegates to the packer. It checks offsets against the declared payload, but does not establish device identity, load base, DHTB hash validity, footer integrity, partition size, or RSA verification. Its instruction masks accept changes in branch immediates / BL targets. Without `--dry-run`, it writes an output image. | Every patch word and mask is from the Anbernic U-Boot described below. A mask match is not proof of matching function semantics or boot chain. Do not run it on a Nubia dump. |
| `tools/magic_pack_ums9620.py` | Inserts a branch at file offset `0x200`, moves the payload to `0x210`, increases the 32-bit size at `0x30` by `0x100`, emits a fixed shellcode template and patch table, updates the vendor footer fields, then truncates to the input file length after checking discarded bytes are zero. Default load base is `0xb5000000`. | These are Anbernic-specific packaging assumptions. It is an image-writing tool, not an inspector. Do not run it on Nubia or stock images. |
| `docs/UMS9620_PORT.md` (previous version) | Described T820 unlock and magic packaging as generally hardware-confirmed, including a load base, patch offsets, fused-SPL behavior, and a `0x300000` partition. | Those claims are narrowed below to repository-reported Anbernic experiments; they provide no Z2352N evidence. |

Neither Python tool cryptographically verifies a SIMGHDR RSA signature. The
packer preserves the payload bytes it copies into its output and adjusts its
vendor footer layout, but it does not prove that a target SPL accepts that
layout or that a signature remains acceptable on another product. The
inspector reports hash and signature-related fields only; it never verifies
RSA. Treat the packer as out of scope for the requested read-only workflow.

## Existing structures, offsets, and assumptions

### DHTB and payload bounds

For the UMS9620-specific packer, the observed model is a `0x200`-byte header,
payload at file offset `0x200`, and a little-endian 32-bit `mImgSize` at
`0x30`. An offset described as a payload/code offset `C` therefore maps to
file offset `0x200 + C` in that model. The DHTB header also contains a stored
hash at `0x08..0x27`. The inspector computes SHA-256 over the declared payload
and reports equality; that result says nothing about RSA verification or SPL
policy.

The general DHTB parser and documentation use an eight-byte size at `0x30`.
The UMS9620 patch and pack code reads only four bytes. This disagreement is a
real audit finding, not something to guess away. Z2352N header width and
semantics must be established from a raw dump, field cross-checks, and the
target loader before any parser or mutator uses them.

### SIMGHDR variants

The repository's general format note identifies a classic `SIMGHDR\0`
signature block of `0x494` bytes with a size, header-size, signature metadata,
RSA exponent/modulus, hashes, and signature. Its existing parser can report
those fields, but it does not cryptographically validate the signature.

The UMS9620 packer instead treats the first `0x60` bytes after its declared
payload as a vendor footer beginning with `SIMGHDR`. It reads a 64-bit
`payload_offset` at footer offset `0x18`, expects `0x200` for its input, and
changes it to `0x210`. For each nonzero value at footer offsets `0x20`, `0x30`,
`0x40`, and `0x50`, it adds `0x100` to the corresponding next 64-bit field at
`0x28`, `0x38`, `0x48`, or `0x58`. The code labels the following bytes as
certificate/private/debug data but does not parse or verify them. The meanings
and applicability of these paired values are not established for Nubia.

Do not conflate the classic `0x494` block with this `0x60` vendor footer, and
do not infer signing keys, signature coverage, or verification order from the
presence of either marker alone.

### Anbernic-specific observations (not Nubia offsets)

The old port notes report the following for an **Anbernic T820 device and its
examined U-Boot build**. These are preserved as provenance, not endorsed as
portable values or independently revalidated in this task:

| Payload offset | Reported instruction / change | Reported purpose |
|---|---|---|
| `0x604c0` | `0x35000160` (`cbnz w0`) to `0xd503201f` (`nop`) | Force an unlock-status path |
| `0xafe8` | `0x54000180` (`b.eq`) to `nop` | Suppress an unlock message / delay |
| `0xb2a4` | `0x9400a21c` (`bl`) to `nop` | Suppress a UART warning print |
| `0xb2ac` | `0x9401e7a2` (`bl`) to `nop` | Suppress a display warning print |

The patcher uses masks `0xff00001f` for the conditional branches and
`0xfc000000` for the two `bl` sites. These masks permit immediate/target drift;
they do not validate surrounding code, function identity, or control flow.
All four offsets, stock words, masks, and their stated purposes are
**Anbernic-specific**. The value `0xb5000000` is the packer's Anbernic-derived
default load base; the comments cite an Anbernic PAC XML base and hardware
observation. The `0x300000` partition-size note is also Anbernic-only. Nubia
values for all of these fields are unknown.

### What the old hardware claims say

The prior documentation reports that an Anbernic UMS9620/T820 unit accepted
the signature-preserving packaging approach, reports `0xb5000000` as that
build's payload base, and reports a `0x300000` U-Boot partition. It reports
hardware checks of the `0xafe8`, `0xb2a4`, and `0xb2ac` subset; the notes do not
claim equivalent hardware confirmation for `0x604c0`. It separately reports
the T618 SPL modification route was rejected on a fused Anbernic T820. These
are prior repository statements about that device/build. There is no Z2352N
evidence that its SPL is fused, checks RSA, accepts a relocated footer, permits
post-verification code, or has any of these dimensions.

The packer's stated signature-preservation constraint is to keep the original
payload bytes it copies unchanged while arranging for a runtime patch after
verification. Its output also changes the entry bytes, DHTB size, footer
offsets, and appended data. The code does not prove which bytes the target
signature covers or that target verification will accept those changes.
Re-signing is unavailable in this repository without the matching signing
private key; that observation does not establish Nubia's keys or policy.

## Exact Z2352N U-Boot evidence required

Before proposing device-specific analysis, collect and preserve a dump and
metadata package with:

1. **Identity and provenance:** photographs or system records identifying
   nubia Neo 2 5G / model Z2352N and board P820F03; Android build fingerprint,
   firmware build/version, and acquisition date/tool/version. Redact serials,
   IMEIs, account data, and other personal identifiers.
2. **Partition map:** authoritative partition names, offsets, sizes, slot
   suffixes, and storage device. Record whether each U-Boot slot or backup
   partition is present. The size must come from this device, not the Anbernic
   `0x300000` observation.
3. **Unmodified U-Boot dump(s):** exact byte-for-byte raw reads of every
   available U-Boot slot, including the full partition when practical. Record
   acquisition method and byte counts. Compute SHA-256 at acquisition and
   again after transfer; retain the originals read-only and analyze copies.
4. **Chain context:** matching SPL / first-stage bootloader version and hash,
   boot mode and active slot, relevant bootloader configuration, and the
   device's secure-boot / fuse state from a trustworthy read-only source.
   Include the signed-image metadata needed to identify the actual header and
   footer formats. Do not infer fuse state from the SoC name.
5. **Address evidence:** the image's declared address fields, matching board
   PAC/XML or equivalent vendor metadata if available, relocation / entry
   sequence, and independent evidence for the physical load address. Record
   uncertainty and address coordinate system.
6. **Target-specific code map:** exact Z2352N disassembly around any proposed
   function, cross-references, strings, branch destinations, and neighboring
   instructions. Each candidate offset must be derived from this dump and
   matched to behavior by control-flow analysis. An Anbernic instruction
   match or string match is insufficient.

The read-only inspector report should accompany the raw dump's SHA-256 and the
partition-map evidence. It does not replace any item above, a boot-chain
analysis, or signature verification.

## Validation gates before any patch or flash

No gate below is currently satisfied for Z2352N. A later, separately reviewed
change would need to document evidence for each applicable gate:

1. Confirm model/board/build and obtain hash-stable dumps for the relevant
   slots and matching SPL.
2. Resolve DHTB field widths, payload boundaries, SIMGHDR/footer variant,
   hash meaning, signature coverage, and partition padding using the dump and
   independent format evidence. The inspector must parse it without guessed
   offsets and report all bounds checks cleanly.
3. Establish the actual SPL verification path, key selection, secure-boot
   state, and whether any proposed delivery method is accepted. Do not assume
   that the Anbernic fused-device result applies.
4. Derive any candidate code location, runtime address, and control-flow
   effect solely from the Z2352N build. Validate all branch targets and
   surrounding instructions; do not rely on the existing Anbernic masks.
5. Review the exact proposed binary transformation, image length, partition
   bounds, preserved signed bytes, footer changes, and cryptographic
   implications offline. Synthetic fixtures and host-side tests cannot prove
   that real hardware accepts it.
6. Require independent review and explicit authorization before any future
   operation that writes an image or touches hardware. This branch performs no
   such operation and does not assert that an unlock is possible.

## Synthetic validation and CI

The inspector tests construct tiny synthetic DHTB/footer images in memory.
They cover SHA-256 reporting, size and footer bounds, partition limits,
malformed headers, inconsistent SIMGHDR sizes, and AArch64 decoding of a
small instruction subset. They do not use or modify repository stock image
fixtures and do not model the Z2352N boot chain. GitHub Actions runs Ruff and
the Python unit suite on pushes and pull requests.
