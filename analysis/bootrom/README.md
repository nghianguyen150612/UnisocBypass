# UMS512 (T618) BootROM

Source: [TomKing062/unisoc_bootrom](https://github.com/TomKing062/unisoc_bootrom/blob/main/BootROM_ums512_0x100000_0x111FFF.bin)

- File: `BootROM_ums512_0x100000_0x111FFF.bin`
- Memory range: 0x00100000 - 0x00111FFF (72 KB, 73728 bytes)
- SHA256: `be9fc98c630a78e207f3e2d9f3e0f6cff361097f09056df04c2afad8f27b27ef`
- MD5: `77ae0654cd2f9319a8eda15f3515ac2a`
- Contains `DATE:2018-05-28` marker (matches NCC Group research article)
- Contains `SPRD3` vendor signature

This is the Unisoc UMS512 (Tiger T618) mask-ROM as mapped into physical memory.
Applies to the Anbernic RG Vita. Same chipset as Teclast T40 Plus.

## Why we keep a copy

Voltage-grade ceiling research (see `oc_test/CHANGELOG.md` key findings):
the GPU rail is hard-capped at 800 mV and CPU at ~1050 mV regardless of
device-tree voltage requests. The mechanism that programs PMIC voltage
grades at boot is not in any kernel module we've inspected
(`sprd-hwdvfs-ums512-arch.ko`, `apsys-dvfs.ko`, `mali_gondul.ko`,
`sc2730-regulator.ko`). The remaining candidates are SPL, ATF (BL31),
or the BootROM itself. Having a copy of the BootROM lets us check
whether PMIC grade init happens here.

## Device dump status

No device-side dump recipe is included here. BootROM interaction requires an
externally sourced loader pair and a separate safety review; this repository's
FDL qualification tool is offline-only. The checked-in mask-ROM analysis and
dump artifacts are research references, not evidence that an FDL can be used.
