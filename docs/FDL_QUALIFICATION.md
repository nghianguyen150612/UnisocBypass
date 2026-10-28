# Offline FDL qualification: Z2352N / P820F03 / T820

This is a research and inventory workflow for the nubia Neo 2 5G (Z2352N,
P820F03, UNISOC T820/UMS9620). It does not load a candidate, connect to a
phone, communicate with BootROM, or perform flash operations. No candidate FDL
for this device has been validated by this repository.

## Chain and evidence limits

The usual smartphone download path has two loader stages:

1. BootROM download mode enumerates over USB and receives the first protocol
   exchange. The Linux `spreadtrum_flash` implementation sends CHECK_BAUD and
   expects a version response before sending FDL1.
2. FDL1 is transferred to a package-specified RAM base and executed. In the
   implementation, the host then probes CHECK_BAUD for an FDL1 version reply
   and reconnects before proceeding.
3. FDL2 is transferred to its own package-specified base and executed. FDL2
   initialization and subsequent device/storage responses are later stages.

FDL base addresses belong to firmware/package metadata. The `0x5500` and
`0x9EFFFE00` examples in `spreadtrum_flash` documentation are for its Tiger
T310 example, not evidence for Z2352N. The U-Boot/SPL code in this repository
also contains a `0x5500` BootROM observation; that is not loader qualification
for this model.

The open-source Linux tool documents that smartphone FDL2 performs
board-specific `pinmap` initialization and warns that another model's loader
can be risky even on the same chipset. A shared T820/UMS9620 SoC therefore
cannot establish loader compatibility. A filename, profile label, file
signature/shape, reference in settings.ini, or matching RAM address also cannot
establish compatibility. Establishing that would require model-specific
provenance and controlled hardware evidence that is outside this offline tool.

## Failure categories

The log classifier reports textual observations only. One log can contain
several categories; none is a conclusive root-cause diagnosis.

| Observation | What it tells us | What it does not tell us |
|---|---|---|
| USB transport failure or timeout | Host I/O did not complete as logged. | Whether the cause was cable/port, permissions, enumeration, host timing, device power/state, or a later protocol stall. |
| CHECK_BAUD timeout | A version/baud-check response was not observed at that point. | It does not by itself imply signature failure, authentication rejection, or even identify which stage was active. Capture surrounding stage messages. |
| Explicit loader-format/header mismatch | The log reports a parse/format issue. | It does not prove a candidate has the wrong cryptographic signature unless the tool explicitly reports that check. |
| Explicit security/authentication rejection | The log contains a direct rejection/verification phrase. | It does not identify which key, policy, stage, or package is responsible without further evidence. |
| FDL2 initialization failure | The log associates initialization, DRAM, NAND, or storage failure with FDL2. | It does not by itself distinguish incompatible board init, bad transfer, power/transport trouble, or damaged media. |
| `FDL2: incompatible partition` | `spreadtrum_flash` describes this response as occurring after FDL2 has initialized. | It is not evidence that CHECK_BAUD or FDL2 initialization failed. |

The classifier intentionally adds `root_cause_undetermined` for CHECK_BAUD
timeouts and never translates them into authentication failure.

## Inventory command

Point the tool at a private/external extracted loader directory and its
settings.ini. It reads recursively, does not follow file symlinks, and emits
JSON to stdout. It does not edit or copy the supplied files.

```bash
python3 tools/fdl_qualify.py inventory \
  --loader-dir /mnt/research/cm2-pack/loaders \
  --settings /mnt/research/cm2-pack/settings.ini --json
```

The inventory includes candidate role based on filename, byte size, SHA-256,
limited header/marker observations, settings references, profile labels found
in the settings path/content, and known/unknown FDL base addresses. Structural
heuristics only flag obvious cases such as empty files, text/XML containers,
or very small images; “opaque binary” is not a positive loader identification.

Compatibility status is deliberately limited:

* **unverified** — candidate-like FDL1 and FDL2 files are present and no
  obvious inventory problem blocks inspection. This still means unvalidated.
* **insufficient evidence** — one/both roles are absent, references are
  missing/ambiguous, or the settings file is malformed.
* **structurally incompatible** — a candidate has an obvious non-loader
  structure such as empty file, text/container content, or implausible size.

There is no `compatible` status. A report of `unverified` is not authorization
to test a loader on the phone.

## Historical log command

Classify an existing local log or pipe copied text via stdin:

```bash
python3 tools/fdl_qualify.py classify-log ./historical-cm2.log --json
cat ./historical-spd-dump.log | python3 tools/fdl_qualify.py classify-log --json
```

Possible classifications distinguish transport failures/timeouts,
CHECK_BAUD timeouts, explicit loader-format reports, explicit
security/authentication reports, and FDL2 initialization reports. Unknown
text remains `unclassified`; no diagnostic command is issued to a device.

## Infinity CM2SP3 profile and boot-pack notes

Infinity CM2SP3 is proprietary. Its private program files, loader binaries,
settings, and boot-pack contents are neither required by this repository nor
included here. Its public release notes describe external FDL loader support
and model support, but do not publish enough pack internals to establish
candidate file hashes, loader bases, signing status, or board initialization.

| Profile / evidence | What is established | What remains unknown |
|---|---|---|
| `ZTE/Z2352N` | Z2352N is the target model specified for this research. Infinity's public v2.49 release note lists Z2352N among ZTE models. | No CM2SP3 private profile or settings.ini was inspected here; exact FDL file names, hashes, addresses, file format, and proven hardware behavior remain unknown. |
| `ZTE/8150N` | ZTE's public conformity document identifies model 8150N as a 5G phone. | No evidence here establishes that its board, memory/pin initialization, FDL pair, or profile is interchangeable with Z2352N. Do not use 8150N loaders for Z2352N based on SoC similarity. |
| `settings.ini` layout | The CLI recognizes common FDL1/FDL2 filename/value references and address-labelled settings keys. It reports ambiguity when a generic FDL reference cannot be assigned a stage. | Infinity may use other private pack conventions. The parser does not claim complete CM2SP3 profile-format support. Supply a copy for offline inspection and review the raw settings if the report omits references. |

## Evidence matrix

| Claim | Evidence | Confidence / limit |
|---|---|---|
| FDL is commonly transferred in two stages on smartphones; FDL1 initializes external RAM and loads FDL2. | `spreadtrum_flash` README. | Upstream tool documentation; protocol/device variants exist. |
| Host sends CHECK_BAUD and expects a version response before transfer; after FDL1 execution it probes for the FDL1 response. | `spd_dump.c`, in the first `fdl` command path. | Describes this tool's implementation; exact firmware behavior varies. |
| FDL2 may perform board-specific pin-map initialization. | `spreadtrum_flash` README. | Strong reason not to substitute by chipset alone; not a complete list of board differences. |
| `FDL2: incompatible partition` is reported after FDL2 execution/initialization. | `spd_dump.c` executes FDL2, waits for its response, then labels that response; README describes it as after initialization. | Not equivalent to failure during CHECK_BAUD or transfer. |
| Infinity v2.49 public support list includes Z2352N; external FDL loaders are supported by CM2SP3. | Official Infinity CM2SP3 release notes and feature notes. | Public support listing only; no private loader identity or proof of hardware validation. |
| No candidate FDL for Z2352N is validated here. | No hardware was used and no proprietary profile contents are present in this change. | Explicit scope limitation. |

## Weekend read-only Arch Linux checklist

This checklist gathers USB and log evidence only. Do not run `spd_dump`,
ResearchDownload, CM2SP3 download/flash actions, loader upload/execute, or
partition/memory commands as part of this checklist.

1. Record host and kernel context: `uname -a`, `lsusb --version`, and the
   installed `usbutils` version. Use a known data-capable cable and a direct
   host port; note any hub in the path.
2. In one terminal, observe kernel USB events:

   ```bash
   sudo journalctl -kf
   ```

   In a second terminal, take a baseline before connecting the powered-off
   phone: `lsusb -nn`, `lsusb -t`, and `sudo dmesg --ctime | tail -n 80`.
3. If the owner chooses to enter the documented download-mode key sequence,
   connect once while observing the journal. Record timestamps, VID:PID,
   interface/class, disconnect/re-enumeration events, and whether charging or
   a stable USB device appears. Do not probe beyond USB enumeration.
4. Capture a second `lsusb -nn` / `lsusb -t` and the relevant journal lines.
   If a pre-existing diagnostic log exists, preserve it unchanged and run the
   offline `classify-log` command above. Do not create a new diagnostic log by
   sending protocol packets.
5. Run the offline inventory only against loader files already obtained
   externally. Keep the report, source/version provenance, and hashes together;
   redact account identifiers and unrelated host paths before sharing.

**Stop immediately** if the phone heats, repeatedly resets, enumerates
intermittently, enters an unexpected boot state, or the required key sequence
is uncertain. Disconnect USB if the device behaves unexpectedly. Stop at a
CHECK_BAUD timeout rather than retrying with a different FDL. Do not infer
authentication failure from it. No FDL upload/execute or storage operation is
part of weekend read-only qualification.

## Sources

* [ilyakurdyukov/spreadtrum_flash README](https://github.com/ilyakurdyukov/spreadtrum_flash/blob/main/README.md) — stages, model-specific initialization cautions, package addresses, and diagnostic note.
* [`spd_dump.c`](https://github.com/ilyakurdyukov/spreadtrum_flash/blob/main/spd_dump.c) and [`spd_cmd.h`](https://github.com/ilyakurdyukov/spreadtrum_flash/blob/main/spd_cmd.h) — CHECK_BAUD, BSL version/connection, FDL1/FDL2 transfer sequence, and response codes.
* [Infinity CM2SP3 v2.49 release note](https://infinity-box.com/news/?r=4439) — public model support listing, including Z2352N.
* [Infinity CM2SP3 v2.32 release note](https://infinity-box.com/news/?r=4372) — FDL-mode boot-log extraction feature.
* [ZTE conformity document for 8150N](https://download.ztedevices.com/bigmediafiles/device/global/certification/Smart_phone_2023/P0322_23ZTE0060_ZTE_8150N/P0322_23ZTE0060_ZTE_8150N_CE_DOC.pdf) — model identity only.
