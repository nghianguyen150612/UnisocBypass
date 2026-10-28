# Offline FDL qualification

This repository does not distribute FDL binaries. Supply files from a source you
are authorized to use to the read-only inventory tool; it hashes and inspects
them locally but never loads them onto a device.

```bash
python3 tools/fdl_qualify.py inventory \
  --loader-dir /path/to/extracted/loaders \
  --settings /path/to/settings.ini --json
```

See [`docs/FDL_QUALIFICATION.md`](../docs/FDL_QUALIFICATION.md) for protocol
notes, evidence limits, the source matrix, and a read-only hardware checklist.
The tool will never label a loader "compatible". A same-SoC label, profile
name, or plausible address is not validation.
