---
id: registry/devices-dates
title: Device install, arrival and removal dates
when: The question turns on when a removable device was first, last or recently attached.
needs: [registry/devices]
tools: [regkv, timestamp_decode, icat_extract]
requires_host: []
---

Use when you need device dates. Not for identity or mounts (`registry/devices`).

- Where present, the device subkey's `Properties` hold `DEVPKEY_Device_InstallDate`, `FirstInstallDate`, `LastArrivalDate` and `LastRemovalDate` under one property-set GUID, `{83da6326-97a6-4088-9453-a1923f573b29}`, with property IDs `0064` to `0067` (from the Windows SDK's `devpkey.h`; confirm them on the build you hold). They are different events: an install is not an arrival, an arrival is not a removal.
- Layout differs between builds: read the property's own key with `regkv`, record key path, value name, type and the raw bytes. The eight bytes are a FILETIME in little-endian byte order and `regkv` returns them as hex, in that order; `timestamp_decode` with `hex: true` reads the hex as big-endian and gives a wrong date. Turn the eight bytes into a little-endian integer (or reverse the byte pairs), pass the decimal, and record both the hex and the integer.
- The key's last-write time is key-level (`registry/overview`) and no substitute for any of these. A device or hive without the properties gives no first or last date: say so, do not estimate one.
- `Windows/INF/setupapi.dev.log` is text (extract it with `icat_extract`) and records installation in the machine's local clock: convert by `registry/clock`. An absent entry means a log that rotated or was never written, not a device never installed.

Sensitive output: `regkv` withholds by name and place only (`registry/readers`).
Shows: the dates the properties and the log carry, each for its own event. Does not show: the connection window, continuous attachment, or any date for a device without these properties. Record: key path, value name, raw hex and integer, decoded time and the clock rule.
