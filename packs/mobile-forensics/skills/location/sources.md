---
id: location/sources
title: Mobile location records, provenance and uncertainty
when: Use when a question asks where a device, a media item or a person was. Not for the meaning of an app's tables.
needs: [apps/databases, timeline/build]
tools: [sqlite_query, timestamp_decode]
requires_host: [exiftool]
---

Use when a question asks where a device, a media item or a person was. Not for the meaning of an app's tables (`ios/artifacts`, `android/artifacts`).

**Three claims, three proofs.** A record holds coordinates; a device was at that place; a person was there. Each later one needs its own evidence.

**Sources** (inspect table, record type, provider and coverage with `sqlite_query` on a working copy; none is ranked above another):
- iOS routine caches, visits: not every coordinate is a significant place or a contemporaneous fix.
- `Photos.sqlite` and media metadata: capture, import, download, sync and later edit are different times.
- Health and workout routes can hold coordinates; find the originating device or app and whether the route was processed afterwards.
- Android provider and app records: actual fixes, visits or routes. Usage statistics are not a location history.
- Maps, ride, fitness apps: a search, a requested destination, a displayed map, a planned route and a recorded journey differ.
- Wi-Fi and cellular records: saved configuration, scan, association and externally supplied infrastructure location differ.

**For a coordinate** keep raw values, datum if known, provider, device and account, timestamp meaning, units, accuracy fields, fix age and any mock indicator. An accuracy radius is not a promise of presence. Do not invent accuracy or a zone. Convert times from the schema (`ios/containers-and-time`); `timestamp_decode` lists candidates only.

**Media.** Map the `Photos.sqlite` record to the exact file, then `exiftool -json -n -- FILE`; keep the output and the file's digest. Compare GPS time, capture fields, offset fields, library times and file times, keeping conflicts. File and library times may be transfer or import. EXIF can be absent, stripped, edited or carried over from another file. A photo received in a message may carry no coordinates, or those of its capture; it does not locate its sender or recipient.

**Networks.** An SSID is not a place and a saved profile is not a join. A join does not locate a person without BSSID or cell identity, a time match and an independently justified infrastructure location (hotspots, moved access points and copied settings exist).

**Independent families**: two exports of one synced record are one source. State device and person separately.

**Does not show**: that airplane mode stopped GNSS recording (it does not by itself, and recording still depends on hardware, permissions, app activity and retention), or that no record means the device was elsewhere.

**Record**: for a negative, the sources, period, accessible profiles, settings, parser coverage and missing data.

**Sensitive output**: location stores and media metadata are personal data: run as a job with `secret_output: true` where the case treats them so, and cite a record, not a coordinate pasted into a post.
