---
id: artifacts/shellbags
title: ShellBags
when: Read BagMRU, RecentDocs, OpenSavePidlMRU.
needs: [artifacts/shell]
card: shellbags {"hive": "<UsrClass.dat>"}: key_last_written is not a first or last view; item times are local DOS times. long_name_from strings is a candidate.
tools: [shellbags, regkv]
requires_host: []
---

Use when you read BagMRU, RecentDocs or OpenSavePidlMRU. Not for links (`artifacts/links`) or for device attachment (`registry/devices`).

- `shellbags` walks every BagMRU root the hive has and names each (the Shell and ShellNoRoam trees can both be populated). Per entry it returns the rebuilt `path`, `key_last_written` (raw FILETIME and ISO UTC), the item's own created, modified and accessed times, `mru_position` and how the name was obtained. `values_without_subkey` lists a numbered value with no key under it, `not_walked_below_max_depth` the keys not walked (below `max_depth`, or at the time limit), and `status` partial means something was not walked or read (`problems` names it: a list the hive's size cannot hold, a stop at the time limit).
- Root folders, volumes and file or directory entries are read by layout (`decoded: layout`). A long name is read from the layout only for the file entry extension, versions 3, 7, 8 and 9 (at 0x14, 0x26, 0x2A, 0x2E), bounded by `extension_block_size` and only when the block's own name offset agrees: `long_name_from: layout`, `extension_layout: decoded`; a localised name after it is `localized_name`.
- Otherwise the name is the longest string in the block (`long_name_from: strings`, `extension_layout` says why) or the item is `undecodable` or unrecognised. These are candidates found by search, not decodes: do not report one as read until a reader that follows the documented layout agrees, such as `libfwsi-python` (a library, no program).
- Two clocks: `key_last_written` is UTC and moves when anything under the key changes, so it is not the first or last time the folder was viewed. The item's times are DOS times in local time, to two seconds, with no zone stored; convert by the zone rules of their date (`registry/clock`), and never put an unconverted DOS time in a UTC timeline.
- `shellbags` says `hive_dirty` (partial) but replays no log (`registry_recover` does: `registry/overview`); a dirty hive may lack the newest bags.
- RecentDocs (by extension) and `ComDlg32\OpenSavePidlMRU` come back from `regkv` as hex, nothing decoded. `MRUListEx` is 32-bit little-endian slot numbers, most recent first, ended by FFFFFFFF; registry enumeration order is not recency. A name read by eye from hex is a candidate.

Shows: that a shell component opened that folder on this account, including folders on devices and shares that are gone. Does not show: who, that a file in it was opened, that the folder still exists, or when it was first or last viewed. Record: the root, full BagMRU path, value slot, MRU position, item type, and whether the name was decoded or found by strings.

Sensitive output: `regkv` withholds secret-bearing values by name, place and shape; a shell item name is a path, withheld when it is not a plain name (`boundary`); `contains` looks at the path as printed, and unmatched entries with text withheld are counted in `contains_blind_entries` (partial). Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
