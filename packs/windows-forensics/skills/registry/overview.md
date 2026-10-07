---
id: registry/overview
title: Registry hives: acquire, hive state, control set
when: You are about to read an offline hive and must keep its state and time meaning.
needs: []
tools: [regkv, icat_extract]
requires_host: []
---

Use when you acquire or open an offline hive. Not for the answer fields of `regkv` or a second reader (`registry/readers`: read it before you rely on an absence or on a decoded value).

    SYSTEM SOFTWARE SAM SECURITY    Windows/System32/config/
    Users/<user>/NTUSER.DAT         that user's settings and activity
    ...AppData/Local/Microsoft/Windows/UsrClass.dat   shell bags (`artifacts/shell`)
    Windows/AppCompat/Programs/Amcache.hve            inventory (`execution/amcache`)

- Extract with `filesystem/extract` or `icat_extract` into a file whose digest you record. Take each hive with its `.LOG1`, `.LOG2` (and a legacy `.LOG`) beside it, as one set.
- State: `regkv` reports `hive_dirty` (the two sequence numbers differ), `hive_sequence_numbers` and `transaction_logs_beside_hive`, and says `transaction_logs_replayed: false`. This pack replays no log, so a dirty hive's newest state may be missing: say so, keep the original and its logs, and treat a copy recovered elsewhere as a derivative with its inputs, method and tool version. Earlier states are other sources (`filesystem/shadowcopies`).
- Control set: an offline SYSTEM hive has no `CurrentControlSet`. Read `Select` (`Current`, `Default`, `Failed`, `LastKnownGood`), use the `ControlSet00n` the question concerns, and never substitute another one silently.
- Time: a key's last-write time dates a change to that key, not to one value in it and not the key's first existence; software that restores or edits a hive can set it. Some values carry a time of their own with another meaning. Quote hive, full key path, value name and type, raw data, key time and tool version together.
- A value's presence is configuration, not execution (`execution/overview`). Machine basics: `registry/system-profile`.

Sensitive output: `regkv` withholds by name and place only (`registry/readers`).
Shows: the configuration a hive held in the state you acquired. Does not show: who set a value, that what it names was used, or that nothing else was there. Record: hive path and digest, sequence numbers, logs beside it, control set read.
