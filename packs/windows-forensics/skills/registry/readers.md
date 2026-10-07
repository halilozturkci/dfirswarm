---
id: registry/readers
title: Reading a regkv answer, and a second reader
when: You read a key with regkv and must know what its answer covers and withholds.
needs: [registry/overview]
tools: [regkv]
requires_host: [regfexport, RECmd, regripper]
---

Use when you query a hive with `regkv` or want an independent reading. Not for acquiring a hive or its state (`registry/overview`).

- Path: from the hive's root, leading backslash or not; the file name (`SYSTEM`) is no part of it. A key that is absent is answered `ok: false` with `deepest_found`, `missing` and `subkeys_there`: ask again from those.
- Values arrive whole with their registry type and length (`value_types`, `value_lengths`). A binary value is hex and nothing more: UserAssist, ShimCache, BAM, SAM and ShellBag values are not decoded here. Say which decoder you used or that none was available.
- Completeness: read `status`, `problems`, `corrupted_values` and `stopped_branches` first. A recursive listing stops at `depth` (0 to 128) or the node limit; `tree_complete: false` means branches were not entered, `all_subkeys` names the file with every subkey past the inline 2,000 and `all_nodes` the whole listing. A hive that did not parse to its end cannot support an absence. A path that is not a regular file is refused and counted (`not_attempted`).
- Withheld: values are judged by name and place, never by type (a DWORD or QWORD under a secret-sounding name is let through). A name that says password, secret, token or credential, everything under `Policy\Secrets`, `PolEKList` and `PolSecretEncryptionKey` in SECURITY, the cached logons and a SAM user's `V` come back as a length marker, listed in `sensitive_values_withheld`; no flag brings one back. A secret inside an ordinary value (a Run command with `--password`, an `ImagePath` with a key) is not recognised and comes back whole.
- Second reader: where the image carries them (`/etc/dfirswarm/tools.md`), `regfexport` (libregf) exports a hive with a parser that is not regipy, `RECmd` runs batch files per artefact family and `regripper` one plugin per question. Record the plugin or batch file and its version, keep a disagreement instead of choosing, and do not assume support for the hive's build or logs.

Sensitive output: run `regkv` as a job with `secret_output: true` when values may carry a secret the name and place rule cannot see; describe a command by its shape.
Shows: values, types and times as the hive holds them, and what the walk did not enter. Does not show: a decoded structure, or an absence when `status` is `partial`. Record: key path, value name, type, raw data, key time, `status`, reader and version.
