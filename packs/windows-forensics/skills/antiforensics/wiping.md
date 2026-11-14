---
id: antiforensics/wiping
title: Wiping leads
when: Overwritten files; a wiping tool appears.
needs: [antiforensics/traces]
card: prefetch_mam {"path": "<utility>.pf"} and amcache_apps {"hive": "<Amcache.hve>"} give leads, not an overwrite: Prefetch shows a launch under that name (the hash in its file name is of the path), Amcache that the file was inventoried (sha1_raw is the hash as stored: a match is a lead, a mismatch no exclusion). Identify a renamed utility by the recovered file's content, not its name. Neither says which files were overwritten: separate with record reuse and sequence numbers (mft_records {"path": "<$MFT>", "deleted_only": true}) and usn_journal records for the names. Keep deletion, reuse, overwrite, TRIM and missing coverage apart. Does not show: that a file's bytes are gone.
tools: [prefetch_mam, amcache_apps, mft_records, usn_journal]
requires_host: []
---

Use when files or records look overwritten or a deletion utility appears in execution evidence. Not for recovering a deleted file (`filesystem/deleted`).

- Observation: records or files with repeated-character names, high-entropy content, or an execution artefact for a deletion utility (`prefetch_mam`, `amcache_apps`). These are leads. High entropy is also what encryption, compression and archives look like, and repeated names come from software that makes temporary or placeholder names.
- A Prefetch entry shows a program was launched under that name; the hash in its file name is of the path, not the content (`execution/prefetch`). An Amcache entry shows it was inventoried; `amcache_apps` returns the hash as stored (`sha1_raw`) without establishing which range of the file it covers, so a match is a lead and a mismatch is no exclusion (`execution/amcache`).
- A renamed utility is identified from the recovered file's content (hash, PE metadata), not its name.
- Neither artefact says which files were overwritten or that recovery is impossible. Separate with the utility's configuration and target list, MFT record reuse and sequence numbers (`mft_records`), change-journal records for the affected names (`usn_journal`), and what remains in unallocated space (`filesystem/deleted`).
- Keep deletion, later reuse, overwrite, storage discard (SSD or virtual-disk TRIM and unmap) and missing coverage apart. To claim an overwrite, show it in the extents and the surviving content, for the part of the file you mean, and allow for sparse allocation, compression and encryption, which also give zeros or noise.

Shows: that a wiping utility, or the traces of overwriting, are consistent with an attempt. Does not show: which files were overwritten, that a particular file's bytes are gone, or who ran the utility. Record: the artefact and its source, the utility's identification by content, the extents and content examined, the routes tried.

Sensitive output: `mft_records` with `with_resident` returns small files' content; run it as a job (`secret_output: true`). Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
