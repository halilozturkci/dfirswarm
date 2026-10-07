---
id: identify/collector-clues
title: Layout clues for the collector families
when: You describe a family's layout, or collection_id names none.
needs: []
tools: [collection_id]
requires_host: []
mentions: [CyLR]
---

Use when you describe a family's usual layout or `collection_id` names no collector (its `layout_clues` hold only a top-level `C`, `C$` or `Windows` directory). Not for attribution: a layout is a clue, never a signature, and the delivery's own records decide.

- **KAPE**: a mirrored source tree (often a top-level `C`) beside copy, skip and console logs. Keep target collection apart from module-generated reports: a parsed table is derived, not the source.
- **UAC**: archive members such as `[root]`, `[bodyfile]` and `[live_response]` and a `uac.log`. Read the profile and the artefact definitions actually used.
- **Velociraptor**: uploaded files, an upload index and per-artefact result files. Keep accessor and original-path fields, and keep result rows apart from uploaded bytes: an artefact that produced rows did not necessarily upload every file.
- **CyLR**: a mirrored tree is compatible with CyLR output and is not unique to it; attribute it from delivered acquisition records, or leave it open. This pack has no CyLR-specific reader.
- **Cado**: record the exact product, acquisition mode and export type, then read the inventory and provenance it supplied. This pack has no Cado detector and asserts no Cado layout.
- **Eric Zimmerman tool output**: name the generating program and version. Parsed CSV or JSON is derived evidence; it does not show that its source files were delivered, and a missing row or column is not absence from the source.
- **Unknown or hand-made**: list the records you do have and name the provenance that is missing. Do not infer that no manifest exists, or that nothing was left out.

Shows: which family a layout is compatible with. Does not show: which tool, which version or which profile produced it, or what it omitted.
Record: the paths that gave the clue, the families still possible, and what would settle it (a log, a manifest, the operator's account).
