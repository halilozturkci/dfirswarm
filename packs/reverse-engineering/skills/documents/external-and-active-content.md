---
id: documents/external-and-active-content
title: External targets, PDF actions and RTF objects
when: A document has an external relationship, a PDF action marker or an RTF object.
needs: []
tools: [doc_probe]
requires_host: []
---

Use when `doc_probe` reports an External relationship, a PDF action marker or an RTF object. Not for contacting a target or deciding that anything ran.

- **External relationships.** `external_targets` give the part, relationship id, type, a redacted target and its length: a target and a type, not a completed fetch. Never contact a target. The whole target (credentials, tokens) is written to `doc-probe-values.jsonl` only when the job runs with `write_values: true` and `secret_output: true`; cite it by `finding_id`. Whether anything is retrieved depends on the application, its version and policy.
- **PDF.** `markers` are name tokens with offsets: `/OpenAction` names an action or a destination, `/AA` event-dependent actions, `/Launch` a request subject to reader policy, `/JavaScript` and `/JS` script actions, `/EmbeddedFile` an embedded file stream (content to extract and read, not execution). None is resolved here. Whether an action is reachable needs the object structure, filters and triggers, which `doc_probe` does not read; `encrypt_marker_present` is a marker, not an encryption determination. Object streams hide keywords, so a zero count is not an absence.
- **RTF** embeds OLE data as hex; `objdata_markers` and `classes` locate it. Parse recovered objects as data and do not infer an exploit from their presence.
- Extracted OLE or VBA parts are data to read, never to open.

Sensitive output: targets and extracted parts can be credentials; see above.

Shows: where references and markers sit. Does not show: fetch, execution, trigger conditions or reachability. Record: part, relationship id, offsets, counts, and what was not parsed.
