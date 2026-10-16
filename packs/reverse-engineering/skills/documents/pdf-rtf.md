---
id: documents/pdf-rtf
title: PDF and RTF structure: objects, actions, embedded content
when: A PDF or RTF must be read for objects, actions or embedded content.
needs: [triage/quarantine]
tools: [doc_structure, file_type]
requires_host: []
---

Use when a PDF or RTF must be read for its contents. Not for opening it, contacting a target, or deciding that anything ran.

Run `doc_structure` in a job; read `status`, `problems`, `limits_hit` and `coverage` first: a budget hit or unreadable object is a gap, not an absence.

**PDF**
1. `structure_source`: the cross-reference chain or a scan for headers (`anomalies` says why). `revisions`: each update. Content outside the newest chain is data, counted in `objects_scan` (`headers_freed_in_newest_chain`, `headers_not_in_the_cross_reference_chain`, `numbers_defined_more_than_once`); an action there is a row with `outside_chain`, cited by object number.
2. `encryption_summary` `found` true: the current trailer names an encryption dictionary (`encryption.dictionary`: handler, `v`, `r`, crypt filters, permissions; verifiers by length). Strings and streams are then ciphertext (unless `str_f`/`stm_f` is `Identity`) and no key is tried: actions outside object streams are listed, ciphertext targets marked `ciphertext: true`, by length; objects in encrypted object streams are unread (`census.objects_unreadable`). `found` null: not determined; false: bounded to the chain read. Permission flags ask a reader to restrict; they protect nothing.
3. `actions` (table `pdf_actions`): an action, the key that reaches it (`trigger`) and whether anything does (`reached_from_catalog`) are three facts. A destination is not an action; whether a reader runs one depends on the reader, its version and settings. `script`: form and size; `extract: ["javascript"]` with `extract_to` under `$OUT` writes scripts: read as text, never run. A `URI` or `/F` target (`Launch`, `GoToR`, `SubmitForm`) is shown redacted (whole: `write_values`); `/Win` strings by length.
4. `embedded_files`: stream object, size, filters. `pdf:<n>` (filters undone) or `pdf-raw:<n>` (as stored) writes one, named in `extracted`: ciphertext in an encrypted file, else route it by `file_type`; record its parent object.
5. `streams.undecodable_filter`: streams behind filters not decoded here (LZW, JBIG2, JPX), unread. `pages`: the declared `/Count` and the leaves traversed; neither is a verified page count.

**RTF**
6. `structure` (open groups, stray braces) and `objects`: kind, class, hex length, data `signature` (no byte printed), OLE 1.0 header; a compound-file payload is in `nested_compound_file`. `fields`: `instruction_word` (a known field type, `=` a formula) and length; `templates`: a redacted target and length. Each is a row of `rtf_fields` or `rtf_templates`, whole in the values file with `write_values`; one past its bound is cut, a limit. `\bin` data is skipped by its length.

Sensitive output: scripts, targets and embedded files can hold credentials: `secret_output: true` with `extract` or `write_values` (else targets are withheld by shape; another shape is printed); cite object, finding id, length.

Shows: structure, actions and triggers, where embedded content is. Does not show: that an action ran or a fetch happened, what encrypted content holds. Record: status, problems, `structure_source`, revisions, object numbers, extracted files.
