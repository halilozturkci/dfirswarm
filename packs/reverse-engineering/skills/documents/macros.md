---
id: documents/macros
title: Office document inventory: OLE, OOXML and VBA
when: The sample is an Office document, OLE file or OOXML package.
needs: [triage/quarantine]
tools: [file_type, doc_probe, doc_structure]
requires_host: [olevba]
---

Use when the sample is an Office document, OLE file or OOXML package. Not for opening it in an application, for a PDF or RTF (`documents/pdf-rtf`), or for judging whether anything ran.

Never open a sample in Office, a browser or a PDF reader. Parse it in a job with time, memory, output and nesting limits; keep the original and whole inventory.

1. `file_type` first, then `doc_probe` for the container. Read its `status` and `members` counts (encrypted, failed, over budget): an unread member is a gap, not an absence. An extension describes expected content, not validated contents. Code-related parts in a `.docx`, `.xlsx` or `.pptx` are a discrepancy (`extension_content_disagreement`), not proof of renaming or that an application would run them. `parts[].modified` is the ZIP DOS date and time: the writer's local time, no zone, two-second resolution; it is not UTC and not an editing history.
2. `doc_probe` is a preliminary inventory: byte markers, relationships from `*.rels` parts only; with `extract_to` (in a job, a path under `$OUT`) it writes only members whose names match a code-related pattern. `doc_structure` reads structure within budgets: the OLE directory (with entries no storage reaches), VBA modules and encryption records; read its `status`, `problems` and `coverage`. A token-shaped part name is withheld, by shape only; `withheld_names_file` names the private file with the real name. An OOXML VBA project part (by content type) is an OLE compound file: `doc_structure` lists its modules; extract it for `olevba`.
3. For VBA, `olevba` extracts source and names auto-execution entry points such as `AutoOpen`, `Document_Open` and `Workbook_Open` (`olevba -h`). A name does not show execution, and its absence does not show a click was needed (callbacks invoke procedures). If source looks absent or inconsistent, comparing it with compiled VBA needs a version-aware p-code reader, which this pack does not provide: record the comparison as not made. `doc_structure` names Excel 4.0 macro sheets and hidden sheets (if encrypted, only their count); their formulas, embedded packages (an OLE package object can hold an executable, a shortcut or a script), ActiveX and nested documents stay unread.
4. Encrypted or unsupported content stays unexamined until an authorised offline reader parses it; `doc_structure` reports scheme, algorithm and key size, tries no key; its negative is bounded to the structures it names. A clean marker scan does not prove active content absent.

Only if the question is external references in an OOXML package, read `documents/external-and-active-content`.

Sensitive output: macro source, targets and extracted parts can hold credentials. Use `secret_output: true` for `olevba` and when `doc_probe` or `doc_structure` writes files (`extract_to`, `write_values`). Names are withheld by shape; another shape is printed.

Shows: container, listed members, markers, macro source where `olevba` could read it. Does not show: execution, fetch, user interaction, or that anything is absent. Record: tool versions, status, counts, limits, each extracted file's `job:` path and parent part.
