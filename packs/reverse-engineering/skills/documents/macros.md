---
id: documents/macros
title: Document inventory: Office, PDF and RTF
when: The sample is an Office document, PDF, RTF or other package.
needs: [triage/quarantine]
tools: [file_type, doc_probe]
requires_host: [olevba]
---

Use when the sample is an Office document, PDF, RTF or other package. Not for opening it in an application, or for judging whether anything ran.

Never open a sample in Office, a browser or a PDF reader. Parse it in a job with time, memory, output and nesting limits, and keep the original and the complete inventory.

1. `file_type` first, then `doc_probe` for the container (OOXML or ZIP, OLE, RTF, PDF). Read its `status` and `members` counts (encrypted, failed, over budget): an unread member is a gap, not an absence. An extension describes expected content, not validated contents or editing history. Code-related parts in a `.docx`, `.xlsx` or `.pptx` are a format and content discrepancy (`extension_content_disagreement`): not proof of renaming, and not proof an application would run them.
2. `doc_probe` is a preliminary inventory, not a document parser. The OLE answer is byte markers, the PDF answer name tokens with offsets, the RTF answer control words; relationships are read from OOXML `*.rels` parts only; with `extract_to` it writes only members whose names match a code-related pattern.
3. For VBA, `olevba` extracts source and names auto-execution entry points (`olevba -h`). An entry-point name does not show execution, and its absence does not show a click was needed: callbacks can invoke procedures. If source looks absent or inconsistent, compare it with compiled VBA using a version-aware reader and record the disagreement. Excel 4.0 macros, embedded packages, ActiveX and nested documents are separate checks that this pack has no structural reader for.
4. Encrypted or unsupported content stays unexamined until an authorised offline reader can parse it. A clean marker scan is not proof that active content is absent.

Only if the question is external references, PDF actions or RTF objects, read `documents/external-and-active-content`.

Sensitive output: macro source, targets and extracted parts can hold credentials. Run these jobs with `secret_output: true`.

Shows: container, listed members, markers, macro source where `olevba` could read it. Does not show: execution, fetch, user interaction, or that anything is absent. Record: tool versions, status, counts, limits, each extracted object's parent part and digest.
