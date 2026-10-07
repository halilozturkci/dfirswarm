---
id: pe/signature-and-resources
title: PE exports, certificate table and resources
when: You need export names, signing state or version information.
needs: []
tools: [pe_info]
requires_host: [r2]
---

Use when a question turns on exports, a signature or resources. Not for verifying anything: no tool in this pack validates a signature or extracts resources.

- **Exports.** `export_name` is the export directory's image-name field, not the symbol list. An entry routine may be named, ordinal-only or forwarded, and a service DLL need not export a symbol called `ServiceMain`; correlate with the service configuration. List exports with `r2 -2 -q -c 'iE' SAMPLE` and keep the whole output: names, ordinals, forwarders.
- **Certificate.** `certificate_table_declared` is a header declaration; `certificate_table` gives offset, size, `within_file` and the first entry's type. It does not show that the table parses, that a signature verifies, or who signed. No embedded table does not exclude catalog signing. Report verification, trust chain, timestamp and revocation separately, each with its policy, trust material and time; this pack has no trust-aware verifier, so write "not verified". A valid signature does not show a file is benign, and does not show a key was stolen: leave the circumstances open without other evidence (build records, distribution, certificate history).
- **Resources** hold version information, icons, configuration and embedded objects. `pe_info` does not parse them. `r2` with `izz` lists strings across the whole file; it does not tie a string to a resource. Company and original-file-name values are editable claims. A renamed executable is matched by path, content identity and execution artefacts; an OriginalFilename or a Prefetch name alone does not establish it (the Windows execution skills, if that pack is loaded).

Shows: declared structures and where they sit. Does not show: signature validity, publisher trust, resource contents. Record: offsets, the `r2` version and full output, and "signature not verified".
