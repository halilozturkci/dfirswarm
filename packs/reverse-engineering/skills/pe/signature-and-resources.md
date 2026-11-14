---
id: pe/signature-and-resources
title: PE exports, certificate table and resources
when: You need export names, signing state or version information.
needs: []
card: Only authenticode_verify checks a signature, against roots you pass ({"trust_ca": "<roots.pem>"}): certificate_table_declared is a declaration. Else write "not verified".
tools: [pe_info, pe_directories, authenticode_verify]
requires_host: [r2, osslsigncode]
---

Use when a question turns on exports, a signature or resources. Not for judging a publisher: only `authenticode_verify` checks a signature, and only against trust material you supply.

- **Exports.** `export_name` (`pe_info`) is the export directory's image-name field, not the symbol list. `pe_directories` lists every export: ordinal (base plus index), RVA, section, name and forwarder; an export may be named, ordinal-only or forwarded, and a name is a claim. A service DLL need not export a symbol called `ServiceMain`; correlate with the service configuration. Cross-check with `r2 -N -q -c 'iE' SAMPLE`; keep the whole output, stderr too.
- **Certificate.** `certificate_table_declared` is a header declaration; `certificate_table` gives offset, size, `within_file` and the first entry's type. It does not show that the table parses, that a signature verifies, or who signed. No embedded table does not exclude catalog signing. `authenticode_verify` runs `osslsigncode verify` against the roots you pass; a part it got none for is `not_checked`: write "not verified". `pe/authenticode` holds the rest: the parts reported separately, the one release it was read against, what was not measured, and what a valid signature does not show.
- **Resources** hold version information, icons, configuration and embedded objects. `pe_directories` lists the tree (type, name, language, size, file offset), reads the version information and the manifest's `requested_execution_levels`, and `extract` writes a row byte for byte. `r2` with `izz` lists strings across the whole file and can show credentials; write it to `$OUT` (`r2 -N -q -c 'izz' SAMPLE > "$OUT/izz.txt" 2> "$OUT/izz.err"`) in a job with `secret_output: true`, cite offsets and not values; it does not tie a string to a resource. Company and original-file-name values are editable claims. A renamed executable is matched by path, content identity and execution artefacts; an OriginalFilename or a Prefetch name alone does not establish it (the Windows execution skills, if that pack is loaded).

Sensitive output: `izz` output, an extracted resource and the values file of `write_values` can hold credentials. Run those jobs with `secret_output: true` (a `pe_directories` call without `extract` or `write_values` withholds token-shaped strings by shape only: a plain password or a token family it does not name is printed, and 0.1-4% of random base64 or AWS-format keys holding a `/`; run it with `secret_output` when a file's secrets matter); cite offset, kind and length, never a value, a fragment or a hash.

Shows: declared structures and where they sit; with `authenticode_verify`, what `osslsigncode` accepted against your roots. Does not show: publisher trust beyond them, what a resource or export does. Record: offsets, `pe_directories` status and problems, the `r2` version and output, `authenticode_verify`'s `verification` and `verifier.version_output`, or "signature not verified".
