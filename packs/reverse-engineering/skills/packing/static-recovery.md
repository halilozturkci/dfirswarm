---
id: packing/static-recovery
title: Identifying packing from structure, and where static recovery stops
when: Packing, compression or encryption of an executable is in question.
needs: [triage/quarantine]
tools: [entropy_map, pe_info, pe_directories, archive_extract]
requires_host: [upx]
---

Use when an executable may be compressed, packaged or encrypted and you must say what is established. Not for running a loader, debugging, patching the file so it runs, or any unpacking that needs the sample to execute.

1. **Say which you mean.** Compression (reversible without a key), packaging (an installer or self-extracting archive), encryption (needs a key you were not given) and "packed" as an inference are different statements. Use the narrowest one the evidence supports.
2. **Features are leads, never the verdict.** An entropy profile (`entropy_map`: window, threshold, profile file), a size gap with high entropy (`pe_info` `size_entropy_pattern`), a writable and executable section, few imports, odd section names, a large overlay, a large resource (`pe_directories` `resources`): installers, runtimes, media and legitimate protectors produce each. Record them; do not write "packed" from them.
3. **Identify by structure.** If a UPX container is suspected, test a copy without writing: `upx -t COPY`, and `upx -l COPY` to list. A recognised container and a passing test show the file is in that program's format; they do not show what the content does, and a failure does not show the file is unpacked. A signature name from any detector is a lead with the signature database's version recorded; none is declared in this pack.
4. **Decompress only a derived copy, in a job, with an output name**: `upx -d -o "$OUT/<name>.upx-d" COPY` (never without `-o`: UPX rewrites its input). Record the UPX version, the diagnostics, the SHA-256 of the original, the copy and the result, and the relation between them. Read both forms.
5. **Stopping rule.** Stop static recovery when the next step needs the loader or entry code to run, a debugger, a patched file, a key you were not supplied, or a format no reader here supports. Then: keep the original untouched, state exactly what stayed inaccessible, and say that a separate, authorised dynamic examination would be needed. This pack has no such mode and this leaf gives no steps for one.
6. **A negative is bounded.** "No packing found" names the routes tried (entropy, UPX test, structure, resources, overlay) and the versions; a failed route does not make the file clean.
7. An installer or a self-extracting archive is an archive, not packing. `archive_extract` reads a ZIP with a stub in front of it (a ZIP self-extractor); it does not read MSI, CAB, NSIS, Inno Setup, RAR or 7-Zip self-extractors: record the format as identified and its content as not read (`evidence/archives`), and never run the installer to unpack it.

Sensitive output: a recovered or derived file can hold credentials; keep it under `$OUT` and cite file, offset and length.

Shows: structural features, a recognised container, and any derivative with its receipt. Does not show: that a file is packed, what the packer hides, or the behaviour of recovered content. Record: features with their files, tool versions, hashes of every object, the stopping point and why.
