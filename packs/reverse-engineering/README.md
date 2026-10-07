# Reverse Engineering Pack

Static triage of a binary or a document, under quarantine. This pack's tools and
skills parse and read samples; they never run one. A no-exec mount on the
extraction directory reduces accidental direct execution of a binary, but it does
not stop an interpreter from running a script or an application from evaluating a
macro, so the rule is kept in method as well: samples are read, never run, and
what a run records about its isolation is what to cite.

Depends on the Computer Forensics Base Pack.

## What it carries

**Twelve skills**, each a short decision-rule leaf; the second-level leaves are
opened only when the leaf above points to them.

| Family | Skills |
| --- | --- |
| Triage | `triage/quarantine` |
| Executables | `pe/structure`, `pe/signature-and-resources`, `elf/structure`, `elf/packing-and-identity` |
| Strings | `strings/obfuscated`, `strings/decoding-and-similarity` |
| Capabilities | `capabilities/mapping` |
| Documents | `documents/macros`, `documents/external-and-active-content` |
| Rules | `rules/yara`, `rules/authoring` |

Not provided yet, and the skills say so where it matters: a managed (.NET)
metadata reader, Go, Rust and packaged-Python readers, script analysis, a
Mach-O method, structural PDF and RTF reading, and a trust-aware Authenticode
verifier.

**Four tools of its own, and `file_type` from the base pack.** `file_type` reads
what a file is from its bytes and says when the extension disagrees.
`entropy_map` measures how evenly byte values are spread, window by window, and
writes the whole profile to a file; it reports a measurement and does not
identify packing. `pe_info` reads PE, ELF and Mach-O structure (sections with
their entropy and permissions, imports with their function names, the compile
timestamp as the header's raw value, the dynamic array of an ELF through its
program headers, every slice of a universal binary) and says for each answer what
it read and what it did not; it verifies no signature. `fuzzy_hash` computes
SHA-256, ssdeep and TLSH together, and can give the TLSH distance between two
samples without executing either one. `doc_probe` opens a document as a container:
the member list, the External targets of its relationships, the members whose
names match a code-related pattern, and byte markers for OLE, RTF and PDF. A
marker or a relationship shows what a file holds, not what runs or was fetched.

**One catalogue recipe.** `static-binary` recognises PE, ELF and Mach-O files
by magic and structure and writes the parser's structure (long tables kept
whole in files) plus a complete entropy profile for kickoff or the derived
catalogue. Its status comes from what the parsers say they read, not from their
exit codes. It is an inventory (`purpose: inventory`): the
binary's structure, not its behaviour or its strings.

**One goal template**: `sample-triage.md`.

## The line this pack will not cross

Everything here is a claim about a file. "The binary contains the string
`http://x/y`, referenced from the function at 0x4012a0" is one. "The malware
connects to `http://x/y`" is a claim about behaviour, and static analysis cannot
make it. The skills say so repeatedly because it is the way a report from this
kind of work most often fails review.

The pack also refuses one convenience: do not submit a sample to a public
service. An upload discloses the sample: it can expose confidential material and
reveal investigative interest, and what follows depends on the service, the case
authority and the rules that apply. A hash lookup discloses an identifier too, so
send one only through the run's authorised mechanism, and record that you did.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/reverse-engineering
    scripts/swarm.sh start --pack computer-forensics-base,reverse-engineering --quarantine ...
