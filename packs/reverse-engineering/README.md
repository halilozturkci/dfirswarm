# Reverse Engineering Pack

Static triage of a binary or a document, under quarantine. Nothing from the
evidence is executed, and the harness enforces that at the kernel rather than
trusting it.

Depends on the Computer Forensics Base Pack.

## What it carries

**Seven skills.**

| Family | Skills |
| --- | --- |
| Triage | `triage/quarantine` |
| Executables | `pe/structure`, `elf/structure` |
| Strings | `strings/obfuscated` |
| Capabilities | `capabilities/mapping` |
| Documents | `documents/macros` |
| Rules | `rules/yara` |

**Five tools.** `file_type` reads what a file is from its bytes and says when
the extension disagrees. `entropy_map` shows where a file is packed before
anything is disassembled. `pe_info` reads PE, ELF and Mach-O structure —
sections with their entropy and permissions, imports with their function names,
the compile timestamp, and for a fat Mach-O the architectures it holds.
`fuzzy_hash` computes SHA-256, ssdeep and TLSH together, and can give the TLSH
distance between two samples without executing either one.
`doc_probe` opens a document as a container: the macro project, the external
references that fetch on open with no macro at all, PDF actions that run by
themselves, and RTF objects that a plain `strings` cannot see.

**One catalogue recipe.** `static-binary` recognises PE, ELF and Mach-O files
by magic and writes the parser's uncapped structure plus a complete entropy report for kickoff
or the derived catalogue.

**One goal template**: `sample-triage.md`.

## The line this pack will not cross

Everything here is a claim about a file. "The binary contains the string
`http://x/y`, referenced from the function at 0x4012a0" is one. "The malware
connects to `http://x/y`" is a claim about behaviour, and static analysis cannot
make it. The skills say so repeatedly because it is the way a report from this
kind of work most often fails review.

The pack also refuses one convenience: do not submit a sample to a public
service. It publishes the evidence, tells whoever wrote it that they are being
looked at, and in some jurisdictions breaks the custody chain. Send a hash if
the goal allows it, and record that you did.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/reverse-engineering
    scripts/swarm.sh start --pack computer-forensics-base,reverse-engineering --quarantine ...
