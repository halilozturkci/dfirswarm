---
id: triage/quarantine
title: Handling a recovered sample for static examination
when: Before you parse anything an examined system produced: a binary, script, document or archive.
needs: [evidence/verify]
tools: [file_type, entropy_map, pe_info]
requires_host: []
---

Use when you are about to look inside a recovered sample. Not for judging whether it is malicious: this pack describes a file, and behaviour comes from other artefacts.

**Isolation is yours to keep, not the mount's.** Treat every sample and derived object as hostile data. A no-exec mount reduces accidental execution of a binary; it does not stop an interpreter from running a script or an application from evaluating a macro. Never run evidence, never load a recovered script, macro, module or project as code, and never build source the evidence supplied. Cite the isolation this run recorded (VM, mounts, whether the network is open); do not assume it.

1. Source first: where the object came from, under what authority; for an extracted object its parent and member path or byte range. Verify the inputs, then record SHA-256 and size before any transformation.
2. Identify from bytes with `file_type`. Extension disagreement, ambiguous signatures and parser disagreement are observations; none shows deliberate renaming.
3. Measure entropy with `entropy_map` as a feature: record window, threshold and the profile file. High entropy fits compression, encryption, media and packing; no threshold proves any of them, or malice.
4. Route by format and runtime, not extension: PE, ELF, Mach-O, documents, scripts, .NET, Go, Rust and packaged Python each need their own reading, and this pack has leaves only for `pe/structure`, `elf/structure` and `documents/macros` (`pe_info` reads Mach-O slices, but no leaf explains them). Say which routes you could not take.
5. Strings and capabilities come after structure: `strings/obfuscated`, `capabilities/mapping`.

**Do not upload a sample.** Disclosure can expose confidential material and reveal investigative interest; what follows depends on the service, the case authority and the rules that apply. A hash lookup discloses an identifier too: make one only through the run's authorised mechanism and record the identifier, service, time and what came back. A reputation hit is external intelligence, not proof of behaviour.

Sensitive output: strings, decoded content, extracted parts and document targets can hold credentials. Run those jobs with `secret_output: true`; describe a secret by place, kind and length, never its value, a fragment or a hash.

Shows: what the file is, its size and hash, its entropy profile. Does not show: what it does, who wrote it, whether it ran anywhere. Record: sample reference and hash, each tool and version as printed, settings, complete output, errors, what was not parsed, and that the sample was not executed.
