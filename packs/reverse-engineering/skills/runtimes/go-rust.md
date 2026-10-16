---
id: runtimes/go-rust
title: Go and Rust binaries
when: A large statically linked binary looks like Go or Rust.
needs: [triage/quarantine]
tools: [pe_info, entropy_map]
requires_host: [strings, floss, r2, capa]
---

Use when a native binary is large, mostly static and sparse in imports, and its text names Go or Rust. Not for calling the runtime's own code a capability, or its static linking concealment.

1. **Say which runtime and how you know.** Record the artefacts, not a guess: for Go, a toolchain string (`go1.` and digits), the text `Go buildinf:` and a function-name table; for Rust, mangled names (`_ZN...E` with a `17h` hash tail, or a `_R` prefix) and panic messages that carry source paths. Search with `strings -a -t x SAMPLE > "$OUT/strings.txt"`; a miss is bounded by how you searched (stripped files keep some of these and lose others). Markers and mangling forms differ by compiler release: record what you found and check a documented form before naming a release.
2. **Paths and names are build claims.** A `/rustc/...` or `.cargo/registry/src/<crate>-<version>/` path names crates and versions the compiler recorded; a Go module list names what was built in. Neither is provenance, and none shows a dependency is used by the author's code.
3. **Most functions are runtime and dependencies.** A function count of thousands, goroutine scheduling, panic and allocator code, TLS and HTTP libraries are what these toolchains produce. A `capa` match or an import is the author's only when the matched code is application code you can cite (`capabilities/mapping`, `code/static-inspection`); even then it is a capability hypothesis, not intent.
4. **Imports are sparse by design.** Static linking and runtime-resolved calls are ordinary here; `pe_info` imports or ELF dependencies say little. A static ELF has no dependencies to list (`elf/packing-and-identity`).
5. **Strings are not NUL-terminated.** Go and Rust strings are a pointer and a length, so plain extraction runs neighbours together. FLOSS support for both depends on the release: run `floss -h`, record which modes completed and what the output says it skipped, and treat a recovered string as derived.
6. **A stripped file** can still hold function names; their presence is not provenance, and their absence is not packing (check the entropy profile with `entropy_map` before saying anything about packing, then `packing/static-recovery`).
7. `r2` finds fewer functions here than a language-aware tool would; state the pass (`code/static-inspection`) and do not write "no function" beyond it.

Sensitive output: strings and module paths can hold credentials and user names; write output to `$OUT` in a job with `secret_output: true`, cite offsets and lengths.

Shows: runtime artefacts and where they sit. Does not show: what the author's code does, that a dependency is used, concealment. Record: the artefacts and offsets, search commands, FLOSS modes completed, tool versions.
