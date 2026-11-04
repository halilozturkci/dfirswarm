# Reverse Engineering Pack

Static triage of a binary or a document, under quarantine. This pack's tools and
skills parse and read samples; they never run one. A no-exec mount on the
extraction directory reduces accidental direct execution of a binary, but it does
not stop an interpreter from running a script or an application from evaluating a
macro, so the rule is kept in method as well: samples are read, never run, and
what a run records about its isolation is what to cite.

Depends on the Computer Forensics Base Pack.

## What it carries

**Twenty-four skills**, each a short decision-rule leaf; the second-level leaves are
opened only when the leaf above points to them.

| Family | Skills |
| --- | --- |
| Triage | `triage/quarantine` |
| Executables | `pe/structure`, `pe/signature-and-resources`, `pe/authenticode`, `elf/structure`, `elf/packing-and-identity`, `macho/structure` |
| Code | `code/static-inspection`, `code/second-readers` |
| Runtimes | `managed/clr`, `managed/decompiled`, `runtimes/go-rust`, `runtimes/python-packaged` |
| Packing | `packing/static-recovery` |
| Strings | `strings/obfuscated`, `strings/decoding-and-similarity` |
| Capabilities | `capabilities/mapping` |
| Documents | `documents/macros` (Office), `documents/external-and-active-content`, `documents/pdf-rtf`, `documents/second-reading` |
| Scripts | `scripts/static-analysis` |
| Rules | `rules/yara`, `rules/authoring` |

Not provided, and the skills say so where it matters: a Python archive extractor, a bytecode disassembler or
decompiler, and parse-only script tooling. A .NET decompiler runs only through `clr_inspect` (`ilspycmd`, where it
is installed; `pe_directories` reads the metadata tables only when asked, with `clr_tables`). Declared, run by no
tool of the pack and never observed on a real sample: Ghidra's headless analyzer (a method, never a script, in
`code/second-readers`), `diec` and `lief`. `ilspycmd` was not run for real either, and the limits of
`authenticode_verify` and of `doc_structure`'s `second_reading` are in `pe/authenticode` and
`documents/second-reading`. The skills name only programs the pack declares.

**Thirteen tools of its own, and `file_type` from the base pack.** `file_type` reads
what a file is from its bytes and says when the extension disagrees.
`entropy_map` measures how evenly byte values are spread, window by window, and
writes the whole profile to a file; it reports a measurement and does not
identify packing. `pe_info` reads PE, ELF and Mach-O structure (sections with
their entropy and permissions, imports with their function names, the compile
timestamp as the header's raw value and as a Unix time, the dynamic array of an ELF through its
program headers, every slice of a universal binary) and says for each answer what
it read and what it did not; it verifies no signature. `fuzzy_hash` computes
SHA-256, ssdeep and TLSH together, and can give the TLSH distance between two
samples without executing either one. `elf_directories` reads an ELF file's program headers, every dynamic tag, `.dynsym` and `.symtab`, and the notes (the GNU build ID among
them), through the program headers when the section headers are stripped. `macho_directories` reads, per slice of a Mach-O or a universal binary, the symbol table, the dyld bind and export names, the chained-fixups imports, the build version and the code-signature blob structure (no signature is verified). `authenticode_verify` verifies a PE file's Authenticode signatures by running `osslsigncode verify` (never its own cryptography) against the roots, timestamp-authority roots and revocation list the call supplies, reads the program's words back per signature (the file's digest against the signed one, the signature, the signer's names, the signing time, a timestamp counter-signature) and says `not_checked` for every part it was given no material for; it uses no default CA store and no network, and reads its words only for the release it was checked against (2.5). `unpack_safe` unpacks a UPX-packed file
into a derivative under the output budget (UPX only; both SHA-256 values and the
UPX version recorded; the original never changed). `clr_inspect` reads a .NET assembly's CLR header, metadata root and declared row counts as structure and, in a `secret_output` job with `decompile`, runs `ilspycmd` (optional; amd64 Native AOT, arm64 on the declared .NET runtime) to write a labelled C# reconstruction to a file under `$OUT`, never inline: a decompiler's output is an interpretation, not the author's source, and the program was never run for real by the change that added the tool. `doc_probe` opens a document as a container:
the member list, the External targets of its relationships, the members whose
names match a code-related pattern, and byte markers for OLE, RTF and PDF. A
marker or a relationship shows what a file holds, not what runs or was fetched.
`doc_structure` reads the structure those markers only point at, stdlib only and
under budgets: an OLE compound file's directory (including entries no storage
reaches), its VBA project (modules and the size of their compressed source;
source is written only on request, byte for byte) and the encryption records the
Office formats keep; an OOXML package's content types, protection elements and
embedded VBA projects; a PDF's cross-reference chain, object streams, the
encryption dictionary of the current trailer, its actions with the key that
reaches each, and its embedded files; an RTF's groups, objects and fields. A
verifier, salt or hash a structure holds is reported by length, never as bytes,
and this reader tries no key. With `second_reading: true`, an encryption variant
it leaves unsupported (a PDF handler other than Standard, a version or revision
outside the Standard handler's, an Office scheme it does not read) also gets a
reading by qpdf or msoffcrypto-tool, given beside the first and never in place
of it; no password or key is passed to either, but qpdf opens a file with the
empty password on its own and the answer says whether that opened it. `pe_directories` reads the PE directories `pe_info` only
declares: exports, delay-load imports, TLS callbacks, the resource tree with the
version information and manifest, the CLR header and metadata root (and, with
`clr_tables`, the rows of the main metadata tables), the debug
directory and the Rich header. Neither verifies a signature or says what code does.
Both withhold what they print by shape only: user-info, secret-named values and
token-shaped text are withheld; a secret of another shape (a plain password, a
token family the rules do not name, a token split across two fields) is printed,
and some keys of a covered shape are too (the changelog gives the measured rates).
A file whose secrets matter is read in a job with `secret_output: true`.
`go_buildinfo` reads the build information a Go binary carries (the toolchain
version, the main module, every dependency with its version, checksum and
replacement, and the build settings such as `-ldflags`, `GOOS` and `vcs.revision`)
from an ELF, PE or Mach-O file or every slice of a universal binary, in both
header formats, executing nothing. It withholds by shape as the two above do; a
binary built without a header, or stripped of one, answers `found: false`, which is
not a finding that the file is not Go. `marshal_inspect` reads a Python `.pyc` or a
marshal stream carved from a packed program as data (CPython 3.11 to 3.13: code
objects with their names, constants and bytecode size, sha256 and hex), never
calling `marshal.loads` and never running a line of it; the interpreter is named
from the header's magic number and a version outside that range is `unsupported`.
A constant can be a credential, so strings and byte strings are withheld by shape
and kept whole only in a sealed file written with `write_values` in a job with
`secret_output: true`. It unpacks no archive and decompiles nothing.

**Two catalogue recipes.** `static-binary` recognises PE, ELF and Mach-O files
by magic and structure and writes the parser's structure (long tables kept
whole in files) plus a complete entropy profile for kickoff or the derived
catalogue. Its status comes from what the parsers say they read, not from their
exit codes. It is an inventory (`purpose: inventory`): the
binary's structure, not its behaviour or its strings. `capa-floss` is not run
automatically: asked for a PE or ELF, it runs `capa` and `floss` if they are
installed and keeps what each said (the whole JSON, its argv, what `--version`
printed, its exit code); an engine that is missing, fails, times out or prints
something unreadable is a named status of that engine and the recipe is partial
or failed, never complete. Its receipt and `matches.tsv` copy no string and no
matched feature.

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
