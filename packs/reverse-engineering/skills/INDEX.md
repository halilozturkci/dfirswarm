# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `reverse-engineering/router`

- `capabilities/mapping` Static capabilities and the evidence behind them: You must assess what a sample could do without claiming it ran.
- `code/static-inspection` Reading native code with its analysis limits stated: You must read a native binary's code: functions, control flow, references.
- `documents/external-and-active-content` External targets, PDF actions and RTF objects: A document has an external relationship, a PDF action marker or an RTF object.
- `documents/macros` Office document inventory: OLE, OOXML and VBA: The sample is an Office document, OLE file or OOXML package.
- `documents/pdf-rtf` PDF and RTF structure: objects, actions, embedded content: A PDF or RTF must be read for objects, actions or embedded content.
- `elf/packing-and-identity` ELF packing, linking and build identity: You must say whether an ELF is packed, how it links or which build it is.
- `elf/structure` An ELF file and the loader's view: The sample is a Linux or BSD executable, shared object or core file.
- `macho/structure` Mach-O files and universal binaries: The sample is a Mach-O executable, library, bundle or universal binary.
- `managed/clr` Managed .NET assemblies and application bundles: A PE declares a CLR header, or a native PE looks like a .NET launcher.
- `packing/static-recovery` Identifying packing from structure, and where static recovery stops: Packing, compression or encryption of an executable is in question.
- `pe/signature-and-resources` PE exports, certificate table and resources: You need export names, signing state or version information.
- `pe/structure` A PE file and what its structure shows: The sample is a Windows-format executable, DLL or driver.
- `reverse-engineering/router` Reverse engineering notes by question: Pick a reverse engineering note when none is listed, or you cannot choose.
- `rules/authoring` Writing and validating a defensive YARA rule: You write a rule from a sample or test one against a corpus.
- `rules/yara` YARA matches and what they mean: You search evidence with rules or must interpret a rule hit.
- `runtimes/go-rust` Go and Rust binaries: A large statically linked binary looks like Go or Rust.
- `runtimes/python-packaged` Python-packaged applications and bytecode: An executable looks like a launcher for bundled Python code.
- `scripts/static-analysis` PowerShell, JavaScript and VBScript read as evidence: A recovered script must be read, decoded or described without being run.
- `strings/decoding-and-similarity` Decoding blobs and comparing samples by bytes: A string looks encoded, or you want to cluster samples by byte similarity.
- `strings/obfuscated` Literal and derived strings as evidence: You need strings from a binary, with offsets and a statement of what they can support.
- `triage/quarantine` Handling a recovered sample for static examination: Before you parse anything an examined system produced: a binary, script, document or archive.
