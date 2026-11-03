### Added: reverse-engineering `macho_directories` reads a Mach-O file's symbols, dyld information, build version and code-signature structure

`macho_directories` reads, slice by slice of a Mach-O or a universal binary and through checked ranges, what `pe_info` leaves out, without
running the file: `LC_SYMTAB` and `LC_DYSYMTAB` ranges with every nlist row and its name, `LC_DYLD_INFO` offsets and sizes with the bind, weak-bind
and lazy-bind opcode streams decoded to one row per bind and the export trie walked to the names it exports (also through `LC_DYLD_EXPORTS_TRIE`),
the offsets and sizes of `LC_DYLD_CHAINED_FIXUPS` with its import table decoded, `LC_BUILD_VERSION` and `LC_VERSION_MIN_*` (platform, minimum OS,
SDK, tools), the install names, rpaths and dynamic-linker commands, and the code signature as a structure only: the SuperBlob's blobs, each
CodeDirectory's version, flags, hash type, identifier and team identifier, and whether entitlement blobs are present, by length. Nothing is
verified. A load command that is cut, a count larger than the file holds, a range past the end of a slice, a cut or unknown opcode and an export
trie that loops are problems named in `problems`, never an empty list and never a hang; every slice has its own status, and a universal
binary is `complete` only when every declared slice was read in full. The first `limit` rows of each table are in the answer and the whole
table is in a file. Strings out of the file pass the shared withholding and one-way-out blocks, byte for byte the ones `elf_directories`
carries: they are withheld by shape only (a secret of another shape is printed; read a file whose secrets matter in a `secret_output` job, which is
also where `write_values` is allowed). The tests build their fixtures from the format headers, and compare the tool with `otool` only on a machine
that has it (not verified elsewhere).
