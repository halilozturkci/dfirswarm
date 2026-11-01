### Added: reverse-engineering `elf_directories` reads an ELF file's dynamic tags, symbols and notes

`elf_directories` reads, through checked ranges and without running the file, what `pe_info` leaves out
for an ELF file: every program header (and the interpreter, executable-stack and RELRO facts), every entry
of the dynamic array found through `PT_DYNAMIC` (so a file with stripped or damaged section headers reads
the same), with NEEDED, SONAME, RPATH and RUNPATH strings and FLAGS, FLAGS_1, BIND_NOW, SYMBOLIC and TEXTREL
decoded, `.dynsym` (its length from DT_HASH, DT_GNU_HASH or the section header) and `.symtab`, and the notes
with the GNU build ID and ABI tag. ELF32 and ELF64 in both byte orders. A table that runs past the end of
the file, a dynamic array without a terminator and a note that runs past its segment are problems, never an
empty list. The first `limit` rows of each table are in the answer and the whole table is in a file. Strings
out of the file pass the shared withholding and one-way-out blocks, byte for byte the ones `pe_directories`
carries: they are withheld by shape only (a secret of another shape is printed; read a file whose secrets
matter in a `secret_output` job). The test compares the tool with `readelf -d -s -n` on the ELF binaries the
build machine has, read only.
