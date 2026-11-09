### Fixed: reverse-engineering `clr_inspect` and `unpack_safe` refuse a file with a second name at the settle

A process the program had left could make a hard link to its output and append through that name later with no descriptor open,
which no scan of descriptors sees. At the settle both tools now look at the link count of the file: more than one name is a
`partial` answer (`process_left_running`) that removes the file. The manifests and `managed/decompiled` item 5 say that a process
holding nothing which appends later by a name the tool did not see is still not detected.

### Fixed: images `install.py` records an LZMA error and an unsupported zip method as not installed

`lzma.LZMAError` (a corrupt tar.xz, a corrupt LZMA zip entry) and `NotImplementedError` (zip method 99) escaped as a traceback;
both are now in `UNPACK_ERRORS`, and the comment above it says which exceptions still stop the build.

### Changed: reverse-engineering `pe_info` manifest names `withheld_fields_not_listed`

The manifest says that at most 10,000 withheld names are listed, that the rest are counted, and that this bound caps the entries
and not the bytes of the answer.
