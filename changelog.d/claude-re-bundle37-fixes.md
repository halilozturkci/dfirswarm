### Fixed: reverse-engineering `elf_directories`, `macho_directories` and `pe_directories` report a cut string as partial

A symbol, import, install, bind, export, identifier or `#Strings` name longer than the 4,096 bytes the tools read was shown as "a name of 4096
characters" in an answer that said `complete`. The three tools now make the answer `partial` and name the file offset when a string has no terminator
within its table or those 4,096 bytes, and the text they show for it says "at least" and no longer states a length they did not see.
`macho_directories` no longer pushes an export-trie edge that leads to a node already queued or outside the trie (a crafted trie held
well over a gigabyte), and its 4,000,000-symbol limit text says "at most". A table file that cannot be written whole (a full disk or a file-size limit)
is removed and not named. `managed/clr` and `pe/structure` no longer say the pack has no metadata-table reader: `pe_directories` reads the tables
with `clr_tables`.
