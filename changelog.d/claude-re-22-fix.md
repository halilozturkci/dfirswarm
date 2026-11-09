### Fixed: reverse-engineering `clr_inspect` no longer answers `complete` for a reconstruction that an abandoned child keeps growing

`clr_inspect` (decompile) found what the decompiler had forked only by 200 ms samples and by pipe inodes, so a child that was
forked and left (at once, at 0.6 s, or by a double fork) went on appending to the 0600 reconstruction after the answer `complete`,
with the bytes and SHA-256 of the file as it was at that moment. When the program has ended, or been ended, the tool now looks (Linux, /proc) for every process of its own process group that
still holds the program's output or error file, kills it and waits until none is left, before the file is measured. A process
found that way makes the answer `partial` (`limits_hit` `process_left_behind`); the file is kept, stable, and its hash is taken
after that. After a short settle the tool looks at the file again: a file that grew, or one that a process outside the group still
holds open, is a `partial` answer (`process_left_running`) that removes the file and says that a process in a session of its own
(setsid) cannot be ended by this tool. Where /proc is not readable only the growth check and the earlier samples remain, and a
note says so. The manifest and `managed/decompiled` item 5 say this plainly; "first moments" was too narrow (measured: 0.6 s, and a
setsid child outlives the tool). `unpack_safe` had the same defect (a child of `upx -d` appending to the derivative it then hashed) and gets the same fix;
`fuzzy_hash` read its engines' output from a log file and left an engine's child running after the answer, and now ends it and
fails that engine. The programs stay in the tool's process group, as the harness ends the tool by killing that group. Tests use stand-ins (an `ilspycmd`, `upx`, `ssdeep`): the real programs were not run. `authenticode_verify` and
`doc_structure` read a pipe, and tests confirm that a child holding it is ended.

### Fixed: reverse-engineering `pe_info` withholds import function names

An import function name was printed as read; it now passes the same sanitiser as the library names and the export name, in the
answer and in the paged result file. A file with a very large number of withheld names lists the first 10,000 and counts the rest
(`withheld_fields_not_listed`).

### Fixed: reverse-engineering `marshal_inspect` runs its backstop over the paged result file

`final_check` was applied to the printed answer only; the `marshal_inspect-*.json` result file held what the front sanitiser let
through. The backstop now runs over the file too; a string it withholds is counted in `withheld_by_final_check` and makes the answer
`partial`.

### Fixed: images `install.py` records a corrupt compressed archive as not installed

A corrupt deflate stream raised `zlib.error` and a gzip tar cut short raised `EOFError`, which the unpack handlers did not catch, so
the image build aborted with a traceback. Both are caught with the other unpack errors and the optional program is recorded as not
installed.

### Changed: reverse-engineering `go_buildinfo` states what the canary measurement did not bound

The sentence "none reached an output (at most 0.8% per shape)" held for the shapes and slots of that run and not for a random
base64 run of 30 characters in a `-tags` build setting, where a later independent review measured a leak. The manifest and the
changelog now say so. Pack `reverse-engineering`.
