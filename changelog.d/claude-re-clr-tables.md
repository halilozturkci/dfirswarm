### Added: reverse-engineering `pe_directories` reads the CLR metadata tables with `clr_tables`

`pe_directories` takes a new `clr_tables` parameter (default false: without it the answer is what it was). With it, the tool reads the ECMA-335
`#~` stream of a managed assembly through the metadata root it already finds: the heap-size byte, the valid mask, the row count of every table and
the width of every table index and coded index, which decide where each table starts, and then the rows of Module, TypeRef, TypeDef, Field, MethodDef,
Param, MemberRef, ImplMap, Assembly, AssemblyRef and ManifestResource, each with its file offset, its names read from `#Strings`, its blobs given by
offset and size only, its GUIDs from `#GUID`, and its coded references as `Table:row`. The `#US` heap is listed string by string. The first `limit` rows
of each table are in the answer and the whole table is in a file; the other tables are given by row count only. The placement is a view of
`pe_directories`, which already reads the CLR header and the metadata root and carries the withholding and one-way-out blocks, so no block is copied
into a new tool.

A `#-` (uncompressed) or edit-and-continue stream, a heap-size byte with the delta bit, a table above 0x2C and the pointer, `EncLog` and `EncMap`
tables are refused as unsupported: the answer is `partial`, `clr_tables.status` is `unsupported` and `problems` names the reason. Row counts the stream
cannot hold, heap indexes outside their heap, a heap that runs past the metadata root and a cut `#US` entry are problems, never an empty list. Strings
out of the file pass the same sanitiser as every other string of the tool: they are withheld by shape only (a secret of another shape is printed; read
a file whose secrets matter in a `secret_output` job). Method bodies, custom attributes, signatures and blob contents are not read, and nothing is said
about what a method does. The tests build their metadata from the standard's table layouts, and compare the tool with a C# compiler's output only on a
machine that has one (not verified elsewhere).
