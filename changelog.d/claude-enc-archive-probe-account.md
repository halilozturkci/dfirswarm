### Fixed: encrypted-containers archive_probe finds an archive of streamed local headers, and a RAR 4 block of any header size, in the bytes no member claims

The byte account of a ZIP (every byte a member, the directory, a Zip64 record or the
End record, or dark and searched for archive shapes) was checked as one design
against archives placed in every region. Two shapes the manifest says are found were
not, and a file holding one in the gap between its last member and its directory was
answered `complete` with `protected: false`:

- a ZIP made of local headers whose sizes are in a data descriptor (bit 3 of the
  flags, zero or Zip64 sizes in the header, as a streaming writer such as `zip -` or
  Java's `ZipOutputStream` writes them, with no directory): it is now found by its
  descriptor (the 4-byte kind or the Zip64 kind, with its signature), whose
  compressed size must be the distance from the data to the descriptor and which must
  be followed by the end of the region or the next record. The search reaches 16 MiB
  after a header and 256 MiB in all, and one cut short is `dark_unsearched`, partial.
  A local header with Zip64 sizes in its extra field is followed the same way. A
  streaming writer that leaves the descriptor's signature out is not found (said in
  the manifest);
- a RAR 4 block whose main header is longer than the 57 bytes the first 64 bytes of a
  region hold (an archive comment, extra fields): the header is now read whole from
  the file and its CRC checked.

`PARSER` moves to archive_probe/6 (a record newly kept). The other weak points the
review listed are stated limits and stay so: the second reader (7-Zip) runs only where
it is installed (`cross_check.result` says `not_installed`), and the dark bytes are
searched for ZIP, 7-Zip and RAR shapes only.
