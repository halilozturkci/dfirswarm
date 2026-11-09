### Added: computer-forensics-base

`byte_range_extract` copies declared byte ranges (`[{offset, length}]`) of a regular file, or of a raw split set through a
`layer_describe` descriptor so that a range may cross a segment boundary, to files of their own in a new private directory.
Each range is created with `O_EXCL` and `O_NOFOLLOW` as `range-NNNNNN.bin.partial` and renamed only when all the bytes asked for
are there; a range that ends or starts past the end of the source is short (`requested` against `actual`) and stays `.partial`. The
sha256 of each range, and of all of them in order when every one is whole, is taken as the bytes are copied; the sha256 of fewer
than 128 bytes is not written. `max_total_bytes` and `max_seconds` bound the run, a range the budget cuts stays `.partial`, and
`stopped_by` and `next_range` say where to go on. A link, FIFO, directory or device source is refused, a source that changed
during the run fails it, and a descriptor with an E01, VMDK or QCOW layer is refused as unsupported (the decoded media is not those
bytes). The answer carries locators, lengths and digests, never a byte; the tool says nothing about whether a range forms a file,
and the manifest tells the caller to run it as a job with `secret_output` when a range may hold a credential store.
`filesystem/layers` names it.
