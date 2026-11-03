### Added: computer-forensics-base

`image_layout`, `icat_extract` and `chunk_needles` take `descriptor` (a file `layer_describe` wrote) in place of `image` and
`sector_size`, and the `disk-volumes` recipe takes `{"descriptor": ...}` as its target. The descriptor is read the same way in
all four (the text is copied, not imported): its bytes must hash to the name it carries (`layer-<sha256>.json`), `descriptor_sha256`
can pin it, it is refused when it lists a `missing_dependencies` entry, when a source it names is no longer a regular file of the
size it records, or when a volume's offset is past the end of the media. The sources are given to the Sleuth Kit in order and
the descriptor's sector size is passed as `-b` when it is not 512; the answer is otherwise the one the same image gives by
path, with `descriptor` (and `images`) added. `offset` must be one of the descriptor's volumes, and may be left out when it has
one. Only the sizes of the sources are checked by default: a source swapped for another of the same size is found only with
`verify_sources`, which reads every source again against its sha256. The recipe keeps what it read in `descriptor.json`.
