### Changed: computer-forensics-base

The base skills name the Phase C tools. `evidence/verify` and `evidence/provenance` say that `image_verify` wraps `ewfverify`
(and names a missing segment); `filesystem/layers` says what the `layer_describe` descriptor holds and that `image_layout`,
`icat_extract` and `chunk_needles` take it as `descriptor`; `filesystem/layers-mapping` says a slot the descriptor shows as
unreadable is where it starts; `filesystem/extract` says `icat_extract` reads a split raw set through a descriptor (the old
advice to run `icat` by hand with every segment is gone) and carries "a byte range is not a file" for `byte_range_extract`. Every
leaf stays at or under 800 tokens, the index and the router are unchanged, and the sentences the pack's split rules register are all
still present; the wording that was tightened to make room keeps its meaning.
