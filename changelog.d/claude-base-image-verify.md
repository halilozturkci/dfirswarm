### Added: computer-forensics-base

`image_verify` gives a verification receipt for an EWF image set. Give the first segment or the ordered list: it reads
the naming run (`.E01` to `.E99`, `.EAA` on, `.S01`, `.Ex01`), names a missing segment, refuses a list that is out of
order and a segment that is a link, FIFO, directory or device, and takes each segment's size and sha256. For an E01 or
S01 segment it reads the file header and the chain of section descriptors itself (the segment number, the checksum of
every descriptor, `next` or `done` at the end), so a truncated last segment and a missing later segment are found. It runs
`ewfinfo` and `ewfverify -d sha1` in the tool's own process group under a budget below its deadline, keeps the argv, the
version, the exit code and the output as files, and compares the digests `ewfverify` stored with the ones it recomputed
and with `ewfinfo`'s. `complete` only when every segment is present and in order, the set ends with `done`, every segment
was hashed, `ewfverify` ran to its end with exit 0 and its SUCCESS line, and every stored digest agrees; a digest that
differs, a missing segment or a damaged chain is `failed`; a missing program, a budget hit, an answer it cannot read or a
container with no stored digest is `partial`. An EWF2 (`.Ex01`) set is read by header only and is never `complete`; a
logical evidence file (`.L01`) is refused. The words `authentic` and `genuine` are never used: agreement shows the
container is internally consistent, not that the image matches its source. The wording of `ewfverify` and `ewfinfo` was
read on libewf 20140814; another build's wording is not verified here. `evidence/verify` names it.
