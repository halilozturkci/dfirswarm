### Fixed: computer-forensics-base lists a compressed tar complete only when its whole stream has been read

For a gzip, bzip2 or xz tar, the `archive-members` recipe and `archive_extract`
stopped at the tar's first end blocks and never read the rest of the decompressed
stream, a further compressed stream or the compression trailer. Two tars in one
gzip stream, two gzip members (the second a tar), bytes after the stream or a
gzip trailer with a wrong CRC-32 or length were all answered `complete` with the
first archive's members only (the same bytes uncompressed were `partial`), and the
recipe runs at kickoff on every archive. Both now read the rest under the clock
(and `archive_extract`'s ratio budget): zeros are not a finding (a tar ends in two
zero blocks and zero padding to its record size), but a non-zero byte after the
end blocks, a further tar header or stream holding data, bytes after the last
stream that are not zero padding, a trailer that does not match and a stream that
does not end make the answer `partial` with the decompressed offset named, and a
rest that the clock or a budget cut short says it was not read to its end. This
also reads a large gzip member past end-of-archive to its end. A sound single
compressed tar stays `complete`. The recipe lists a compressed tar through a
reader that sees every stream (tarfile's own `r|*` reads no trailer); the gzip
framing is done by the tool, so a member whose trailer does not match hands out
its bytes first and is reported after them. zstd tars are read as before. The
recipe's time on a sound 1 GiB tgz of zeros is stated in the verification notes.
