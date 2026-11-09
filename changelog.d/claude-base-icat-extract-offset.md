### Fixed: computer-forensics-base `icat_extract` validates its offset and writes 0600 files

- **An explicit `offset` is a whole number from 0 to 2**40 sectors, or a JSON refusal.** It was used as it came (a negative number, a text such as `"12"`, `1.5`, `true` or `2**70`) for icat's `-o` and for the catalogue path `p<offset>`. The refusal comes before anything is made or icat runs, with `status: failed`.
- **The extract, its `.partial` and the `.icat.stderr` file are created 0600**, with `O_NOFOLLOW`, whatever the umask; they were 0644.
- **Refusals carry `status: failed` and `status_basis`**, and a refusal from the image or offset search (no image, several images, several filesystems) is JSON on standard output, as the other refusals are, instead of text on standard error. A NUL or a lone surrogate in `output`, `image` or `inode`, an `image` that is not text, and arguments nested past the parser are refused as JSON; an error nobody expected answers `failed` with the error's class and no message.
- **The search for the image under `inputs/`** (when `image` is not given) is on a 60-second clock read for every entry and keeps at most 200 names, as in `chunk_needles`.
