### Fixed: the AD1 reader takes the parent folder's address FTK Imager writes after each item's name (computer-forensics-base)

FTK Imager writes, after an item's name, the address of the item's parent folder (0 for a top-level item). The AD1 reader of `ad1_extract` and
of the `ad1-items` recipe took an item as its 48-byte header and its name only, so on any image with folders below the top those 8 bytes were
data "reached by no item": a whole, verified image came out `partial` and `unverified`, and `ad1_extract` ended with exit 1 although every file
it was asked for was written and matched its stored digests. On a real 12-segment image (17 GB, 399,836 items) every one of 399,820 such gaps
was this field; 68 of 90 `ad1_extract` jobs in three runs on it failed for that reason alone, and the hub then held the findings that cited them.

- The reader takes the 8 bytes after the name as reached when they hold the parent folder's address (0 at the top), and leaves them to the
  unreferenced-data check when they do not, so a wrong parent field is named as non-zero data nothing accounts for, never passed over.
- The synthetic images of the tests now write the field (they left it zero, which reads as padding, so they mirrored the reader's blind spot);
  the real FTK Imager fixture has top-level items only, whose field is 0. A new case reads a nested image as complete and verified with exit 0,
  and names the one wrong parent field, and nothing else, when an item points at another folder.
