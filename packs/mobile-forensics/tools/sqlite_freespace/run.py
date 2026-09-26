#!/usr/bin/env python3
"""Read what a SQLite database no longer lists.

Deleting a row does not erase it. SQLite marks the space free and the bytes stay
in the page until that page is reused; whole pages go on a freelist and keep
their contents. Only VACUUM reliably clears them, and phones almost never run
one. So a messenger's database usually still holds the messages somebody
deleted.

Two places to look, and this reads both:

    freelist pages          whole pages no longer in any table
    the unallocated middle  of an in-use page, between the cell pointer array
                            and the first cell, where deleted cells used to be

What comes back is text, not rows. A recovered fragment has no guaranteed column
mapping, no guaranteed table, and no reliable time — the page it sat in may have
belonged to another table entirely. The output says so on every call, because a
recovered fragment presented as a row is the way this evidence fails review.

The header is read for the page size and the freelist head, and the file is
never written to: it is opened read-only, as bytes.
"""
import json
import os
import re
import struct
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def readable(blob, minimum):
    """UTF-8 and UTF-16LE runs, which is what a text column looks like in a page."""
    out = []
    for found in re.finditer(rb"[\x09\x0a\x0d\x20-\x7e]{%d,}" % minimum, blob):
        out.append(("ascii", found.start(), found.group().decode("ascii", "replace")))
    for found in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, blob):
        out.append(("utf-16le", found.start(), found.group().decode("utf-16-le", "replace")))
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    db = args.get("db")
    if not isinstance(db, str) or not db:
        fail("db is required: a SQLite database file")
    if not os.path.isfile(db):
        fail("no such file", db=db)
    minimum = args.get("min_length", 6)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 3:
        fail("min_length must be an integer of at least 3")
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))

    with open(db, "rb") as fh:
        header = fh.read(100)
        if header[:16] != b"SQLite format 3\x00":
            fail("this is not a SQLite database", db=db, head_hex=header[:16].hex())
        page_size, = struct.unpack_from(">H", header, 16)
        if page_size == 1:
            page_size = 65536
        freelist_head, freelist_pages = struct.unpack_from(">II", header, 32)
        write_version = header[18]
        size = os.path.getsize(db)
        pages = size // page_size if page_size else 0

        # Walk the freelist: each trunk page names the leaves that follow it.
        free = {}
        trunk, guard = freelist_head, 0
        while trunk and guard < 100000:
            guard += 1
            fh.seek((trunk - 1) * page_size)
            page = fh.read(page_size)
            if len(page) < 8:
                break
            nxt, count = struct.unpack_from(">II", page, 0)
            data_start = 8 + min(count, (page_size - 8) // 4) * 4
            free[trunk] = (data_start, "freelist trunk page")
            for i in range(min(count, (page_size - 8) // 4)):
                leaf, = struct.unpack_from(">I", page, 8 + i * 4)
                if leaf:
                    free[leaf] = (0, "freelist leaf page")
            trunk = nxt

        fragments = []
        for number in range(1, pages + 1):
            fh.seek((number - 1) * page_size)
            page = fh.read(page_size)
            if len(page) < 12:
                continue
            offset = 100 if number == 1 else 0
            regions = []
            if number in free:
                data_start, description = free[number]
                regions.append((data_start, page[data_start:], description))
            else:
                kind = page[offset]
                if kind not in (2, 5, 10, 13):
                    continue
                cells, = struct.unpack_from(">H", page, offset + 3)
                start, = struct.unpack_from(">H", page, offset + 5)
                header_size = 12 if kind in (2, 5) else 8
                gap_from = offset + header_size + cells * 2
                gap_to = start or page_size
                if gap_to > gap_from:
                    regions.append((gap_from, page[gap_from:gap_to], "unallocated space in page"))
                # A deleted cell is not in that gap: it is put on the page's freeblock
                # chain, in the middle of the cell content area, and that is where a
                # deleted row's bytes actually sit.
                block, guard = struct.unpack_from(">H", page, offset + 1)[0], 0
                while block and guard < 4096:
                    guard += 1
                    if block + 4 > len(page):
                        break
                    nxt, length = struct.unpack_from(">HH", page, block)
                    if length < 4 or block + length > len(page):
                        break
                    regions.append((block, page[block + 4:block + length], "freeblock in page"))
                    block = nxt
            for at_base, region, where in regions:
                for encoding, at, text in readable(region, minimum):
                    if pattern and not pattern.search(text):
                        continue
                    fragments.append({"page": number, "where": where, "encoding": encoding,
                                      "offset": (number - 1) * page_size + at_base + at,
                                      "text": text})

    beside = {}
    for suffix in ("-wal", "-shm", "-journal"):
        companion = db + suffix
        if os.path.isfile(companion):
            beside[suffix] = os.path.getsize(companion)

    print(json.dumps({
        "db": db,
        "page_size": page_size,
        "pages": pages,
        "freelist_pages_declared": freelist_pages,
        "freelist_pages_walked": len(free),
        "write_ahead_log": write_version == 2,
        "companions": beside,
        "fragments": fragments,
        "fragment_count": len(fragments),
        "note": "A fragment is text recovered from space the database no longer uses. It has no "
                "guaranteed column, no guaranteed table and no reliable time: the page may have "
                "belonged to something else entirely. Report it as recovered text with its page "
                "and offset, never as a row. If a -wal or -journal is listed above, copy it with "
                "the database — the newest rows are in there, not in the file you just read.",
    }, indent=2))


if __name__ == "__main__":
    main()
