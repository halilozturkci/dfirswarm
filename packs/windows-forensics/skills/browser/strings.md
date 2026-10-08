---
id: browser/strings
title: URL strings in raw bytes, and direct SQLite queries
when: URL-shaped text turns up in a pagefile, memory image, unallocated space or raw extract.
needs: [browser/artefacts]
tools: [utf16_urls, sqlite_query]
requires_host: []
---

Use when URL-shaped text turns up in raw bytes, or when you must query a SQLite file directly. Not for browser history databases (`browser/artefacts`).

- `utf16_urls` returns string candidates with byte offset and encoding; it is not a browser parser. Every occurrence is kept (the same text twice is two candidates); the groups view lists each distinct text once with its count and first offset. Nothing is cut by length: a long run comes back in adjacent pieces marked `continued`.
- UTF-16LE candidates read printable ASCII, Latin-1 and the letters of several scripts; CJK is not read. A URL with other characters is found only up to the first one it cannot read.
- A candidate is not a visit, a typed address, a download or an origin: cached page text, rule lists, advertising and security-product data hold URLs too. It counts as browsing only when a visit or download record with a time ties that host to this profile (`browser/artefacts`, `browser/downloads`). In an image the offset is a file offset.
- URL tokens and user-info are masked in the candidate text; `url_secrets_withheld` says how many, of what kind, and at which offset. `contains` is matched against the text as returned, so it cannot test a guess.
- `sqlite_query` (base pack) is a read-only query on a SQLite file. It copies no sidecar and withholds nothing: use it only on a database with no pending `-wal`, and never on `Login Data`, `Cookies`, `Web Data`, `cookies.sqlite`, `logins.json` or `key4.db`.

Shows: that this text was present at that offset of the source. Does not show: that it was visited, typed, downloaded or opened, by whom, or when. Record: source file, offset and encoding, the text as returned, and any visit or download record that ties it to a profile.

Sensitive output: run `utf16_urls` as a job (`secret_output: true`); the whole text of masked URLs is written only with `write_url_secrets`.
