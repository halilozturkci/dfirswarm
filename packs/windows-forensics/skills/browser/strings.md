---
id: browser/strings
title: URL strings, SQLite, logins
when: Raw URL text; a SQLite file; saved passwords.
needs: [browser/artefacts]
tools: [utf16_urls, sqlite_query, chromium_logins, dpapi_masterkey]
requires_host: []
---

Use when URL-shaped text turns up in raw bytes, you must query a SQLite file directly, or a saved password is needed. Not for browser history databases (`browser/artefacts`).

- `utf16_urls` returns string candidates with byte offset and encoding; it is not a browser parser. Every occurrence is kept (the same text twice is two candidates); the groups view lists each distinct text once with its count and first offset. Nothing is cut by length: a long run comes back in adjacent pieces marked `continued`.
- UTF-16LE candidates read printable ASCII, Latin-1 and the letters of several scripts; CJK is not read. A URL with other characters is found only up to the first one it cannot read.
- A candidate is not a visit, a typed address, a download or an origin: cached page text, rule lists, advertising and security-product data hold URLs too. It counts as browsing only when a visit or download record with a time ties that host to this profile (`browser/artefacts`, `browser/downloads`). In an image the offset is a file offset.
- A URL's user-info password and the value of a parameter whose name says token, secret, password, key, session or signature are masked in the candidate text, a token in a path or under another name is printed; `url_secrets_withheld` says how many, of what kind, and at which offset. `contains` is matched against the text as returned, so it cannot test a guess.
- `sqlite_query` (base pack) is a read-only query on a SQLite file. It copies no sidecar: use it only on a database with no pending `-wal`. An `sql` query prints the values it selects, so `Login Data`, `Cookies`, `Web Data`, `cookies.sqlite` and `key4.db` are read as secret output: a job with `secret_output: true`, `table` and `write_values: true`, never an inline `sql` over the values (the base pack's `data/sqlite-secrets`). The stored values are still encrypted (next rule). `logins.json` is JSON, not SQLite.
- Saved logins: `chromium_logins` decrypts `Login Data`; `dpapi_masterkey` verifies a DPAPI master key and opens a blob. A `v10` secret needs the profile key (in `Local State`, under DPAPI). Look where the user keeps secrets (notes, exports, password files) before attacking DPAPI: a key found there is `key_file`. A negative from your own crypto counts only after the tool's self-test passed (`selftest: true`). `decrypted: false` and `verified: false` are answers, not errors.

Shows: that this text was present at that offset of the source. Does not show: that it was visited, typed, downloaded or opened, by whom, or when. Record: source file, offset and encoding, the text as returned, and any visit or download record that ties it to a profile.

Sensitive output: `chromium_logins` and `dpapi_masterkey` run only as `secret_output` jobs, take secrets as files and write values only to the sealed file. Run `utf16_urls` as a job (`secret_output: true`); the whole text of masked URLs is written only with `write_url_secrets`. Masking is by parameter name and user-info: a token in a path or in free text is printed. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
