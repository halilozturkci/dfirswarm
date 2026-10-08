---
id: browser/artefacts
title: Browser profiles and visit history
when: Examine browser profiles and navigation records, apart from background or synchronised activity.
needs: []
tools: [browser_history]
requires_host: []
---

Use when you examine browser profiles and what they logged as navigation. Not for downloads, WebCache or URL text in raw bytes (below).

Open `browser/downloads` only if the question is where a file came from, `browser/webcache` only if the evidence has WebCacheV01.dat or index.dat, `browser/strings` only if the text comes from raw bytes.

Enumerate every installation and profile, and record the browser's version from the profile's own files. Chromium family: `AppData\Local\<vendor>\<product>\User Data\` (`Local State` lists the profiles; each has History, Login Data, Web Data, Cookies). Firefox: `AppData\Roaming\Mozilla\Firefox\profiles.ini`, and per profile places.sqlite, cookies.sqlite, logins.json, key4.db. Bookmarks, Preferences, Sessions\, formhistory.sqlite and sessionstore-backups\ are not read by any tool. Portable installations keep profiles elsewhere: look for the database names. Preserve a database with its `-wal`, `-shm` and `-journal` as one set.

`browser_history` queries a copy (owner-only and writable, so read-only evidence works) with its sidecars, drops every trigger, lets SQLite checkpoint the log in the copy, and removes it; the original is never opened for writing. Read `sqlite_header`, `wal_present` and `wal_frames_replayed` beside every result: 0 frames means the log held none valid for this database; `wal_refused` or `journal_refused` (with `wal_inspection`) says a log contradicted it, `wal_not_established` what could not be told. With no log, the newest rows may never have reached the acquisition.

- `chrome_visits` and `firefox_visits` return one row per visit: id, raw time (Chromium counts from 1601, Firefox from 1970) and ISO UTC, transition (`transition_raw` keeps the qualifier bits `transition_core` drops) or visit type, referring visit. `chrome_url_summary` and `firefox_url_summary` return one row per URL with a count and last visit: a summary, never a visit list (the old `*_history` names answer as those).
- For your own `sql`, list `tables` and `PRAGMA table_info` first. `typed_count` and a typed transition are what the browser logged; redirects, autocomplete and automation produce them. History can hold other devices' entries: look for a table recording where a visit came from (Chromium `visit_source`, if this version has it) before placing a visit on this machine.
- History expires, can be cleared, and can sit in a profile not collected; the earliest visit row bounds what a database covers.

Shows: a navigation the browser logged, with time and transition. Does not show: that a person viewed the page, or that the history is complete. Record: profile, database, sidecars and WAL fields, browser version, the query.

Sensitive output: run `browser_history` as a job (`secret_output: true`). Credential cells (Login Data, Cookies, Web Data, key4.db, columns named for a password, secret, token, card or pin, Luhn-valid card numbers) become length markers, listed in `sensitive_columns_withheld` with their `rule`; URL tokens are masked (`url_secrets_withheld`; text only by `write_url_secrets`). Nothing is decrypted: report that as a limit.
