---
id: artifacts/plists-archives-dates
title: Keyed archives, plist dates, recent items
when: A plist is a keyed archive, holds a date-like number, or lists recent items.
needs: []
card: safari_history's visit_time_raw is Apple absolute seconds (since 2001-01-01 UTC); a partial read goes on with after_visit_id from resume. URL query values are withheld by shape and a plain secret is printed: read a store whose URLs matter as a job with secret_output: true. A visit is the time Safari recorded, not what the visit was. plist_read shows a keyed archive's UID references unresolved; timestamp_decode lists candidate epochs for a bare number, and a plausible date is not proof that the epoch is the field's. Does not show: what an unresolved reference meant, or that a recent item was opened.
tools: [plist_read, safari_history, timestamp_decode]
requires_host: []
---

Use only if the plist is an NSKeyedArchiver archive, a `.btm` or SharedFileList record, a field that might be a date, or a recent-items list. Not for plain key and value reading (`artifacts/plists`).

**Keyed archives.** An NSKeyedArchiver plist is an object graph: `plist_read` shows its dictionaries, arrays and UID references and does not resolve them into what an application meant. Keep the original archive, use a version-aware decoder for bookmarks, SharedFileList records and background-task registrations, and label any reference left unresolved. A `.btm` file read here is structure, not a list of login items.

**Dates and numbers.** A date object is seconds since 2001-01-01 UTC; a bare integer, real, string or embedded blob inside a plist gets no such meaning from its container. Establish a field's type and unit from its schema or a validated parser before converting it: `timestamp_decode` lists candidate interpretations of a bare number, and a plausible date is not proof that the epoch is the field's.

**Recent items.** Safari's history is `History.db` (`safari_history`), whose times are Apple absolute. `com.apple.recentitems.plist`, the Finder's recent folders and the `com.apple.sharedfilelist` records under the user's Application Support are leads. A stored reference does not show that the content was opened, or when. Sources, bookmarks, MRUs and limits: `artifacts/recent-items`.

Shows: the structure of the archive and the stored reference or number. Does not show: what an unresolved reference meant, the epoch of a bare number, or that a recent item was opened.
Record: the original archive, the decoder and its version, the references left unresolved, the field's raw value with the epoch you assumed.
