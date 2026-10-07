---
id: normalise/inventory
title: What the census guarantees and what it does not
when: You quote a file count or say a file is not in the delivery.
needs: []
tools: [collection_index]
requires_host: []
---

Use when a statement depends on `collection_index` being complete. Not for source paths (`normalise/layout`).

1. Run it without `contains` for a census. In a job the whole index is written under `$OUT` and named in `complete_index`; elsewhere pass `out_file` (never inside the collection, never over a file that is there: the new one is kept beside it and named). A `contains` filter limits the inline page and the hashing only: the file holds every object with `matches_filter`, and files outside the filter say `not_attempted`.
2. What the tool records: every regular file with size, nanosecond mtime and a SHA-256 of the whole file (`hash: false` and credential-store names say `not_attempted`); every symbolic link as a row, never followed; special files as rows, not read; every directory or file it could not list, stat or read as a row with its error. `census.errors` and `status: partial` are the stop signs: a count with errors is a count of what was read.
3. What it cannot know: names the collector did not copy, files its extraction left out, members of an archive nobody extracted, or what an extraction renamed. Reconcile the census with the container's own member list and the collector's manifest, and account separately for duplicate member names and extraction collisions, which the tree no longer shows, and for the links and unreadable paths the census lists as rows.
4. A tree that holds an image, a memory capture or an archive lists it as one file with an `object_class`; the objects inside are not in the census. Classify and open each separately.
5. When the time limit ends the census, `census.stopped` says how many directories were not listed: that is not a finished census.

Shows: the objects the tool met below the root and how it met them. Does not show: that nothing else was delivered, or that nothing was lost before the tree reached you.
Record: the answer's `census`, `hashing` and `status`, the index file named, any filter used, and what you reconciled it against.
Sensitive output: the index lists paths and digests of every file, credential stores among them (`may_hold_secrets`); run it as a job with `secret_output: true` and do not copy such digests into a post, report or indicator list.
