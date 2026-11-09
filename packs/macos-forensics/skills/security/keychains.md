---
id: security/keychains
title: macOS keychains, identification and opening
when: A keychain file is in the evidence, or an answer needs what a Mac's keychain held.
needs: []
tools: [keychain_open, plist_read]
requires_host: [chainbreaker]
---

Use when a keychain file is in the evidence or an answer would need what a Mac stored in one. Not for property lists (`plist_read` is not a keychain decoder), for iOS data, or for guessing, recovering or cracking a password.

**Identify first, from metadata.** There are three stores. The System keychain (`/Library/Keychains/System.keychain`) and a user's login keychain (`~/Library/Keychains/login.keychain-db`, or an older `login.keychain`) are files that begin with `kych`. The Local Items store (`keychain-2.db` under a user's `Library/Keychains/<UUID>/`, the data protection keychain) is an SQLite database. Record each store's path, size, times and owning account before any content is read. Whether the reader parses a given file is not assumed: the tool's outcome says. A keychain's presence shows that an account used it, not what it holds.

**Opening is the case's decision.** `keychain_open` (it drives the pinned reader, chainbreaker, which you do not run yourself) opens a `kych` keychain only when the case supplies the login password as a job input file or, for the System keychain, its SystemKey file (kept under `/var/db`). Every job of it is secret output: the items go to one sealed file and the answer holds the outcome, counts and sizes. `opened` is the only complete outcome, and it is `partial` when the reader left a process behind (the tool ended it, and the items file is what it held then) or when that cannot be ruled out (not Linux). `partial` means some records were not decrypted. `wrong_secret` is not proof that the password is wrong (the key file or the keychain may be). `unsupported_format` is the answer for the Local Items store, which is not opened here. `damaged` and `unavailable` say the reader could not run. Without the password or the key, say the keychain was not opened; do not try passwords you were not given.

**The sealed file.** Read it in the job's output, a record at a time; each read is recorded. A value is a credential of the account's owner. Say that an item exists, in which store and class, and how long its value is; use a value for the case only as the case allows.

Shows: which stores exist, record classes and counts and, if opened, the items the reader parsed. Does not show: that an item was used, when or by whom; the Local Items store; a file the reader cannot parse.
Record: store paths, sizes and times; the reader and its pin; the outcome and counts; the sealed file's name and size; who supplied the secret, and why.
Sensitive output: the items file, the password file and the SystemKey file are secrets. No value, fragment or hash of one goes into the ledger, a note or an answer: presence, location and length only.
