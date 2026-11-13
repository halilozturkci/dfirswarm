---
id: documents/second-reading
title: Second readings of encryption by qpdf and msoffcrypto-tool
when: doc_structure left an encryption variant unsupported.
needs: [triage/quarantine]
card: Ask for it: doc_structure with {"path": "<file>", "second_reading": true} runs qpdf (PDF) or msoffcrypto-tool (Office) only where the first reading left an encryption variant unsupported; otherwise second_reading.applicable is false and no program starts. It sits beside the first reading: where the two differ, neither is taken as right. Read second_reading.status: only read is a reading; failed, ambiguous, not_installed, not_attempted and not_finished mean "second reading not made". No key is passed: opened_with says whether qpdf's own empty password opened the file; content stays unread. Does not show: plaintext, execution, or which of two differing readings is right.
tools: [doc_structure]
requires_host: [qpdf]
---

Use when `doc_structure` recorded an encryption variant it does not interpret (a PDF handler other than Standard, a version or revision outside the Standard handler's, an Office scheme it does not read). Not for opening, decrypting or trying a key.

1. **Ask for it.** `second_reading: true` on `doc_structure` runs `qpdf` (`--show-encryption`) for a PDF and `msoffcrypto-tool` (`-t`: is the file encrypted) for an Office file. Both are optional. Where the first reading left no such variant, `second_reading.applicable` is false and no program starts.
2. **It sits beside the first reading, never in place of it.** Where the two differ, neither is taken as right. The tool's own fields are the first reading's; the program's are given under `second_reading.result`, as fixed fields, never its text.
3. **No key is passed and no stream is read.** `qpdf` does open a file with the empty password on its own: `opened_with` says whether that opened it as the user, as the owner (`user_and_owner` for both) or failed. That is the program's act, not a decryption by you: content stays unread, and the line in which `qpdf` prints a password it recovered is never kept. `msoffcrypto-tool` is asked only whether the file is encrypted.
4. **Read `second_reading.status`.** `read` is a reading. `unsupported_by_the_program` means it does not support the variant either. `failed`, `ambiguous` (a line printed twice: not taken as a reading), `not_installed`, `not_attempted` (the call's time was spent, or the file name holds a line break) and `not_finished` (ended at 20 seconds or 1 MiB of output) are not readings: write "second reading not made". Record the program's version (`version_output` for `qpdf`).
5. **What the readings still do not show:** that the file opens in an application, what a key would reveal, or that an encrypted action or macro is benign.

Sensitive output: the reading holds parameters and permission flags, never a verifier, a salt, a hash or a key.

Shows: a second parser's reading of the encryption parameters. Does not show: plaintext, execution, or which of two differing readings is right. Record: `status`, the program and its version, `opened_with`, the first reading beside it.
