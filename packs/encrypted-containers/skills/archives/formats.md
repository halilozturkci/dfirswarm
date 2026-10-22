---
id: archives/formats
title: ZIP, 7-Zip, RAR, Office and PDF protection
when: You read a member's protection, a ZIP time, an Office or a PDF encryption structure.
needs: []
tools: [archive_probe]
requires_host: []
---

Use only if you read a ZIP, 7-Zip, RAR, Office or PDF structure for its protection or its times. Not for the first pass over an archive (`archives/protected`).

**ZIP.** Read each member's protection from its own flags and fields: ZipCrypto,
WinZip AES (strength and AE version come from the extra field) and other variants
differ, and one archive can mix encrypted and plain members. The directory being
readable is a separate finding from any member being encrypted. A name that is not valid text
is shown escaped and does not hide the other members; a directory larger than
`max_metadata_bytes`, or declared larger than the file, is not listed (`partial`). A comment can hold an End
record of its own, bytes can follow the archive, and a second archive can be appended (7-Zip lists the first,
`zipfile` the last): when End records disagree (`end_records_disagree`, an earlier archive found in the last
64 KiB included), or bytes that are not zeros follow the comment, the answer is `partial` and
`protected` is not `false`.

**7-Zip and RAR.** Separate data encryption from header encryption. Printable strings
in a header are not a member list: confirm names, sizes and encryption with a reader
that opens the format. A missing volume or an unsupported method can stop a listing
without any password failure.

**Time.** A ZIP member's `modified` is an MS-DOS local time with no zone and a
two-second resolution (`timezone_unknown`); do not append UTC to it. A recorded
extended or NTFS time is a separate field (`modified_utc`) with its source. Keep the
raw fields, note conflicts, and remember that archive times are member metadata, not
the time of collection or transfer.

**Office.** Separate encryption needed to open a document from editing restrictions,
a write-reservation password and rights management. OOXML encryption sits in
`EncryptionInfo` and `EncryptedPackage` streams inside a compound file; binary Word,
Excel and PowerPoint record theirs inside the document stream, so a missing
`EncryptionInfo` does not show a file is plain.

**PDF.** Resolve the effective encryption dictionary through the current trailer
before saying anything. A file can be encrypted and still open with an empty user
password: say "encrypted, opens without a supplied password", and record permission
restrictions apart. An `/Encrypt` string, or any `/V` or `/R`, is a marker, not a
parse.

**Does not show.** That a readable ZIP directory means no member is encrypted; that a header's printable strings are a member list; that a ZIP time is UTC or the time of collection or transfer; that a missing `EncryptionInfo` means a file is plain; that an `/Encrypt` string is a parse.

Record: per member the flags and the variant, the raw time fields with their conflicts, the effective encryption dictionary.
Sensitive output: `archive_probe` reads no secret value and withholds name parts shaped like identifiers or secrets, by shape; a job that handles a password or a decrypted derivative runs with `secret_output: true` (`archives/protected`).
