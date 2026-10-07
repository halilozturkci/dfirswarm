---
id: archives/protected
title: Examining encrypted archives and protected documents
when: An archive or document may require a password.
needs: [identify/headers]
tools: [archive_probe, file_type]
requires_host: []
---

Identify the container with `file_type`, keep every supplied part, and record the
source object, the reader and its version, the members examined, missing volumes,
damage, unsupported features, and nested containers left unopened.

`archive_probe` is a triage reader, and what it can establish differs by format:

- ZIP: read structurally from the central directory, per member.
- 7-Zip: the member list and each member's flag come from the installed `7z` where
  there is one, and `header_encrypted` is true when 7z cannot open the archive
  without a password. Without `7z`, only hints from the start header remain.
- RAR: identified; protection and names are not determined.
- PDF and Office (OLE): a byte search for markers, reported as `heuristic` with
  offsets. The structural document reader is not provided by this pack, so
  protection stays undetermined for them; say that, and do not read "no marker" as
  "not encrypted".

Check any consequential finding with a reader that supports the format and the
version. Do not treat an unknown or false as the same thing: they differ.

**ZIP.** Read each member's protection from its own flags and fields: ZipCrypto,
WinZip AES (strength and AE version come from the extra field) and other variants
differ, and one archive can mix encrypted and plain members. The directory being
readable is a separate finding from any member being encrypted.

**7-Zip and RAR.** Separate data encryption from header encryption. Printable strings
in a header are not a member list: confirm names, sizes and encryption with a reader
that opens the format. A missing volume or an unsupported method can stop a listing
without any password failure.

**Names are not an exfiltration finding.** A member list shows the names the
container records. It does not show what the contents are, that they were copied, or
where they went: corroborate with independent evidence.

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

Use passwords the case supplies, where the examination is authorised, and write
decrypted derivatives only under the job's output, validated by the format's own
checks. Do not run extracted programs, scripts, macros or active content.

Further recovery of a password needs an explicit instruction in the case contract
and a recorded basis, scope and stopping condition; this skill does not authorise it
and gives no method. Any approved job that handles candidates, verifiers, logs or
recovered values runs with `secret_output: true` and keeps them sealed. An attempt
that fails shows only that the authorised method did not succeed within its scope:
not that the document is plain, empty or permanently inaccessible.

**Does not show.** That a member list means anything was copied; that the data is
intact or openable; that a PDF or Office file with no marker is plain; who encrypted it,
or why.

**Sensitive output.** `archive_probe` reaches no secret value. A job that handles a
password, a candidate list or a decrypted derivative runs with `secret_output: true`.
Never write a password, a fragment of one, or a hash of one.
