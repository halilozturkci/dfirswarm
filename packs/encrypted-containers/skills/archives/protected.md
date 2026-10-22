---
id: archives/protected
title: Examining encrypted archives and protected documents
when: An archive or document may require a password.
needs: []
tools: [archive_probe, file_type]
requires_host: [7z]
---

Use when an archive or document may require a password. Not for the format rules of ZIP, Office and PDF.

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

Only if you read a ZIP, 7-Zip, RAR, Office or PDF structure for its protection or its times: `archives/formats`.

**Names are not an exfiltration finding.** A member list shows the names the
container records. It does not show what the contents are, that they were copied, or
where they went: corroborate with independent evidence.

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

**Sensitive output.** `archive_probe` reads no secret value, but it prints member
names, header strings and the path, and a part of one shaped like an identifier or a
secret is withheld (`names_withheld`); a secret of another shape is printed, so read
a file whose names matter in a job. A job that handles a password, a candidate list or
a decrypted derivative runs with `secret_output: true`.
Never write a password, a fragment of one, or a hash of one.
