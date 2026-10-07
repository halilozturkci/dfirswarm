---
id: keys/where-they-hide
title: Locating and safeguarding authorised key material
when: A case question requires access to encrypted evidence.
needs: [identify/headers]
tools: [recovery_key_scan, ioc_scan]
requires_host: []
---

Record first: the question, the encrypted object, and the authority for locating
and using key material. Holding a device, an account name or a candidate secret
is not authority over another account or service.

Look in what the case supplies before anything else: documented passwords and
recovery material, key files, acquisition notes, authorised escrow exports. Then
the in-scope files, backups and captures. Choose a source by its relation to the
container, not by a presumed success rate.

For every candidate keep: the source object and exact locator, its kind, any
non-secret identifier (a protector or key id, which the worker rules say to write
in full), the acquisition provenance, and the container it may belong to. A
valid-looking recovery password or a conventional file name is a lead. It does not
show that the material opens this container: it may belong to another volume or
to a protector that was later replaced.

**recovery_key_scan.** Shows where text in the BitLocker recovery-password format
sits (file, offset, length, ASCII or UTF-16LE, and whether its eight groups pass
the divisible-by-11 check), where a PEM private-key header sits (type and offset),
and which file names are conventional for key files and credential stores. Does
not show: that a value opens anything, what is in a key store, or anything in an
image, an archive or a container (no OCR, no unpacking). It reads the first 8 MiB
of each file unless `max_bytes_per_file` is raised, and lists every file it could
not read, skipped or read only in part: a clean result is bounded by that coverage.
A value is found unless it is glued to more digits (`key_<value>` is found,
`<value>7` is not). A file or directory named after a recovery password has that
name withheld from the paths it prints.
It returns no value, fragment, shape or digest; `write_values: true` is for the one
case that needs the value (below).

**ioc_scan** finds a literal you name, in ASCII and UTF-16LE, in a file or an image;
use it for a known identifier or a phrase such as the name of a key file. Its hits
carry context snippets that can themselves be the secret.

Browser password stores, password managers and keychains are protected by the
account's own material, and this pack provides no reader for them. Record that the
store exists, where, and that it was not examined; use one only where the case
supplies the material and the authority. A credential found there is an indicator,
not a credential to try: never test it against a live service, and do not read its
presence as reuse on the encrypted object.

A memory image, page file or hibernation file may hold material for a volume that
was mounted at capture. Say when and how it was captured and what it covers: a
mounted volume at one time does not put a key in a later capture. If the
memory-forensics pack is loaded, its `acquire/images` skill covers capture;
otherwise state the limit.

Escrow (a directory service, a cloud identity, a fleet manager) is requested as a
scoped export through its authorised custodian. Match the device, volume and
protector identifiers the record gives against the volume's metadata; record the
retrieval time, the source and any rotation history. Do not use found credentials
to sign in to any of these.

Shell history and configuration may hold a password given on a command line.
Retention, shell settings, session length and redaction decide what survives, so
"no match" is a search result (which file, which period), not proof that none was
used.

**Sensitive output.** `recovery_key_scan` and `ioc_scan` reach secret material:
run them as jobs with `secret_output: true`. `recovery_key_scan` answers with
locators; `write_values: true` (refused outside a job) writes values only to
`recovery-passwords.jsonl` under `$OUT`, which the job seals as sensitive. Cite a
value by its finding's file and offset, never by text. In the ledger and the report
write the source locator, the secret class, the non-secret identifier, the
authority, the method, the result and a sealed reference: never a password, a PIN,
a recovery value, a fragment of one, or a hash of one. Hand the value over through
the channel the operator named, and use it through a reader that takes it from a
sealed file, not from a command line; where no such reader exists, say so in the
report so the trace can be redacted before it is shared.

An opening that works shows the supplied material worked on that object. It does
not show who owned the material, that it was used before, or who used it.
