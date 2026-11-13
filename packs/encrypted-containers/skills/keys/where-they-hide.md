---
id: keys/where-they-hide
title: Locating and safeguarding authorised key material
when: A case question requires access to encrypted evidence.
needs: []
card: Record the question, the encrypted object and the authority first; look first in what the case supplies. recovery_key_scan ({"path": "<directory or file>"}) locates recovery-password text and private-key headers: run it as a job with secret_output: true; {"write_values": true} writes values only to recovery-passwords.jsonl under $OUT. ioc_scan ({"path": "<file>", "needles": "<literal>"}) finds a literal you name. Cite file and offset, not the value. Does not show: that it opens this container.
tools: [recovery_key_scan, ioc_scan]
requires_host: []
---

Use when a case question needs access to encrypted evidence and you look for key material the case supplies. Not for how `recovery_key_scan` reads.

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

**recovery_key_scan** locates BitLocker recovery-password text, PEM private-key
headers and conventional key-file names. Only if you report what it found:
`keys/recovery-key-scan` says what it shows and does not.

**ioc_scan** finds a literal you name, in ASCII and UTF-16LE, in a file or an image;
use it for a known identifier or a key file's name. It answers with locators; the
bytes around a hit can be the secret and need `write_values`.

Only if the key may sit in a password store, a memory image, an escrow record or shell history: `keys/other-sources`.

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
