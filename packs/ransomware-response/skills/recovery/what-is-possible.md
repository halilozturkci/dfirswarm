---
id: recovery/what-is-possible
title: Assessing and validating recovery without destroying evidence
when: The organisation needs a defensible recovery position and restoration plan.
needs: [encryptor/destroyed-backups]
tools: [encrypted_survey, file_type, file_carver]
requires_host: []
---

Keep apart a plausible route to recovery, a tested recovery result and a service
that is usable. State uncertainty in both directions: optimism and pessimism are not
substitutes for validation.

**Preservation gate.** Before any decryption, repair or restoration, preserve the
encrypted originals that matter, representative unaffected files, notes, metadata,
logs, recovery inventories and any keys, under the case's evidence controls. Record
source identity, integrity check, custody and collection limits. Work on separate
copies and keep a map from each output to its original. If urgent service
restoration goes before full preservation, record who decided, what was preserved and
what was lost.

**Files without confirmed encryption.** `encrypted_survey` names candidates from an
extension and entropy; a file in `noncandidate` was not shown to be unaffected, one in
`unmeasured` was not measured (4096 bytes or less, or the read budget ran out) and one
in `read_failed` was not read. Compressed, packed and already-encrypted files are false
positives; small files, names that are unchanged or that lose the original extension, and
encryption outside the sampled windows are misses. Validate representative files with format-aware parsing and, where there is
one, a trusted pre-incident copy; `file_type` says what the first bytes show. A readable
header is not an intact file, and an intact file is not a consistent application
dataset. Report the population tested and the denominator, and do not extrapolate an
unrepresentative sample to the estate.

**Surviving copies.** Check independent backups, offline copies, immutable objects,
cloud versions, snapshots, replicas and other authorised originals. Establish their
date, completeness, required keys and dependency chains. Replication can carry
damage, and a backup can hold an earlier compromise. A successful job or a mountable
filesystem does not show that the application can be restored safely.

**Partial encryption or corruption.** Three entropy windows do not locate every
modified region and do not show recoverability. Use format-aware analysis, a wider
byte-range comparison and known-good copies where they exist. A readable region may
yield fragments while the metadata or index that makes them usable is gone. Virtual
disks and databases need specialist validation of their format and their dependent
files. Record exactly which objects or records came back and which did not.

**Deleted originals.** An original may survive a family that writes a new file and
deletes the old one, but it is not guaranteed: weigh overwrite, fragmentation, TRIM or
discard, flash garbage collection, thin provisioning, deduplication, encryption and
the limits of a logical collection. `file_carver` extracts, at an offset you give it
and for a signature type, what the header and footer markers delimit: a candidate, not
a recovered file. Check its completeness and structure and keep its source offset.
Encryption in place does not exclude an older copy elsewhere.

**Public decryptors.** Use only a tool the operator supplied whose provenance was
checked and whose documented support matches the variant. Keep its version, hash,
source and instructions. Test on disposable copies of representative files, large
files and the relevant formats included, never over an original. Compare what comes
back with trusted originals where they exist, and check structure and application
behaviour: a success message is not enough. Never run a decryptor that came from the
evidence.

**Sensitive output.** Jobs that extract or handle recovered key material run with
`secret_output: true`. Do not place a key, a password or a hash of either in a
command, a report or the ledger; cite the sealed output by reference. A tool that can
take its key only on its command line puts it in the recorded trace: say so in the
report, so that the trace can be redacted before it is shared.

**Restoration gate.** Give the response team a tested recovery position, the
remaining compromise concerns, the credential and identity remediation needed, the
clean-build requirements, the dependency order and the monitoring needed. Services
reconnect only under the authorised restoration plan.

Use bounded wording: "no supported recovery method was established for these objects
with the evidence, keys and tools available on this date", and name what would change
it: a key, a copy, a specialist examination, a public release. A finding of permanent
loss does not rest on entropy readings, on a failed decryptor test or on one failed
route; name the routes tried.

**Does not show.** A candidate count does not show what is lost or what survives; a
carved file does not show a recovery; a tested copy does not show the service works.
