---
id: recovery/routes-and-decryptors
title: Partial damage, deleted originals, decryptors
when: Files are partly encrypted, originals may be deleted, or a decryptor is to be tested.
needs: []
tools: [file_carver, recovery_validate]
requires_host: []
---

Use only if files are partly damaged, originals may survive deletion, or a decryptor is to be tested. Not for the preservation gate or the restoration position (`recovery/what-is-possible`).

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

**Public decryptors.** Looking one up, obtaining it, testing it on copies and keeping its provenance: `recovery/public-decryptors`.

**Checking an output.** `recovery_validate` checks what came back, run separately: it hashes the
output, tests the structure of its format, compares with known originals and the
ciphertext, and names the unrecovered ranges. Its verdict is one of
`matches_known_original`, `structurally_valid`, `unrecovered`, `inconclusive`; a
decryptor's exit code is not evidence, and a valid structure is not the original.

**Sensitive output.** Jobs that extract or handle recovered key material run with
`secret_output: true`. Do not place a key, a password or a hash of either in a
command, a report or the ledger; cite the sealed output by reference. A tool that can
take its key only on its command line puts it in the recorded trace: say so in the
report, so that the trace can be redacted before it is shared.

**Does not show.** Three entropy windows do not locate every modified region or show recoverability; a carved file does not show a recovery; failing one route does not show permanent loss.

Record: the carve's source offset and the checks of completeness and structure; for a decryptor's output, the verdict of each checked file.
