---
id: recovery/preserve-and-restore
title: The minimum preservation package before a rebuild
when: A rebuild, repair, decryption or reconnection is about to change a source.
needs: []
tools: []
requires_host: []
---

Use when a rebuild, consolidation, repair, decryption or reconnection is about to change a source. Not for the recovery position (`recovery/what-is-possible`), the first hour (`scope/first-hour`) or partial damage (`recovery/routes-and-decryptors`).

**The minimum package.** Before the first change to a system, hold for it: the
encrypted originals that matter, a sample of unaffected files, the notes, the
system's own logs and their configuration, the authentication and directory
records that touch it, the configuration of the service it ran, and an image or
a recorded reason why none was taken. Name the owner of each item and where it is
kept. If the package is incomplete, say what is missing, not that it was kept.

**Emergency exceptions.** A service the business or the public cannot do without
may come back before the package is whole. Decide each exception with the
authorised responder, write down who, when and why, and write down the evidence the
exception loses: a rebuild loses the disk and its slack, a consolidation loses the
snapshot chain, a repair loses the damaged state, a reconnection can spread what
remains. An exception covers one system, not the estate.

**Test in isolation first.** Restore, decrypt or repair a copy on a network that
cannot reach production and holds no credentials of it. Check the result against
what you can trust, then check the application, not only the files.

**Identity before reconnection.** A restored system that trusts the old
credentials, keys, tokens or trusts between domains hands access back. Record
which were reset or rotated, by whom and when, and which were not.

**Clean-build decisions.** For each system decide, and record the reason: rebuild
from known-good media, restore a copy and treat it as untrusted until examined,
or keep it in place under watch. A restore point taken during the dwell period
may carry the adversary's changes.

**Acceptance.** The authorised person accepts a system for service: write down
who, on what test results, with what known gaps and which monitoring.

**Shows.** What was held before each change, and what each exception cost.

**Does not show.** A rebuilt system does not show the compromise ended; a passing
application test does not show the data is whole; an accepted system does not show
the adversary is gone.

Record: the package per system (item, owner, location, hash), each exception with
its approver and its loss, the identity resets, the build decision, the acceptance.
Sensitive output: restored data, keys and credentials stay in the evidence store;
cite them by reference, never by value or hash.
