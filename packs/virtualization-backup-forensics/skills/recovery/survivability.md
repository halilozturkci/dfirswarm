---
id: recovery/survivability
title: Which recovery points survive, and could one be restored?
when: The question is whether a VM or dataset can still be recovered, and from what.
needs: []
tools: [snapshot_chain_check, backup_audit_normalise, virtualization_inventory]
requires_host: []
---

Use when you must say which recovery points stand and whether any can be restored. Not for decryptor evaluation or the order of recovery steps (the ransomware pack's `recovery/what-is-possible`, if loaded).

1. **List the protected objects** from the inventory (`virtualization_inventory`: VMs, disks, and the disks a configuration leaves out of snapshots or backups). A disk that was never protected has no recovery point to survive.
2. **List every candidate copy per object:** hypervisor snapshots, backup restore points, replicas, copies on other storage, offline or immutable copies, and exports. A snapshot on the same storage as the disk is not independent of it.
3. **Test each copy for five things,** recording evidence or "unverified" for each: the point exists (listing); its chain is whole (`snapshot_chain_check` on image-based chains; for a backup chain, the product's record of which full and increments it needs); the media is readable and the bytes are intact (a listing, a checksum the product keeps, a read); the key or credential to use it is held somewhere separate from what was damaged; and a restore has been tested, and by whom.
4. **A job record is not a restore test.** `backup_audit_normalise` shows what jobs reported; an application-consistent, tested restore is shown only by a restore record or a test someone ran. Say which.
5. **Dependencies on the damaged plane count.** A copy that needs the management server, the backup server's database, a key held on a compromised host, or an account that was misused is only as available as those are. Record the dependency.
6. **Age and gap:** the newest usable point per object and the interval since; the retention window; points that expired or were pruned (`backup/deletion-vs-loss`).
7. **State the position per object** as one of: restorable and tested; present with chain whole and untested; present with chain incomplete; absent in the listings examined; unknown (and why).

**Shows.** For each object, which copies the evidence says exist and what is known of their state. **Does not show.** That a point is clean, free of the damage, application-consistent, or restorable within a time.
**Record.** Per object: copies, each of the five tests with source or "unverified", dependencies, the newest usable point, and the evidence that would settle the unknowns.
**Sensitive output.** Run the three tools as jobs with `secret_output: true`; a key or credential a copy needs is cited by where it is held, never written. Names, paths and ids are shown only if plain, else `<withheld: N bytes, field F>`; free text has secrets withheld; a short password in plain text passes unseen.
