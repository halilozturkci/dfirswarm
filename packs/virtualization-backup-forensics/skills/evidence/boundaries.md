---
id: evidence/boundaries
title: Planes of virtualization evidence, and handling
when: You are about to open VM images, hypervisor or backup exports and must scope and protect them.
needs: []
tools: [check_inputs]
requires_host: []
---

Use when you start on virtualization or backup evidence. Not for the contents of a guest (platform packs) or for one plane's detail (the skills in `router/start`).

1. **Name the plane each object belongs to.** Guest (inside the VM); VM files (disks, descriptors, configuration, snapshot state); hypervisor host (its configuration and logs); management server (inventory, tasks, events); backup server (catalogue, job and audit records, settings); repository or storage (backup files, retention or immutability state, replication). Each plane has its own clock and its own administrators. A finding on one is not a finding on another: a compromised guest does not show a compromised host, and the reverse.
2. **Work from copies and hash first.** Hash every descriptor, extent and export before reading (`check_inputs` of the base pack for the run's inputs). Take the whole set: a descriptor without its extents and parents, or a catalogue without its repository listing, answers less than it seems to.
3. **Read natively, never run the product.** Do not power on, register, import, clone, consolidate, commit, rebase, restore or "repair" an evidence VM or backup, and do not start the hypervisor or backup product against evidence: each can rewrite the chain, merge snapshots or prune restore points. Convert only a copy, to a separate output, and record the options.
4. **Credentials in the evidence are indicators, not logins.** A configuration or export may hold a console password, an API token or a repository key. Record where it sits and what it grants; do not use it against a live system. The pack's tools show a VM, snapshot or key name, a path or an id only if it is plain (letters, digits, `. _ - ( ) + [ ] ' # , & ~ % $`, 160 characters at most; a GUID, VMFS or `naa.` id), else `<withheld: N bytes, field F>` with the original in the `write_text` file of a job run with `secret_output: true`; hosts and free text have tokens, user-info and `password=` values withheld. A short plain password in a name is not recognised, a value in angle brackets after a secret's name is withheld unless it is a placeholder word (`<redacted>`), and a base64 key with a `/` can still leave a few characters of itself (at most 2 in 1,000 in tests).
5. **Say what the export is.** A product's export or log is that product's account of itself, at the time it was written, for the objects it kept. Record the product, version if shown, the time the export was taken, the account that took it, and what filter was applied.

**Shows.** Which plane an object belongs to and how far each source can speak. **Does not show.** That a plane is intact because another is, or that an export holds everything the system once did.
**Record.** Source, plane, hash, how and when the export was taken, version strings as written, and what was not supplied.
