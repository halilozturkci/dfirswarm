### Added: ransomware-response has two platform leaves, `platforms/esxi-hypervisors` and `platforms/nas-storage`

Two method leaves of at most 800 tokens each. The ESXi leaf keeps the host, the
management plane, the guest and the datastore apart, lists what to preserve
(the version's support bundle, task and event records, authentication and shell
activity, machine configuration, virtual-disk descriptors, backing extents and
snapshot chains) and says not to consolidate a snapshot, power on, register or
migrate a machine, or reboot the host before the chain metadata is preserved.
The NAS leaf separates a client's writes, a compromised management plane and
replication of damaged data, lists the appliance records to preserve, and says
that imaging one RAID member is not a logical acquisition. Both route to the
virtualization pack's `virtualization_inventory`, `snapshot_chain_check` and
`backup_audit_normalise` only conditionally ("if the virtualization-backup-forensics
pack is loaded; check the run's tool inventory", `mentions:` only); no
dependency is added. `encryptor/backup-infrastructure` now points to the two
leaves for hypervisors and network storage instead of repeating them, and
`ransomware/router`, the index, the README and the `method_only` list name both.
The pack goes to 1.5.0 (1.6.0 with the next entry). Measured: the router 329 of 400 tokens before and 364
after, the index 663 of 1,000 before and 736 after, the leaves 719 and 634.

### Added: ransomware-response has two more method leaves, `intrusion/entry-and-spread` and `recovery/preserve-and-restore`

Each is at most 800 tokens, named once by `ransomware/router` and the index, and `method_only` in
the pack manifest. `intrusion/entry-and-spread` reconstructs initial access, persistence and
deployment as a graph of observed edges, correlates VPN, identity, mail, endpoint-detection,
service, task, remote-management and cloud-audit records, keeps the alternative routes and a
bounded observation window, and reproduces no exploit; it names the readers of the Windows, Linux,
cloud and network packs only conditionally (`mentions:` and "if the pack is loaded; check the
run's tool inventory"). `recovery/preserve-and-restore` states the minimum preservation package
before a rebuild, consolidation, repair, decryption or reconnection, the emergency exceptions and
the evidence each loses, isolated recovery tests, identity remediation, clean-build decisions and
authorised acceptance. Neither repeats a sentence of `scope/phase-timeline`, `scope/first-hour` or
`recovery/what-is-possible`; a test holds that. The pack goes to 1.6.0.
