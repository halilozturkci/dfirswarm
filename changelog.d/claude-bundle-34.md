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
The pack goes to 1.5.0. Measured: the router 329 of 400 tokens before and 364
after, the index 663 of 1,000 before and 736 after, the leaves 719 and 634.
