
### Added: ransomware-response has a sixth tool, `backup_destruction_correlate` (RAN-15 and RAN-16)

It keeps five observations apart per host and object: `command_seen`, `action_attempted`, `reported_outcome`,
`inventory_change_observed` and `recovery_loss_verified`. Each row carries the host, the actor as recorded, the source
record's reference, the time as recorded with its uncertainty (`host_clocks`) and the alternative explanations. It reports
a command with no inventory change, a change with no command, an exit status with no verified loss, a verified loss with
no command, and a command whose time falls inside or after the interval of the change, as flags; it never says that the
backups are gone. Inputs are the answers of other tools by reference, each versioned by its `parser` and an unknown one
refused by name: `evtx_query/4`, `vss_stores/5`, `regkv/4` (RAN-15); `backup_audit_normalise/2`,
`snapshot_chain_check/2`, `shell_history/14` and `cloudtrail_parse/6` (RAN-16; `backup_audit_normalise/3` is not read
until it exists). A snapshot-chain loss counts as verified only when the chain check shows a missing base or a
dependent file; a deleted snapshot with a whole chain is an action and a reported outcome. An inventory from an answer
that did not say `complete` is not compared. No event text is copied, so the tool declares no secret output. Measured: 500,000
event rows (268,559,214 bytes, 100,000 recognised) were read in 15.1 s at 40 MB resident. `only_objects` narrows the
rows and a rerun keeps the earlier file. `encryptor/destroyed-backups`, `encryptor/windows-evidence`,
`encryptor/backup-infrastructure` and `platforms/esxi-hypervisors` name it and are no longer `method_only`. The
RAN-15 and RAN-16 parts are one tool and one commit, because the tool is one file.
