
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

### Fixed: ransomware-response `backup_destruction_correlate` holds its clock in every walk and reads a hostile command in linear time

Two defects of the first version could hold a run past the manifest's timeout. The matching of a process-exit record
to its attempt walked every record of the same process id for each attempt (20,000 attempts and 20,000 exit records of
one id took 45.7 s at `max_seconds` 20); the records are now kept in order of time and the earliest at or after the
start is found by bisection, and the three phases after the reading (matching, comparing inventories, writing the
summary) look at the clock before each entry, may run 20 seconds past `max_seconds` at most, and when the clock stops one
the answer is partial and names how many attempts were not matched, comparisons not made or summary rows not written.
The `rm` recogniser was quadratic on a 64 KiB command (`rm -` and 32,000 `r` and 32,000 spaces held a run for about 750 s):
its repetitions are bounded now, a test times all thirteen recognisers on 64 KiB texts of several hostile shapes (the
worst took 0.03 s), and a command with more than twelve letters of flags on either side of the `r` or more than eight
spaces is no longer seen as `rm_recursive_on_a_backup_path`. Also: a command that is later than the last of the complete
inventories, or earlier than the first, is flagged apart (`command_seen_after_the_last_inventory`,
`command_seen_before_the_first_inventory`) and no longer as a command with no change; `reported_exit_without_verified_loss`
no longer says "attempted action" of an outcome-only backup job; a `shell_histories` text file carries no status of its
producer, so the answer says how many were read without their answer, and the optional `answer` of the entry (the
shell_history answer) is checked for its parser and its status; a complete `chains` table (or `events` table of an audit
answer) beside a cut one is read from its own page record and reads as complete; `2026-02-30` is not a time (the row has
none, a verification or an inventory that carries it is refused). The manifest lists the forms that fire as `command_seen`
without being run (`man lvremove`, `cat lvremove.txt`, `echo rm -rf /backups`), says that the observations file is
bounded only by the size of the inputs and the clock, and says that the tool writes no sealed text file (the plan for the
tool named one: a deviation for the owner to approve), and that a deleted snapshot seen only in a product's audit is an
action and an outcome, never an inventory change, because no snapshot inventory is an input (also for the owner).
