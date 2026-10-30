# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `linux/router`

- `accounts/sessions-histories` Sessions and shell histories: Reading wtmp, btmp, lastlog and shell histories as leads.
- `accounts/users` Accounts, identities and authorization: Which identities and configured privileges could apply, without equating them with use.
- `containers/docker` Docker evidence locations and scope: Mapping supplied Docker metadata, logs, layers, volumes and host relationships.
- `containers/layers-times` Container layers, runtime metadata and times: Reading overlay layers, whiteouts, config timestamps, commands and environments.
- `containers/removed-logs` Removed containers and the daemon log: A container is gone and you ask what else records it, including the daemon's journal.
- `filesystem/ext` ext metadata and timestamps: Interpreting ext inode times and their relationships, with explicit limits.
- `filesystem/ext-deleted` ext deleted files and journal recovery: Deciding what an inode, the ext journal and listings say about a deleted file.
- `filesystem/storage` Linux storage layers and parser coverage: Identifying volume dependencies and parser coverage before examining a filesystem.
- `filesystem/storage-lvm-luks` LVM and LUKS on evidence copies: Mapping logical volumes and their files, and LUKS headers, without activating or unlocking.
- `filesystem/storage-xfs-btrfs-virtual` XFS, Btrfs and virtual disk images: A volume is XFS or Btrfs, or the disk is a VDI, VMDK, QCOW2 or VHD file.
- `linux/router` Linux notes by question: Pick one when none is listed, or you cannot choose.
- `logs/auth` Authentication and privilege-use records: Reading retained auth logs, their timestamp assumptions and attribution limits.
- `logs/auth-lines` What each auth log line shows: Interpreting ssh, sudo, su, PAM and account lines, and names typed at a prompt.
- `logs/auth-time` Auth log years, rollovers and parse status: Dating, ordering or counting auth log lines whose stamps have no year or zone.
- `logs/journal` Journal coverage and record identity: Examining supplied systemd journals without losing fields or boot coverage.
- `logs/journal-clocks-verify` Journal clocks, identity fields and verify: Ordering journal entries across clocks and boots, or judging journal integrity.
- `packages/baseline` Package comparison coverage and independent baseline: Stating what a package check covered and obtaining a baseline the machine did not write.
- `packages/integrity` Package integrity against the local database: Checking packaged files for differences against the acquired package database.
- `persistence/cron-timers` cron tables and systemd timers: Inventorying scheduled jobs with cron_dump and reading what it did not read.
- `persistence/mechanisms` Persistence examination and bounded coverage: Finding configured execution mechanisms and separating presence from observed execution.
- `persistence/quieter-routes` Shell, login and other quieter persistence routes: Sweeping startup files, PAM, preload, SUID files, modules and boot artefacts.
- `timeline/linux` Linux chronology across clocks and families: Building a reproducible timeline from independent evidence layers.
- `timeline/linux-normalise` Normalising and correlating a Linux timeline: Merging layers into UTC, ordering equal stamps and weighing a correlation or an absence.
- `triage/clocks-boots` Clocks, zones and boot history: Fixing the zone and year for timestamps and building the boot history.
- `triage/identity-files` Identity files and install date: Establishing release, hostname, machine id, mounts, network configuration and install date.
- `triage/system-profile` Linux system profile and acquisition: You start on a Linux target and must say what was acquired and what covers it.
