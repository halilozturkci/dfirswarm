# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `accounts/users` Accounts, identities and authorization: Establishing which identities and configured privileges could apply, without equating them with observed use.
- `containers/docker` Docker evidence locations, layers and scope limits: Mapping supplied Docker metadata, logs, writable layers, volumes and host relationships.
- `filesystem/ext` ext4 timestamps, deleted inodes, and what Linux does not keep: You need a file's true times on ext, or whether something deleted is recoverable.
- `filesystem/storage` LVM, LUKS, XFS, Btrfs and virtual disks without mounting evidence: A Linux partition is a volume manager or encrypted container, or the file system is not ext.
- `logs/auth` The authentication logs, and what each line actually proves: Someone logged in, tried to, or raised their privileges.
- `logs/journal` The systemd journal: The host runs systemd and you need what the text logs do not carry.
- `packages/integrity` Package integrity against local and independently trusted baselines: Checking packaged files for differences and establishing what the comparison covers.
- `persistence/mechanisms` Where something arranges to run again: You have a payload and need to know how it survives a reboot, or you are sweeping for one.
- `timeline/linux` A Linux timeline is several clocks, not one sorted CSV: Building or checking the chronology of a Linux compromise.
- `triage/system-profile` Build the system profile before anything else: The first ten minutes of any Linux case.
