# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `accounts/users` Accounts, keys, and who could become root: Attributing an action, or sweeping for an account that should not exist.
- `containers/docker` Containers, and where the evidence actually lives: The host ran Docker, containerd or Podman and the incident touched one.
- `filesystem/ext` ext4 timestamps, deleted inodes, and what Linux does not keep: You need a file's true times on ext, or whether something deleted is recoverable.
- `filesystem/storage` LVM, LUKS, XFS, Btrfs and virtual disks without mounting evidence: A Linux partition is a volume manager or encrypted container, or the file system is not ext.
- `logs/auth` The authentication logs, and what each line actually proves: Someone logged in, tried to, or raised their privileges.
- `logs/journal` The systemd journal: The host runs systemd and you need what the text logs do not carry.
- `packages/integrity` Which binary on this machine is not the one the distribution shipped: You suspect a replaced system binary, or you need to clear thousands of files quickly.
- `persistence/mechanisms` Where something arranges to run again: You have a payload and need to know how it survives a reboot, or you are sweeping for one.
- `triage/system-profile` Build the system profile before anything else: The first ten minutes of any Linux case.
- `timeline/linux` A Linux timeline is several clocks, not one sorted CSV: Building or checking the chronology of a Linux compromise.
