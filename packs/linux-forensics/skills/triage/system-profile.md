---
id: triage/system-profile
title: Build the system profile before anything else
when: The first ten minutes of any Linux case.
needs: [evidence/imaging]
tools: [timestamp_decode, image_layout, linux_triage]
requires_host: [fls, icat, target-query]
---

Everything later depends on these, and the timezone decides every timestamp you
will write.

For a disk image, start with `image_layout`, then `linux_triage`. The latter can
read a Linux root inside LVM without activating or mounting the evidence and
keeps its complete output per artefact family. Treat its empty files as parser
results, not automatic proof of absence.

    /etc/os-release              distribution, version, and the build id
    /etc/hostname                the name the logs will use
    /etc/timezone                the zone, as text
    /etc/localtime               a symlink into /usr/share/zoneinfo, which says the same
    /etc/machine-id              a stable identifier that survives a rename
    /proc/version (if captured)  the running kernel at collection time
    /etc/fstab                   what was mounted where, and with which options
    /var/log/installer/          on Debian and Ubuntu, when the machine was built
    /etc/network/ or /etc/netplan/ or /etc/NetworkManager/  addresses and DNS

The install date is not in one place. The oldest of `/etc/machine-id`'s own
inode creation time, `/var/log/installer/`, and the root file system's superblock
creation time (`dumpe2fs -h` or `fsstat`) is the usual answer, and you should
say which one you used.

**The timezone trap is the same as everywhere else, with one Linux twist.**
Files under `/var/log` written by rsyslog carry local time with no offset at
all; the journal stores UTC. So a case that reads both has two clocks in it
unless you convert, and the syslog side needs `/etc/timezone` to be converted.
Say in the report which zone you applied and to which sources.

Uptime and boot history come from `wtmp`, not from the file system: read it with
`utmp_parse`, take the `BOOT_TIME` records, and you have every boot the machine
recorded. That is the frame every other event sits in.

Then the two lists everything else refers to: the accounts, from
`accounts/users`, and what the machine was running, from
`persistence/mechanisms`.
