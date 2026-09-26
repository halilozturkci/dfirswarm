---
id: persistence/mechanisms
title: Where something arranges to run again
when: You have a payload and need to know how it survives a reboot, or you are sweeping for one.
needs: [triage/system-profile]
tools: [cron_dump, shell_history, linux_triage]
requires_host: []
---

Sweep these in order. The first three carry most real cases.

**systemd units and timers.**

    /etc/systemd/system/, /usr/lib/systemd/system/, ~/.config/systemd/user/
        ExecStart, User, and the [Install] WantedBy that makes it start
    *.timer files, and the *.service each one triggers

A unit whose name impersonates a distribution component but whose `ExecStart`
points outside `/usr/bin` and `/usr/sbin` is the shape to look for. Check the
unit file's own mtime and compare it against its neighbours: a directory where
every file is from the install date and one is from last month answers the
question on its own.

**cron.** `cron_dump` collects all of it into one list, including the environment
in force at each entry, because it is scattered:

    /etc/crontab, /etc/cron.d/*, /etc/cron.{hourly,daily,weekly,monthly}/
    /var/spool/cron/crontabs/<user>   the per-user tables, which crontab -l shows
    @reboot entries, which are persistence with no schedule

**Shell and login scripts.** `~/.bashrc`, `~/.bash_profile`, `~/.profile`,
`/etc/profile`, `/etc/profile.d/*`, `~/.zshrc`. A line appended to the bottom of
a 200-line file is the classic, and the file's mtime usually gives it away.

Then the quieter ones: `/etc/ld.so.preload` and `LD_PRELOAD` in a unit or a
profile script; a kernel module in `/etc/modules-load.d/` or a rootkit loaded
from `initramfs`; `/etc/rc.local`; a PAM module added to `/etc/pam.d/`; a SUID
binary that should not be one (`find / -perm -4000`); an `authorized_keys` entry
with a `command=` prefix; a git hook in a repository that a service pulls.

**The absence of all of them is a finding.** It says the operator expected to
return another way — a key, a web shell, a credential — or did not need to.
