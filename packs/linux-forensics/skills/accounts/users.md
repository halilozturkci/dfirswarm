---
id: accounts/users
title: Accounts, keys, and who could become root
when: Attributing an action, or sweeping for an account that should not exist.
needs: [triage/system-profile]
tools: [utmp_parse, shell_history]
requires_host: []
---

    /etc/passwd    name, UID, GID, home, shell
    /etc/shadow    the hash, and the password-change date in days since 1970
    /etc/group     membership, and who is in sudo, wheel, docker or adm
    /etc/sudoers, /etc/sudoers.d/*   who may become root, and without a password
    ~/.ssh/authorized_keys           who may log in without one
    /var/log/wtmp, btmp, lastlog     successful logins, failed logins, last seen

UID ranges tell a story before you read anything else. UID 0 is root. The
system/human boundary is distribution and policy specific: read `SYS_UID_MIN`,
`SYS_UID_MAX`, `UID_MIN` and `UID_MAX` in `/etc/login.defs` instead of assuming
999/1000. **A second account with UID 0 is not a normal configuration**; nor is
a service account with an interactive shell or an unexplained home under
`/home`.

The `shadow` third field is the date of the last password change, in **days**
since 1970. A system account whose password was changed last Tuesday is the
whole finding.

Three additions that need no account at all:

- A key appended to `~/.ssh/authorized_keys`, which grants login without
  touching `/etc/passwd`. Check the file's own mtime against the session you are
  investigating, and check `root`'s copy first.
- A `NOPASSWD` line in `/etc/sudoers.d/`, usually in a file named after
  something plausible.
- Membership of `docker`, which is root by another route: anyone in it can mount
  the host file system inside a container.

`utmp_parse` reads the binary login databases: `wtmp` for successful sessions
with the source address, `btmp` for failures, and the distinct 32/64-bit
`lastlog` layouts for the last record stored per UID. Pass the evidence's
`/etc/passwd` when reading lastlog so UID slots are named. They are the
counterweight to text logs, and an attacker who
cleans `auth.log` frequently forgets them. When `wtmp` and `auth.log` disagree,
say so; that disagreement is evidence in itself.

Then read what each account did, with `shell_history`.
