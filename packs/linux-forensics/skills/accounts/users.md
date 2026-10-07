---
id: accounts/users
title: Accounts, identities and authorization
when: Establishing which identities and configured privileges could apply, without equating them with observed use.
needs: [triage/system-profile]
tools: [utmp_parse, shell_history, sqlite_query]
requires_host: []
---

    /etc/passwd, /etc/group        local accounts and groups (sudo, wheel, docker, adm)
    /etc/shadow                    a password verifier or a lock marker, and password-aging fields
    /etc/sudoers, /etc/sudoers.d/* sudo authorization
    ~/.ssh/authorized_keys         configured key authorization for one account
    /var/log/wtmp, btmp, lastlog   sessions, failures, last login per UID (classic format)

Local files are not a complete identity inventory. Read `/etc/nsswitch.conf`, the PAM configuration and any
SSSD, LDAP, AD or other identity-provider configuration: an identity that can authenticate may not be in
`/etc/passwd`. `/etc/shadow` holds a verifier; read credential-bearing files only in a sealed job with
`secret_output: true`, and report the account, what the field means and where it is, never the verifier, a
fragment of it or a hash of it.

**Candidates, not findings.** Record every UID-0 entry and every unusual account property as a review
candidate. `/etc/login.defs` states allocation policy, not a reliable human-or-service classification for
imported, hand-made or centrally managed identities; compare an account with provisioning records and its
authorised purpose. Shadow field 3 is the date of the last password change in days since 1970. It does not
establish when the account was created, who changed it or that the use was malicious, and an empty or zero
value has its own meaning, so read it before converting it to a date.

**SSH authorization.** A key in `authorized_keys` is a configured authorization candidate. Establish the
effective policy first: `sshd_config` and its includes, `Match` blocks, `AuthorizedKeysFile`,
`AuthorizedKeysCommand`, trusted CAs, principals and key options. The key's presence shows neither a
successful login nor an installation date, and the file's modification time is a copy or extraction time as
often as an edit time.

**sudo and groups.** Evaluate includes, aliases, Runas targets and command restrictions: `NOPASSWD` applies to the
matching authorization, not to every root command. Membership of a group that can reach a rootful container
daemon is a high-risk privilege path; establish the socket's permissions, the daemon's mode and the controls
in force before describing effective authority over the host.

**Sessions.** `utmp_parse` reads classic wtmp, btmp, utmp and lastlog in the layouts it names (read `layout`,
its basis and `byte_order` in the answer; it refuses an ambiguous lastlog layout and tells you to pass one).
It does not decode `lastlog2` or `wtmpdb`, which are SQLite databases: copy them with their -wal and -shm files
and open the copy read-only with `sqlite_query`. Inventory the rotated files and record decoding errors and
ambiguity. Session accounting is written by the applications and PAM modules configured to write it, so a
missing record does not exclude an authentication, and a session with no end record is not shown to be open.

**Histories.** `shell_history` is a lead source. A history file holds what the program saved and when it
wrote it; its `user` is `unknown` unless the evidence's `etc/passwd` gives that home to one account, and the
directory's name is not an account. A recorded command shows neither that it ran to success nor who typed it.
Keep source order, multi-line context and any recorded times, and allow for suppression (`HISTCONTROL`,
`HISTFILE` unset), concurrent shells, custom history paths and sessions that were never flushed.

**Does not show.** That an account existed at the incident time, that a configured privilege was used, who was
at the keyboard, or that a command ran. Corroborate with the authentication records (`logs/auth`), the journal
and audit records where they exist, and package or provisioning records.

**Sensitive output.** `/etc/shadow` content, key material and history commands can hold secrets. Run
`shell_history` as a job with `secret_output: true`, with `write_commands: true` to read the text; the answer
without it carries locators and lengths only. Cite file and record, never a verifier, a key or a hash of one.
