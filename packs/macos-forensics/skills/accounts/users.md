---
id: accounts/users
title: Accounts, sessions and attribution limits
when: Relate activity to accounts and distinguish local from remote sessions.
needs: [triage/system-profile]
tools: [plist_read, knowledgec_query, unified_log]
requires_host: []
---

On modern macOS `/etc/passwd` is a static compatibility file, not the local-account
database. Local accounts are directory-service records, one property list each:

    /private/var/db/dslocal/nodes/Default/users/<name>.plist
        uid, gid, home, shell, generateduid, and credential-bearing keys
    /private/var/db/dslocal/nodes/Default/groups/admin.plist
        the administrator group's membership
    /Library/Preferences/com.apple.loginwindow.plist
        automatic login, and the last user to log in
    the unified log (`unified_log`), and `/var/log/asl/` on older releases
        authentication evidence, subject to retention

Record account name, UID, GID, `generateduid`, home and shell, and say whether the
identity is local, cached or mobile, managed or network. A UID range is a triage
convention (0 is root, low UIDs are usually service accounts, interactive users
often begin at 501); managed, migrated and network accounts break it. A second UID 0,
or a low-UID account with an interactive shell and a home, still wants explaining.

**Sensitive output.** An account plist holds a password verifier (`ShadowHashData`),
and may hold Kerberos keys and a hint. Its presence is normal. Select the identifying
keys with `plist_read` (`key`); a whole account plist is read as a job with
`secret_output: true`, and the tool shows the verifier as a locator (a finding id, a
kind, a length). Write where it sits and how long it is, never its bytes, a preview
or a hash.

**Administrators.** Resolve membership from the acquired `admin` group record: read
every membership key it has (names, UUIDs, nested groups) and keep the references you
could not resolve. Directory-service membership is another route. Membership at
acquisition does not show membership at an earlier event.

**What file times are.** An account plist's or an `authorized_keys` file's mtime is
file metadata. It is not a password-change, account-creation, login or key-installation
event, and restoration, migration and replacement all move it. Treat the loginwindow
preferences as configuration or last state, not as a log.

**Attribution.** Attribute a recorded action first to the account, process or session
the source names. Then correlate authentication, console and session records, lock and
unlock, and application activity where they were retained (`unified_log`,
`knowledgec_query`). Screen-on and foreground-application records are device state:
they do not show keyboard input or physical presence, in a row or alone. Rule out
automatic login, a shared account, remote control and a background job, and say what
you could not rule out. Naming a person needs case evidence the artefacts here do not
supply; state separately what ties the account to the action and what, if anything,
ties a human to the account.

**Remote access is its own question.**
- SSH: read the acquired sshd configuration and the files it includes, the key
  locations and their restrictions, the user's `authorized_keys`, and the retained
  authentication and session records. Remote Login enabled plus an authorized key is a
  configured path in; it does not show that the host was reachable, that the key was
  accepted, or that anyone logged in.
- Screen Sharing and Remote Management: correlate
  `/Library/Preferences/com.apple.RemoteManagement.plist`, management configuration
  and session records. A preference's presence does not show an active service at the
  time.
- Never run the matching utility on the examiner's Mac: it describes that Mac.

**Does not show.** Who typed, when an account was made or its password changed, or
that a key was ever used. A missing local record may mean a network identity or a
collection gap, not that the account never existed.

Record the source path, the exact key or log record, the account and session
identifiers, the interval and the alternatives you weighed.
