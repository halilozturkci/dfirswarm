---
id: accounts/users
title: Accounts, sessions and attribution limits
when: Relate activity to accounts and distinguish local from remote sessions.
needs: []
card: plist_read with {"key": "uid"} (gid, generateduid, home, shell) selects identifying keys; a whole account plist holds a password verifier: read it only as a job with secret_output: true and write where the verifier sits and its length, never its bytes or a hash. An account plist's mtime is not a creation, password-change or login event. Does not show: who typed, or membership at an earlier event.
tools: [plist_read, unified_log]
requires_host: []
---

Use when you list the local accounts or relate an action to an account. Not for attributing activity to a person or for remote access (`accounts/attribution-remote`, only if the question names who or how from afar).

On modern macOS `/etc/passwd` is a static compatibility file, not the local-account database. Local accounts are directory-service records, one property list each:

    /private/var/db/dslocal/nodes/Default/users/<name>.plist
        uid, gid, home, shell, generateduid, and credential-bearing keys
    /private/var/db/dslocal/nodes/Default/groups/admin.plist
        the administrator group's membership
    /Library/Preferences/com.apple.loginwindow.plist
        automatic login, and the last user to log in
    the unified log (`unified_log`), and `/var/log/asl/` on older releases
        authentication evidence, subject to retention

Record account name, UID, GID, `generateduid`, home and shell, and say whether the identity is local, cached or mobile, managed or network. Select those keys with `plist_read` (`key`: `uid`, `gid`, `generateduid`, `home`, `shell`). A UID range is a triage convention (0 is root, low UIDs are usually service accounts, interactive users often begin at 501); managed, migrated and network accounts break it. A second UID 0, or a low-UID account with an interactive shell and a home, still wants explaining.

**Sensitive output.** An account plist holds a password verifier (`ShadowHashData`), and may hold Kerberos keys and a hint. Its presence is normal. Select the identifying keys with `plist_read` (`key`); a whole account plist is read as a job with `secret_output: true`, and the tool shows the verifier as a locator (a finding id, a kind, a length). Write where it sits and how long it is, never its bytes, a preview or a hash.

**Administrators.** Resolve membership from the acquired `admin` group record: read every membership key it has (names, UUIDs, nested groups) and keep the references you could not resolve. Directory-service membership is another route. Membership at acquisition does not show membership at an earlier event.

**What file times are.** An account plist's or an `authorized_keys` file's mtime is file metadata. It is not a password-change, account-creation, login or key-installation event, and restoration, migration and replacement all move it. Treat the loginwindow preferences as configuration or last state, not as a log.

**Does not show.** Who typed, when an account was made or its password changed, or that a key was ever used. A missing local record may mean a network identity or a collection gap, not that the account never existed.

Record the source path, the exact key or log record, the account and session identifiers, the interval and the alternatives you weighed.
