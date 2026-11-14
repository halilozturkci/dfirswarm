---
id: accounts/attribution-remote
title: Attribution limits and remote access on a Mac
when: Tie an action to an account or a person, or decide whether a session was remote.
needs: []
card: knowledgec_query rows and unified_log entries name an account, process or session, not a person: screen-on and foreground-application rows are device state and do not show keyboard input or physical presence. Rule out automatic login, a shared account, remote control and a background job, and say what you could not. A partial knowledgec_query read is a prefix in start order: go on with after_start_raw and after_z_pk from resume. Remote Login plus an authorized key is a configured path in, not a login. Does not show: who typed, a person at the keyboard, or that a remote path was open or used.
tools: [knowledgec_query, unified_log]
requires_host: []
---

Use only if the question asks who acted or whether access came from afar. Not for listing the accounts (`accounts/users`).

**Attribution.** Attribute a recorded action first to the account, process or session the source names. Then correlate authentication, console and session records, lock and unlock, and application activity where they were retained (`unified_log`, `knowledgec_query`). Screen-on and foreground-application records are device state: they do not show keyboard input or physical presence, in a row or alone. Rule out automatic login, a shared account, remote control and a background job, and say what you could not rule out. Naming a person needs case evidence the artefacts here do not supply; state separately what ties the account to the action and what, if anything, ties a human to the account.

**Remote access is its own question.**
- SSH: read the acquired sshd configuration and the files it includes, the key locations and their restrictions, the user's `authorized_keys`, and the retained authentication and session records. Remote Login enabled plus an authorized key is a configured path in; it does not show that the host was reachable, that the key was accepted, or that anyone logged in.
- Screen Sharing and Remote Management: correlate `/Library/Preferences/com.apple.RemoteManagement.plist`, management configuration and session records. A preference's presence does not show an active service at the time.
- Never run the matching utility on the examiner's Mac: it describes that Mac.

Shows: which account, process or session a record names, and a configured path in. Does not show: who typed, a person at the keyboard, that a remote path was open or used.
Record: the source path, the exact key or log record, the account and session identifiers, the interval and the alternatives you weighed.
