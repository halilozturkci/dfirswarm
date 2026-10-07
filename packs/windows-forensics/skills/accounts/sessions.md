---
id: accounts/sessions
title: From account to logon session to person
when: You tie activity to an account or logon session, or someone asks who was at the keyboard.
needs: [accounts/logons]
tools: [evtx_query]
requires_host: []
---

Use when you attribute activity. Not for the account map (`accounts/logons`) or event meanings (`logs/events`).

- Account to session, through the 4624 fields: computer, `TargetUserSid` and name, `LogonType`, `TargetLogonId`, authentication package, `IpAddress` and workstation name where present, and the Subject that requested it. A LogonId is unique within one computer and one boot only and can repeat after a restart; within that scope it joins the 4624 to the 4672, 4688 and 5145 that carry it and to the 4634 or 4647 that ends it. A missing logoff does not show the session stayed open.
- Activity in the user's own hive or shell records (`artifacts/shell`, `execution/userassist`) and a `ProfileList` load time are account-context evidence: something ran under that profile. Convert every time by `registry/clock`.
- Account to person: a record carries the token's account, not the human. A local interactive logon, a loaded profile and shell activity do not identify who operated the account; a service run as a user, a scheduled task, a batch logon, `runas` with other credentials (logon type 2, or 9 for network-only credentials), remote control, a shared credential and token impersonation all read like the user did it. Name the mechanism you claim and state separately what supports a human at that account and which alternatives stay open. Support is evidence outside the account's own logs, cited by name: physical-access or camera records, the account holder's statement, a record of who held the credential, a second authentication record. Without it the finding is "activity under account X in session Y".
- A negative about a logon carries its qualifiers: the audit subcategory may be off, the log may have rolled over, the logon may have happened on another machine or through a service (`logs/coverage`).

Sensitive output: `evtx_query` returns command lines and typed text; run it as a job with `secret_output: true` when the log may hold them.
Shows: an account in a session on one computer and boot. Does not show: who was at the keyboard, intent, or that an unrecorded account was unused. Record: computer, boot, LogonId, SID, logon type, source address, the mechanism claimed and what supports a human.
