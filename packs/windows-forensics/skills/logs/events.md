---
id: logs/events
title: Event ids and logon types
when: You are about to say what an event id or a logon type means.
needs: [logs/security]
tools: [evtx_query]
requires_host: []
---

Use when you gloss an id or logon type from `evtx_query` rows. Not for reading the file (`logs/security`), what silence shows (`logs/coverage`) or joining a session (`accounts/sessions`).

An id alone names nothing: provider, channel and `Version` in the XML you hold decide it. Common readings, to be confirmed from that XML:

    Security  4624 logon (type, LogonId)      4625 failed logon (status, sub-status)
              4634 logoff, may be absent      4648 logon with credentials supplied
              4672 special privileges         4688 process created
              4697 service installed          4698/4699 scheduled task created/deleted
              4720/4722/4725/4726 account created/enabled/disabled/deleted
              4723/4724 an attempt to change / to reset a password
              4728/4732/4756 added to a global/local/universal group
              4719 audit policy changed       4616 system time changed (previous, new, process)
              4778/4779 window-station session reconnected / disconnected
              5140 share accessed             5145 share object checked for requested access
              1100 logging service shut down  1102 the audit log was cleared
    System    7045 service installed          7040 service start type changed
              104  a channel was cleared      6005/6006 logging service started/stopped
    Defender  1116 detection   1117 action taken (read its action and result)

- A detection is not a remediation: read what 1117 says was done and whether it succeeded.
- 5145 is an access check with the rights asked for, not a read or a copy.
- 4688 carries a command line only where that policy was on, so a missing field is not a missing command line.
- 4697 and 7045 are two subsystems' views of a service install: take both. Either shows an installed service, not that it ran.
- 4778 and 4779 are also written by local fast user switching: they show a window-station session, not a remote one, until the client address says otherwise (`logs/remote-access`).

Logon types name how a logon was requested:

    2 interactive   3 network   4 batch   5 service   7 unlock
    8 network cleartext   9 new credentials   10 remote interactive   11 cached interactive

Type 2 does not identify a person at the console. Type 3 does not identify an SMB operation or the user behind it. Type 8 does not by itself show a password crossing a network unprotected. Type 10 is a remote-interactive session, RDP among them.

Sensitive output: `evtx_query` rows carry command lines and typed text; run it as a job with `secret_output: true` where the log may hold them (`logs/security`).

Shows: how the provider classed the event. Does not show: intent, completion of the operation, or that the account's owner acted. Record: provider, channel, id, `Version`, and the fields you read the meaning from.
