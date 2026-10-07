---
id: logs/remote-access
title: Remote Desktop records, inbound and outbound
when: You need to say whether and from where a Remote Desktop session reached this machine, or left it.
needs: []
tools: [evtx_query, regkv]
requires_host: []
---

Use when the question is an RDP session. Not for SMB, WMI, WinRM or tasks, or for joining hosts (`logs/lateral`, only if the session did more than log on).

A logon type in `logs/events` says a session was remote. Keep authentication, session creation, shell start, disconnect, reconnect and termination as separate observations; do not collapse them into "an access event".

**Inbound.** Correlate three channels by computer, account, source address, session id and time, after checking the event schema for the provider and version you hold:

    Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
        1149  user authentication succeeded (user, source network address)
    Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
        21 session logon   22 shell start   23 logoff   24 disconnected   25 reconnected
    Security   4624 type 10, 4625, 4778 reconnected, 4779 disconnected (client name, address)

- An 1149 alone is an authentication, not a usable session. A missing 21 can mean the connection did not become a session, or that the channel was off, rolled over or not collected: say which you excluded (`logs/coverage`).
- A source address is the peer as this machine saw it: a gateway, NAT, VPN or pivot host shows a hop, not the origin, and an address names an interface at a time (DHCP and DNS records are other sources).

**Outbound** leaves client-side traces, where present: the RDP client's channel `Microsoft-Windows-TerminalServices-RDPClient/Operational` (read its fields from the XML for the build), process records for `mstsc.exe` (4688 where audited, `execution/prefetch`), `.rdp` files and recent-item records (`artifacts/shell`), and in the user's NTUSER.DAT, read with `regkv`:

    Software\Microsoft\Terminal Server Client\Servers\<host>    UsernameHint
    Software\Microsoft\Terminal Server Client\Default           the addresses typed

These keys record client configuration and entries, not that a connection succeeded or when. A `Servers\<host>` key's last-write time is that key's last change, and `Default`'s the latest change to the list, not each entry (hive state and key times: `registry/overview`). The client's bitmap cache under the profile's `Terminal Server Client\Cache` may hold tiles of what the remote screen displayed; the pack does not reconstruct it, and tiles rarely give a whole screen, a time or whether anyone looked.

A negative names, per host, the channels and files read and those shown disabled or not supplied. Shows: that the machine recorded an authentication, a session event or a client entry, with a peer address as it saw it. Does not show: who was at the other end, what was done in the session, or that anything was transferred; a quiet session is not noise. Record: channels, record ids, account, address, session id, times with their clock, hive state.
Sensitive output: client names and usernames are in the XML; run `evtx_query` as a job with `secret_output: true` when the logs may hold more.
