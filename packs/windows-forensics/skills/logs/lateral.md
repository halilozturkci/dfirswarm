---
id: logs/lateral
title: Shares, services, WMI and tasks across hosts
when: A session may have moved or run something on another machine, or arrived from one.
needs: [logs/remote-access]
tools: [evtx_query, mft_records]
requires_host: []
---

Use when you follow what a remote session did over SMB, services, WMI, WinRM or scheduled tasks, or join several hosts. Not for the RDP session itself (`logs/remote-access`).

Keep a connection, a share access and an operation apart:

    Security  4624 type 3 (LogonId, source address)   4648 credentials supplied
              5140 a share was accessed   5145 a share object was checked for the rights asked
    System    7045 a service was installed (Security 4697)
    Microsoft-Windows-WinRM/Operational          91 shell created, 169 authenticated
    Microsoft-Windows-WMI-Activity/Operational   5857, 5860, 5861 (5861: a permanent subscription)
    Microsoft-Windows-TaskScheduler/Operational  106 registered, 200/201 action started/completed
    Security  4698 created, 4699 deleted

- 5145 records an access check with the subject LogonId, share, relative target name and access mask; it is not a completed read, write or copy. Join it to the 4624 by LogonId on the same host (`accounts/sessions`), to object auditing and to endpoint records.
- A service installed shortly after a network logon from another host is a candidate remote-administration sequence: record the service name, image path and account, the logon and its source address, and whether the image exists and where it came from (`mft_records`, `filesystem/mft`). Deployment and support tools produce the same sequence; separate them with the estate's inventory and change records.
- Keep provider, event version, account, client machine or process where the record has one, activity and session identifiers and result codes. A permanent WMI subscription supports a subscription finding, not a remote origin (`persistence/tasks-com-wmi`). The pack does not parse the WMI repository, so a subscription's definition cannot be read here: say so.
- Pair a task's registration with its action start and completion (the result code is in the record) and check the TaskScheduler channel was enabled (`logs/coverage`).
- **Across hosts.** LogonIds, session ids and record ids belong to one host and one boot. Join on account (SID), source and destination address, share or target, and time, with each host's clock source and any known offset stated; time alone is supporting evidence. A session with no retained follow-on activity stays an access finding with limited visibility, bounded by what that host logs. If the network-forensics pack is loaded (look in the run's tool inventory) it can corroborate the path.

Shows: that a host recorded a share check, service install, subscription or task event tied to an account and a peer. Does not show: that content moved, what the service or task did, or where the other host was reached from without its own records. Record: host, channel, record id, LogonId, address, names and result codes.
Sensitive output: service arguments and task actions can hold a secret; run `evtx_query` as a job with `secret_output: true` when they may.
