---
id: accounts/logons
title: Accounts, SIDs, RIDs and groups on a machine
when: You build the account map, or must read a SID, a RID or a group membership.
needs: []
tools: [regkv]
requires_host: [regripper, RECmd]
---

Use when you establish which accounts exist and what rights they hold. Not for tying an account to a session or a person (`accounts/sessions`: read it only if you attribute activity).

    SAM\Domains\Account\Users    subkey names are the RIDs in hexadecimal
    SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList   full SID to profile path and state, load times where the build keeps them
    Security log    4720 4722 4725 4726 account changes, 4728 4732 4756 group changes (`logs/events`)

- Account metadata (names, enabled state, last logon, logon count) sits in SAM structures `regkv` does not decode; it withholds each user's `V` (`registry/readers`). Read the metadata with `regripper` or `RECmd` where the image carries one, recording plugin or batch file and version, and ask for metadata only. Without one, say it was not read: the RIDs (key names) and the SIDs in `ProfileList` remain observations.
- A machine SID is the prefix shared by the full SIDs of the local accounts you can see in `ProfileList` and in event fields; it is not taken from the presence of a policy key.
- Record the complete SID and its authority; a RID alone is no identity. RID 500 is the built-in Administrator and 501 the built-in Guest, even if renamed. Accounts a machine creates get RIDs from 1000 up, in creation order on that machine: a RID orders creation there, dates nothing, and a gap may be a deleted account. Tell local, domain, service and cloud-linked identities apart by authority before comparing them.
- Adjacent RIDs, or two creations seconds apart, are not a malicious creation: provisioning tools create accounts in bursts. Establish who created an account from the creating event's Subject account and LogonId (4720, with 4722 and the group events), against the estate's provisioning process and that session's administrative activity.
- Groups: membership of Remote Desktop Users or Administrators shows what the account was allowed to do, not that remote access occurred, why the member was added or by whom (the 4732 Subject; use is `logs/remote-access`).

Sensitive output: `regripper` and `RECmd` plugins can print hashes; run only the metadata ones.
Shows: which accounts, SIDs and group memberships existed in the state acquired. Does not show: who created or used an account, that an administrator account was used rather than created, or that an account with no record was unused. Record: full SID, RID, profile path, reader and version, key paths.
