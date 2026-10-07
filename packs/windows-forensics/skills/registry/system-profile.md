---
id: registry/system-profile
title: Windows build, names, profiles, volume identity
when: You need the machine's build, names and profile map before reading other artefacts.
needs: []
tools: [regkv, timestamp_decode, image_layout, lnk_parse]
requires_host: [fsstat]
---

Use when you establish the system context. Not for zone and clock rules (`registry/clock`) or account metadata (`accounts/logons`).

    SOFTWARE\Microsoft\Windows NT\CurrentVersion   ProductName CurrentBuild UBR DisplayVersion InstallDate RegisteredOwner
    SYSTEM\ControlSet00n\Control\ComputerName\ComputerName, ...\ActiveComputerName
    SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList   one subkey per SID
    SYSTEM\ControlSet00n\Services\Tcpip\Parameters\Interfaces\<guid>

Read the hives by `registry/overview`; each is a configuration state, not a history.

- Build: `ProductName` is a label and can name an earlier release. Decide from `CurrentBuild` with `UBR`, corroborate with a system file's version information where a tool in the image reads it, and cite the published build table you used with its date. `InstallDate` is a Unix-epoch number (`timestamp_decode`, record the epoch): it can date the last upgrade, not the first install. `RegisteredOwner` is text typed at setup. `ActiveComputerName` is the name in use since the last start, `ComputerName` the configured one; record both when they differ.
- Profiles: a `ProfileList` subkey maps a SID to `ProfileImagePath` and `State`, which ties a `Users\<name>` folder or a SID in an artefact to an account. Load and unload times, where the build keeps them, are a low and a high 32-bit word each that you combine into one FILETIME (record the words and field names). It is a profile-service record, not a session history: a loaded profile is not an interactive logon, and a missing unload does not mean the user was still there. For an interval corroborate with `accounts/sessions`.
- Volume: `fsstat` gives the filesystem serial and `image_layout` a `volume_serial` per partition; a link or jump list records a 32-bit serial of its own (`lnk_parse` prints eight hex digits). Compare like with like and say which digits. Equal serials support an association and do not prove one (a clone carries the same serial); keep a mismatch as a mismatch. Record partition, filesystem type and acquisition source.
- Network: the interface keys hold the addresses and DHCP lease times last written (numbers: `timestamp_decode`, record the epoch).

Sensitive output: `regkv` withholds by name and place only (`registry/readers`).
Shows: configuration as last written. Does not show: who used the machine, the original install date, a connection history, or a profile in use at a moment; a profile or interface key absent from one hive is not absent from the machine. Record: key path, value, build source and table, serial digits compared.
