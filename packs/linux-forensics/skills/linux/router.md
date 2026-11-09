---
id: linux/router
title: Linux notes by question
when: Pick one when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a Linux note. Not for rules: each note holds its own.

Start
`triage/system-profile` what was acquired and what covers it
`triage/identity-files` release, hostname, machine id, install date
`triage/clocks-boots` zone, year, boot history
`triage/volatile-state` disk, /proc, memory: what each holds

Storage and files
`filesystem/storage` volume layers, parser coverage
`filesystem/storage-lvm-luks` LVM, files from a volume, LUKS headers
`filesystem/storage-xfs-btrfs-virtual` XFS, VDI, VMDK, QCOW2, VHD
`filesystem/ext` ext inode times
`filesystem/ext-deleted` deleted inode, ext journal
`filesystem/timestamp-anomalies` ext4, XFS, Btrfs times

Logs
`logs/auth` auth logs, attribution limits
`logs/auth-lines` ssh, sudo, su, PAM lines
`logs/auth-time` no year or zone, rollovers
`logs/journal` systemd journal coverage
`logs/journal-clocks-verify` journal clocks, verify
`logs/auditd` audit.log events, rules
`applications/server-logs` web, proxy, app, database logs

Accounts
`accounts/users` identities, privileges
`accounts/sessions-histories` wtmp, btmp, lastlog, shell history
`accounts/session-accounting` utmp, wtmp, wtmpdb, lastlog2
`execution/history` shell and client histories

Persistence
`persistence/mechanisms` sweep frame, configured or run
`persistence/cron-timers` cron, systemd timers
`persistence/systemd` units, links, effective state
`persistence/quieter-routes` startup files, PAM, preload, SUID, modules

Packages, containers, time
`packages/integrity` files against the package database
`packages/baseline` coverage of a check, outside baseline
`containers/docker` Docker evidence scope
`containers/layers-times` overlay layers, config times
`containers/removed-logs` container gone, daemon log
`containers/runtime-orchestration` containerd, Podman, k8s nodes
`cloud/host-artifacts` cloud instance, agents
`timeline/linux` reproducible timeline
`timeline/linux-normalise` UTC merge, ties, correlation
