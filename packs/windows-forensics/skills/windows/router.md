---
id: windows/router
title: Windows notes by question
when: Pick one when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a Windows note. Not for a note's own rules; those below hold for every note.

Always
- Keep the raw value beside every converted time and convert from it: FILETIMEs are UTC, FAT and DOS times the local clock.
- `ActiveTimeBias` is the offset when Windows last wrote it: never apply today's zone to a past date.
- Prefetch shows what the prefetcher recorded for one path: not who ran it, that it finished, or every run.

Machine
`registry/system-profile` build
`registry/overview` hive state; `registry/readers` key reads; `registry/clock` zones
`accounts/logons` SIDs; `accounts/sessions` who

Ran
`execution/overview` which source
`execution/prefetch` `execution/prefetch-carved` `execution/amcache` `execution/shimcache` `execution/userassist` `execution/srum`
`execution/esedb` ESE tables

Files
`filesystem/mft` `filesystem/ads` streams; `filesystem/indx` slack; `filesystem/journals` USN
`filesystem/timestamps` NTFS times; `filesystem/recycle-bin`; `filesystem/deleted` recoverable, thumbnails
`filesystem/shadowcopies` list; `filesystem/shadowcopies-open` read

Touched
`artifacts/shell` which to read
`artifacts/links` `artifacts/jumplists` `artifacts/shellbags`
`registry/devices` `registry/devices-dates` USB

Logs
`logs/security` read .evtx; `logs/events` ids; `logs/coverage` absence
`logs/hunting` Sigma; `logs/carving`; `logs/recovery` cleared
`logs/lateral` shares, services, WMI; `logs/remote-access` RDP
`logs/powershell` `logs/powershell-history`

Persist
`persistence/mechanisms` `persistence/tasks-com-wmi`

Browser
`browser/artefacts` `browser/downloads` `browser/webcache`
`browser/strings` raw text, SQLite, saved logins

Memory
`memory/windows` `memory/hibernation-pagefile`

Anti-forensics
`antiforensics/traces` missing, odd; `antiforensics/controls` exclusions, disabled
`antiforensics/log-clearing` `antiforensics/timestamps-clock` `antiforensics/wiping`
