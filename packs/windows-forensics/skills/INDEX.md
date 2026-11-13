# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `windows/router`

Core: `registry/clock`, `execution/prefetch`

- `accounts/logons` Accounts, SIDs, groups: Account map; read a SID, RID or group.
- `accounts/sessions` Account, session, person: Tie activity to an account or session.
- `antiforensics/controls` Controls changed: Exclusion, disabled protection, deleted VM disk.
- `antiforensics/log-clearing` Cleared logs: Empty or cleared log; missing snapshots.
- `antiforensics/timestamps-clock` Timestamp, clock changes: File times disagree; clock moved?
- `antiforensics/traces` Absence before intent: Missing or inconsistent artefacts.
- `antiforensics/wiping` Wiping leads: Overwritten files; a wiping tool appears.
- `artifacts/jumplists` Jump Lists: Recent and pinned items.
- `artifacts/links` Shell links: Read a .lnk, or carve link structures.
- `artifacts/shell` Links, Jump Lists, ShellBags: Which one traces a path or share.
- `artifacts/shellbags` ShellBags: Read BagMRU, RecentDocs, OpenSavePidlMRU.
- `browser/artefacts` Browser profiles: Navigation, apart from sync.
- `browser/downloads` Download provenance: Source of a file; did it finish?
- `browser/strings` URL strings, SQLite: URL text in raw bytes; read a SQLite file.
- `browser/webcache` WebCache, index.dat: WebCacheV01.dat or index.dat files.
- `execution/amcache` Amcache: Identify a file by path or hash.
- `execution/esedb` ESE databases: Export tables from SRUDB.dat and others.
- `execution/overview` Execution evidence: Cite one, or choose among them.
- `execution/prefetch` Prefetch: A .pf file: run count, last runs.
- `execution/prefetch-carved` Carved Prefetch: No .pf; image or pagefile may hold records.
- `execution/shimcache` ShimCache, AppCompatCache: Records of files seen.
- `execution/srum` SRUM: Application byte counts, CPU, network; limits.
- `execution/userassist` UserAssist, BAM, DAM: Program activity by profile.
- `filesystem/ads` NTFS data streams: List, extract or date alternate streams.
- `filesystem/deleted` Deleted content: Missing files: recoverable here?
- `filesystem/indx` Index slack: Names a directory index still holds.
- `filesystem/journals` NTFS journals: What changed on a volume, in order.
- `filesystem/mft` MFT records: Names, streams, allocation, deletion state.
- `filesystem/recycle-bin` Recycle Bin $I: Original path, size, time.
- `filesystem/shadowcopies` Shadow copies: Which snapshots an image holds.
- `filesystem/shadowcopies-open` Reading a shadow copy: An earlier hive, log or file.
- `filesystem/timestamps` NTFS time sets: Two sets disagree, or you quote an NTFS time.
- `logs/carving` Carved event records: Run or quote an evtx_carve sweep.
- `logs/coverage` Gapped logs: Before saying an event or channel is absent.
- `logs/events` Event ids, logon types: What an id or logon type means.
- `logs/hunting` Sigma review: Rule search over logs; read detections.
- `logs/lateral` Lateral movement: Shares, services, WMI, tasks across hosts.
- `logs/powershell` PowerShell logs: Event records and script blocks.
- `logs/powershell-history` PowerShell history: ConsoleHost_history.txt, -EncodedCommand, engine 2.
- `logs/recovery` Recovering cleared logs: Other sources may hold the records.
- `logs/remote-access` Remote Desktop: Whether, and from where, a session came.
- `logs/security` Reading .evtx: Read, filter or quote .evtx records.
- `memory/hibernation-pagefile` Hibernation, pagefile: hiberfil.sys, pagefile.sys, swap.
- `memory/windows` Windows memory: Image, dump, hiberfil: format, route, limits.
- `persistence/mechanisms` Services, run keys, startup: Configured or fired.
- `persistence/tasks-com-wmi` Tasks, COM, WMI, replaced binaries: Persistence kept there.
- `registry/clock` Windows clocks: Convert or compare a Windows time.
- `registry/devices` Removable devices: Identity, mounts; attachment is not transfer.
- `registry/devices-dates` Device dates: First, last or recent attachment.
- `registry/overview` Registry hives: Offline hive: state, control set.
- `registry/readers` Reading with regkv: What it withholds; a second reader.
- `registry/system-profile` Build, names, profiles: Machine profile first.
- `windows/router` Windows notes by question: Pick one when none is listed, or you cannot choose.
