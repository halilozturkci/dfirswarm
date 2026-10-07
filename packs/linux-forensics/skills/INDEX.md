# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `accounts/users` Accounts, identities and authorization: Establishing which identities and configured privileges could apply, without equating them with observed use.
- `containers/docker` Docker evidence locations, layers and scope limits: Mapping supplied Docker metadata, logs, writable layers, volumes and host relationships.
- `filesystem/ext` ext metadata, timestamps and recovery limits: Interpreting ext inode times or assessing deleted-file recovery with explicit limits.
- `filesystem/storage` Linux storage layers, XFS, Btrfs and virtual disks: Identifying volume dependencies and parser coverage before examining a filesystem.
- `logs/auth` Authentication and privilege-use records: Interpreting retained auth records, their timestamp assumptions and attribution limits.
- `logs/journal` Journal coverage, record identity and clock domains: Examining supplied systemd journals without losing fields or confusing clock order.
- `packages/integrity` Package integrity against local and independently trusted baselines: Checking packaged files for differences and establishing what the comparison covers.
- `persistence/mechanisms` Persistence examination and bounded coverage: Finding configured execution mechanisms and separating presence, activation and observed execution.
- `timeline/linux` Linux chronology across clocks and evidence families: Building a reproducible timeline with source dependencies and uncertainty preserved.
- `triage/system-profile` Linux identity, deployment and acquisition profile: Establishing the target, storage, clock assumptions and evidence coverage before detailed analysis.
