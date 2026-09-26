# macOS Forensics Pack

What a macOS examination needs: where each artefact lives, what it proves, what
parses it, and the traps that make an answer wrong on this platform in
particular.

Depends on the Computer Forensics Base Pack.

## What it carries

**Eight skills**, in six families.

| Family | Skills |
| --- | --- |
| Triage | `triage/system-profile` |
| Artefacts | `artifacts/plists`, `artifacts/fsevents`, `artifacts/knowledgec` |
| Logs | `logs/unified` |
| Persistence | `persistence/mechanisms` |
| Accounts | `accounts/users` |
| File system | `filesystem/apfs` |

**Four tools.** `plist_read` (binary and XML property lists, with Apple
dates converted — the single commonest wasted hour on this platform),
`fsevents_parse` (the per-volume change log macOS writes whether anyone wants it
or not, with its flags decoded and its lack of any timestamp stated rather than
implied), `knowledgec_query` (foreground application, screen state and device
lock, joined and converted from the Apple epoch), `unified_log` (Apple's own
`log` command on macOS or Mandiant's pinned `unifiedlog_iterator` on Linux).

**One goal template**: `mac-compromise.md`.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/macos-forensics
    scripts/swarm.sh start --pack computer-forensics-base,macos-forensics ...

The pack's own tools use the standard library only — `plistlib` and `sqlite3`
are both in it, which is most of what this platform needs. Every host binary in
`requires/host.json` is optional.
