# Windows Forensics Pack

What a Windows examination actually needs: where each artefact family lives,
what it proves, what parses it, and the traps that make an answer wrong.

Depends on the Computer Forensics Base Pack, which carries the method that is
true of any platform.

## What it carries

**Fifty-two skills**, in ten families, each a short leaf: it opens with when to use
it and when not, gives the decision rules, and ends with what the artefact shows,
does not show and what to record. A topic that needs more has a second-level leaf
that its parent opens "only if" the question calls for it. An agent reads the
one-line index once and fetches a body only when it reaches that artefact family.

| Family | Skills (a second-level leaf is indented after its parent) |
| --- | --- |
| Registry | `registry/overview` (`registry/readers`), `registry/system-profile`, `registry/clock`, `registry/devices` (`registry/devices-dates`) |
| File system | `filesystem/mft` (`filesystem/timestamps`, `filesystem/indx`), `filesystem/journals`, `filesystem/ads`, `filesystem/deleted` (`filesystem/recycle-bin`), `filesystem/shadowcopies` (`filesystem/shadowcopies-open`) |
| Execution | `execution/overview`, `execution/prefetch` (`execution/prefetch-carved`), `execution/amcache`, `execution/shimcache`, `execution/userassist`, `execution/srum` (`execution/esedb`) |
| Logs | `logs/security` (`logs/events`), `logs/coverage`, `logs/powershell` (`logs/powershell-history`), `logs/recovery` (`logs/carving`), `logs/remote-access` (`logs/lateral`), `logs/hunting` |
| Accounts | `accounts/logons` (`accounts/sessions`) |
| Persistence | `persistence/mechanisms` (`persistence/tasks-com-wmi`) |
| Shell artefacts | `artifacts/shell` (`artifacts/links`, `artifacts/jumplists`, `artifacts/shellbags`) |
| Browsers | `browser/artefacts` (`browser/downloads`, `browser/webcache`, `browser/strings`) |
| Memory | `memory/windows` (`memory/hibernation-pagefile`) |
| Anti-forensics | `antiforensics/traces` (`antiforensics/wiping`, `antiforensics/log-clearing`, `antiforensics/timestamps-clock`, `antiforensics/controls`) |

**Twenty tools.** The parsers that carry most cases: `mft_records` (both time
sets, resident data, every named stream), `evtx_query` and `evtx_carve` (records
from a log, and records from a log that was cleared), `regkv`, `prefetch_mam`
and `mam_scan`, `amcache_apps`, `usn_journal`, `shellbags`, `jumplist`,
`lnk_parse`, `recyclebin_i`, `vss_stores`, `browser_history`, `indx_carve`, `sigma_hunt`,
`esedb_query`, `extract_stream`, `utf16_urls`, `yara_scan`.

What a tool measures, and what it does not, is in its manifest, and a tool says
what it did not read rather than hand back a clean answer for a run that did not
read everything: `partial` or `failed` in a `status` where it has one, and
otherwise its own counts (`structure_complete`, `unrecognised_bytes`,
`records_examined` against `parse_errors`). An exit status of 0 means the engine
ran, not that the examination is complete. Three of them can reach secret material and print none
of it: `browser_history` replaces the credential cells of Login Data, Cookies and
Firefox's key database by their length, `regkv` does the same for values that can
be secrets, and `yara_scan` returns where a rule matched, never the bytes it
matched; only `yara_scan`, in a job run with `secret_output: true`, can be asked
(`write_matches`) to write the matched bytes to a sealed file.

**Three goal templates** in `goals/`, each with its own questions, definition of
done and checks: `intrusion-triage.md`, `data-left-the-building.md`,
`hidden-data.md`. Pass one with `--goal-file`, or write your own beside them.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/windows-forensics
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics ...

The pack's Python requirements are in `requires/python.txt` and its host
binaries in `requires/host.json`. Nothing third-party is redistributed here: the
parsers install from PyPI and the binaries from the platform's own package
manager, or, in a VM image, from the pinned artefacts `host.json` names and the
image build checks by sha256 (Eric Zimmerman's tools with the .NET runtime they
run on, Zircolite from its tagged source; `images/README.md`), so no licence
travels with this pack but its own. Volatility is
declared as an optional host binary for the same reason: it is invoked as an
executable or not at all.
