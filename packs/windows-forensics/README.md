# Windows Forensics Pack

What a Windows examination actually needs: where each artefact family lives,
what it proves, what parses it, and the traps that make an answer wrong.

Depends on the Computer Forensics Base Pack, which carries the method that is
true of any platform.

## What it carries

**Fifty-three skills**: fifty-two leaves in ten families and the pack's router, `windows/router` (at most 500 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf). Each leaf is short: it opens with when to use
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

**Twenty-seven tools.** The parsers that carry most cases: `mft_records` (both time
sets, resident data, every named stream), `evtx_query` and `evtx_carve` (records
from a log, and records from a log that was cleared), `regkv`, `prefetch_mam`
and `mam_scan`, `amcache_apps`, `usn_journal`, `shellbags`, `jumplist`,
`lnk_parse`, `recyclebin_i`, `vss_stores`, `browser_history`, `indx_carve`, `sigma_hunt`,
`esedb_query`, `extract_stream`, `utf16_urls`, `yara_scan`, `registry_recover` (replays a hive's
transaction logs on a copy, never on the original, and says what it could not apply) and
`lnk_jumplist` (shell links and Jump Lists as rows with the place of every structure in the file,
the container's consistency, and a second read by `lnkinfo`) and `powershell_blocks` (script block
logging records, event 4104, reassembled into blocks with the fragments each block expects, has and lacks;
it carries no script text unless a secret-output job asks for it) and `vss_materialise` (copies
chosen files out of chosen shadow copies through a FUSE mount it always unmounts, tagged with the
snapshot's identity; without FUSE it answers `blocked: no FUSE` and writes nothing), `userassist_bam_shimcache` (UserAssist, BAM, DAM and ShimCache records with the raw bytes beside the decoded
fields, the layout and its basis, and `unsupported` for a layout it does not know; its offsets are from published notes, not checked
against real hives, and no second reader cross-checks it) and
`persistence_normalise` (scheduled tasks, services and autorun keys: the task XML files, the TaskCache, the service keys, the Run, Winlogon, AppInit,
IFEO and Active Setup entries and the events of an `evtx_query` result file as items with observations that are not verdicts; the WMI repository is not
examined and no second reader is started) and `srum_reader` (SRUDB.dat read through SrumECmd and dissect.target, every row naming the backend that produced it, with the
database's state, the unresolved ids counted and the table counts of the two compared; SrumECmd refuses to run off Windows, so in a Linux image only dissect.target can give rows, and neither backend's
shape has been checked against a real run).

**One recipe**, `windows-artefacts`, run on request over an extracted collection: it reads each
family of artefact it finds with the tool above that reads it (and runs a fixed list of
dissect.target's functions when that is installed and the target is one directory), keeps the
whole answer of every call, and writes `coverage.json` with `parsed`, `partial`, `empty`,
`unsupported`, `failed` or `not_attempted` for each family. `complete` there is not coverage of
the host.

What a tool measures, and what it does not, is in its manifest, and a tool says what it did not read
rather than hand back a clean answer for a run that did not read everything: `partial` or `failed`
in a `status` where it has one, and otherwise its own counts (`structure_complete`,
`unrecognised_bytes`, `records_examined` against `parse_errors`). An exit status of 0 means the
engine ran, not that the examination is complete. Several of them can reach secret material and keep
it out of their answers by shape or by name, not wholesale, so a secret of another shape is printed:
`browser_history` replaces the credential cells of Login Data, Cookies and Firefox's key database,
and the cells of columns named for a secret, by their length, and masks URL secrets by parameter
name and user-info (a token in a path or under another name is printed); `regkv` and
`registry_recover` do the same for values judged secret by name or place (a secret inside a value
that does not look like one, such as a command line, is printed); `lnk_parse` and `lnk_jumplist`
keep a link's arguments out of the answer and show a first word only when it is a program, a script
or a known switch name; `utf16_urls` masks URL secrets by parameter name and user-info; and
`yara_scan` returns where a rule matched, never the bytes it matched (its rule and string
identifiers are the rule file's words and are printed). Describe a found secret by where it sits,
its kind, length and what it grants, never by its value. `yara_scan`, in a job run with
`secret_output: true`, can be asked (`write_matches`) to write the matched bytes to a sealed file;
`registry_recover` and `lnk_jumplist` can be asked (`write_values`, `write_strings`) to write
theirs, and so can `browser_history` and `utf16_urls` (`write_url_secrets`), in a job run with
`secret_output: true`.

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
