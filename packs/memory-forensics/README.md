# Memory Forensics Pack

Method and tooling for a memory image, including what to do when no framework is
available — which is more often than the literature suggests.

Depends on the Computer Forensics Base Pack.

## What it carries

**Nine skills.**

| Family | Skills |
| --- | --- |
| Triage | `triage/what-you-have`, `triage/no-framework` |
| Frameworks | `triage/volatility` |
| Processes | `processes/injection` |
| Network | `network/state` |
| Credentials | `credentials/material` |
| Strings | `strings/discipline` |
| Pattern matching | `patterns/yara` |
| Acquisition | `acquire/images` |

**Three tools.** `mem_profile` names the container before anything is run
against it — and prints a crash dump's memory runs, because a dump is not
contiguous and a tool that assumes it is reads the wrong offset for everything
after the first gap. `mem_carve` finds the structures inside the image that the
other packs' parsers already read, and cuts them out with their offsets.
`mem_fs` drives MemProcFS.

**One goal template**: `memory-triage.md`.

## On Volatility

Volatility is declared as an optional host binary and is not imported or
vendored by this pack. The project keeps it at an executable boundary under
its own Volatility Software License 1.0; this is packaging policy, not a legal
conclusion about derivative works. The skills tell an agent to invoke `vol`
directly and to record the version and plugin with every result.

A production-ready memory image needs an offline Windows ISF symbol pack. The
current image source does not declare that payload, so the skill shows how to
verify the cache and fail closed when the matching symbol is absent; silently
fetching a PDB during case work is not an offline proof.

MemProcFS is AGPL-3.0, the same licence as this harness, which is why the one
wrapper here is for that and not for the other.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/memory-forensics
    scripts/swarm.sh start --pack computer-forensics-base,memory-forensics ...
