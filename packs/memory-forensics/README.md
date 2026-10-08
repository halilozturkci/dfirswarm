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

**Three tools.** `mem_profile` says what a memory file's header shows before
anything is run against it (a crash dump's physical-memory runs with their file
offsets, checked for order, overlap and payload; a LiME file's ranges; an ELF core's
byte order) and answers "unrecognised" for anything else, because a flat capture and
a file that is not memory look alike. `mem_carve` finds the byte signatures of
structures that other parsers read (a hive, an event log chunk, a Prefetch record),
says for each where the signature is, where the structure starts and what its header
supports, and cuts a fixed-size slice for the parser: a survey, not a recovery.
`mem_fs` starts MemProcFS for one call, lists a directory of its file tree or copies
chosen files byte for byte into the job's output, and stops it; the mount is gone
when it returns.
Whether MemProcFS contacts a symbol server is governed by the job's network policy; the tool
passes it no flag about that, and the pinned binary's behaviour was not verified in this review.

**Sensitive output.** Memory holds whatever the machine held. `mem_fs` writes file
content only when it runs as a job, only on `write_values: true`, and only under
`$OUT/mem_fs`; its answer carries the locator of each file, never its content or a
digest of it (`recovery_key_scan` of the encrypted-containers pack is the reference
implementation of that pattern). The tool cannot see whether the job was run with
`secret_output: true`, which seals every output of the job as sensitive: the skills
say to run it that way, and to run `aeskeyfind`, the Volatility plugins that print
command lines, environments or shell history, and YARA and `strings` match bytes
that way too. None of them writes a secret, a fragment of one or a hash of one into
a post, the ledger or the report.

**One goal template**: `memory-triage.md`.

## On Volatility

Volatility is declared as an optional host binary and is not imported or
vendored by this pack. The project keeps it at an executable boundary under
its own Volatility Software License 1.0; this is packaging policy, not a legal
conclusion about derivative works. The skills tell an agent to invoke `vol`
directly and to record the version and plugin with every result.

A production-ready memory image needs offline Windows ISF symbol tables. The
image built from this pack carries two sets (`requires/host.json`,
`install.data` of `vol`, with `volatility3` pinned at 2.28.2):

- **curated**: the exact kernels `requires/symbols.windows.json` lists, each a
  public PDB identity (name, GUID, age) with the PDB's sha256 and size and the
  content hash its table must have. The operator fetches the PDBs on the host
  (`scripts/swarm.sh symbols fetch`, which shows Microsoft's terms first); the
  image build converts each with Volatility's own `pdbconv`, checks the
  table's content (json-canon/1, without the conversion time) and keeps the
  table, never the PDB. A kernel a case needs is added here, as one entry.
- **broad**: the Volatility Foundation's `windows.zip`, a bundle of 2019 (last
  changed 2019-10-16), downloaded at build time against its sha256 and indexed
  once so no VM does it again. It covers the Windows builds of that time and no
  newer kernel.

`recipe.py build --symbol-set` chooses (`curated,broad` by default; `none` is
what CI builds), and an image says which it left out. The base pack's
`memory-windows` recipe names the kernel of a memory input at the kickoff when
the image lacks its table, which stops the start unless `--allow-missing-symbols`;
the skill still shows how to verify the table and fail closed when it is
absent, since silently fetching a PDB during case work is not an offline proof. The pack states no licence of its own. Our reading, not
legal advice: the Volatility Software License 1.0 says its "Software" includes
"any data (such as operating system profiles or configuration information)"
provided with the software, and the tables come from Microsoft's public symbol
files, whose Microsoft Symbol Server terms of June 2022 limit their use to
debugging and testing and say you may not "share, publish, rent, or lease the
Symbol Items, or provide the Symbol Items as stand-alone offerings for others to
use". Microsoft's terms grant use for debugging and testing your software;
whether examining a third party's memory image falls inside that is not decided
here. The image's NOTICE has both clauses in full. So the image is for the
machine that built it, and no workflow of ours pushes it anywhere, the private
one included (`images/README.md`).

`aeskeyfind` finds AES key schedules in a memory image (BSD-3-Clause, with
Debian's patches under GPL-2.0-or-later; Debian packages it for amd64 and i386
only, so the image builds it from Debian's source and patches on every
architecture), and `gcc` and `make` are there for a scanner a case needs that no
library provides. `avml` is declared so the operator has the pinned binary to take
to the source host: run in an analysis VM it captures that VM, not the subject.
Volatility's YARA plugins need a YARA Python binding that no requirement here
installs; `patterns/yara` says how to check.

MemProcFS is AGPL-3.0, the same licence as this harness, which is why the one
wrapper here is for that and not for the other.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/memory-forensics
    scripts/swarm.sh start --pack computer-forensics-base,memory-forensics ...
