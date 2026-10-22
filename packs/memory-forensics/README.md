# Memory Forensics Pack

Method and tooling for a memory image, including what to do when no framework is
available — which is more often than the literature suggests.

Depends on the Computer Forensics Base Pack.

## What it carries

**Twenty skills**, nine decision leaves, ten second-level leaves they point to
("only if X") and the router `memory/router` (at most 400 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf); every leaf is at most 800 tokens.

| Family | Skills |
| --- | --- |
| Triage | `triage/what-you-have` (second level: `triage/container-details`), `triage/no-framework` (`triage/carve-signatures`, `triage/paging-files`) |
| Frameworks | `triage/volatility` (`triage/volatility-symbols`, `triage/volatility-plugins`, `triage/volatility-catalogue`) |
| Processes | `processes/injection` (`processes/preserve-regions`) |
| Network | `network/state` (`network/timestamps-dns`) |
| Credentials | `credentials/material` (`credentials/key-schedules`) |
| Strings | `strings/discipline` |
| Pattern matching | `patterns/yara` |
| Acquisition | `acquire/images` (`acquire/avml-and-preserve`) |

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
implementation of that pattern). Both `mem_fs` and `mem_carve` declare `secret_output`
for `write_values`, so the harness seals the job as sensitive, and both check
`SECRET_OUTPUT=1` and refuse as JSON otherwise. `mem_carve` cuts slices out of an image
(credential hives included, deliberately: a cracking tool downstream stays available)
only with `write_values: true`, into a directory with mode 0700 (at most 1,000 slices a call; the slices count toward `max_results_bytes`, and the clock is looked at before each). What the tools print
from the capture, a name MemProcFS lists, a line the engine prints, a kernel release
and a build string, is judged first: a release and a build string are shown only when
they have the grammar of a version (a closed list of tags), names by shape (withholding is by shape, so a
plain password or a name under 16 characters is printed). The skills say to run
`aeskeyfind`, the Volatility plugins that print
command lines, environments or shell history, and YARA and `strings` match bytes
that way too. None of them writes a secret, a fragment of one or a hash of one into
a post, the ledger or the report.

**What the name boundary does not read.** Measured on planted keys (1,000 per cell: a name alone, then inside `proc_<k>.exe`, `<k>.dll` and `1234-<k>`), the share of keys printed whole is 0 to 0.6 per cent for base64 and base62 keys alone and up to 2.9 per cent in a process-name context (24 base62 characters 2.9, 20 bytes of base64 1.2); in an engine line, which a failure shows and which has no allow-list, base64 keys of 16 to 32 bytes 0 to 18 per cent, base62 keys of 20 to 32 characters 10 to 61, a 24-character base36 key 48 to 65 and a base64 key holding `/` 37 to 40. The prefixes of the AWS, GitHub, Slack, Stripe (`sk_live_`, `rk_live_`, `pk_live_`, `whsec_`), GitLab and SendGrid keys, JWTs, 40-digit hexadecimal keys and user-info were not printed in 3,400 plants per shape. Not read at all, and printed in every cell tried: UUID-shaped secrets, 16-digit hexadecimal secrets, tokens split by `.` or `:` into pieces under 16 characters, word passwords and passphrases; printed at the rates given: 14-character policy passwords (67 to 100 per cent), base32 seeds (43 to 46), licence keys of five groups of five characters (18 to 20) and 12-character fragments of a bcrypt hash (28 to 31). A name that matters is read in a job run as secret output, with `write_values`, and a kernel release or a build string is printed only when it fits a closed list of version tags.

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
