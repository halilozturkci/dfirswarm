# Memory Forensics Pack

Method and tooling for a memory image, including what to do when no framework is
available — which is more often than the literature suggests.

Depends on the Computer Forensics Base Pack.

## What it carries

**Twenty-nine skills**, eighteen decision leaves, ten second-level leaves they point to
("only if X") and the router `memory/router` (at most 500 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf); every leaf is at most 800 tokens.

| Family | Skills |
| --- | --- |
| Triage | `triage/what-you-have` (second level: `triage/container-details`), `triage/no-framework` (`triage/carve-signatures`, `triage/paging-files`), `triage/address-spaces`, `triage/coverage`, `triage/memprocfs`, `triage/process-dumps` |
| Frameworks | `triage/volatility` (`triage/volatility-symbols`, `triage/volatility-plugins`, `triage/volatility-catalogue`) |
| Symbols | `symbols/macos` (no support claim for any macOS version), `symbols/linux` |
| Artefacts | `artifacts/reconstruction` |
| Processes | `processes/injection` (`processes/preserve-regions`), `processes/kernel-integrity` |
| Time | `timeline/memory` |
| Network | `network/state` (`network/timestamps-dns`) |
| Credentials | `credentials/material` (`credentials/key-schedules`) |
| Strings | `strings/discipline` |
| Pattern matching | `patterns/yara` |
| Acquisition | `acquire/images` (`acquire/avml-and-preserve`) |

**Nine tools.** `mem_profile` says what a memory file's header shows before
anything is run against it (a crash dump's physical-memory runs with their file
offsets, checked for order, overlap and payload; a LiME file's ranges; an ELF core's
byte order) and answers "unrecognised" for anything else, because a flat capture and
a file that is not memory look alike. `mem_carve` finds the byte signatures of
structures that other parsers read (a hive, an event log chunk, a Prefetch record),
says for each where the signature is, where the structure starts and what its header
supports, and cuts a fixed-size slice for the parser: a survey, not a recovery.
`mem_fs` starts MemProcFS for one call, lists a directory of its file tree or copies
chosen files byte for byte into the job's output (with a ranges file for each: the ranges read, the ranges
unavailable or not copied, and the zero-filled pages, which are zeros, not proof of missing data), and stops it; the mount is released
when it returns, unless the clean-up failed (an engine that cannot be ended, an unmount helper
that does not answer): the answer then names a `cleanup` problem and the mount may remain.
Whether MemProcFS contacts a symbol server is governed by the job's network policy; the tool
passes it no flag about that, and the pinned binary's behaviour was not verified in this review.
`vol_readiness` asks, before an examination, whether Volatility 3 can be used here and, with an image, on that image: offline
(every call carries `--offline`, and the tool fetches nothing), in four views that each say `ready`, `blocked` or `unknown`: the plugins `vol`
lists (as it lists them, and whether the names asked for are among them), the symbol table of the image's kernel (a Windows table by PDB, GUID
and age; a Linux or macOS banner matched exactly against `isfinfo`), whether a YARA binding imports in the Python that runs `vol`, and whether FUSE is
usable (`/dev/fuse` opens and a `fusermount3` or `fusermount` is on PATH; absence is `blocked`). It is not a plugin result, writes nothing from the
capture to a file, and was run against a stand-in `vol` in this review: the real Volatility's listing, `windows.info` and `isfinfo` output were not
exercised here. On a host or image without `/dev/fuse` or a `fusermount3`/`fusermount` (the image build installs only `libfuse2`), the FUSE view answers `blocked`; that is correct, not a defect.

`mem_registry` is opt-in: it lists the registry hives of a Windows image and reads one key of one hive (`windows.registry.hivelist` and `windows.registry.printkey`, the names taken from what the installed `vol` lists), offline, with the hive offset, the plugin and the Volatility version on every record and a coverage of hives found against hives read (partial when pages were missing). The SAM and SECURITY hives, and keys under SAM, SECURITY, `PolicySecrets` and `SAMDomains`, are refused unless `write_values` is set in a job run as secret output; the value of a credential-named key or value is withheld whole (by name, not by content) and written, unjudged, to a 0600 file under `$OUT/mem_registry` only then. Like `vol_readiness`, it was run against a stand-in `vol` in this review, with hand-written fixtures of the documented columns, not against the real Volatility.

`carve_handoff` takes one hit of `mem_carve` (`kind`, `signature_offset`) and readies it for the parser that reads it, without parsing: the structure's start (a plain Prefetch record four bytes before `SCCA`, only when those bytes are a known version), the cut by `mem_carve`'s own rule, the header checks and, for a registry hive (base-block checksum, sequence numbers, chain of bins) and an event log file or chunk (chunks, header checksum), whether the pages stay adjacent in the image. It hashes the slice only for a family that cannot be a credential store (a hive, a SQLite database and a property list never are hashed) and writes slice bytes only with `write_values` in a job run as secret output. It names the windows-forensics tools that read the family (`regkv`, `evtx_carve`, `mam_scan`, `prefetch_mam`) and calls none of them, so it depends on that pack not at all.

`vol_views` puts one named question to the installed Volatility on an image, offline, and keeps the engine's whole answer: `question` names a plugin as the installed `vol` lists it (a name it does not list is refused, and none is guessed), `readiness` is the `ready` answer of `vol_readiness` for that image, and the output comes back with its scope and a status. Every line is split at its tabs and each cell judged by the same rules as the other tools, paged with the whole judged output in a file whose size and sha256 are given; the raw output and the files a plugin's own dump option exports are kept only with `write_values` in a job run as secret output, with their digests in a `manifest.jsonl` beside them and never in the answer. A Linux or macOS question stays blocked until `vol_readiness` finds a table for it. Run against a stand-in `vol` in this review, like the other two Volatility tools.

`isf_intake` turns the debug material an operator supplies for a Linux kernel (a vmlinux or debug-symbols file, or a System.map) into an ISF with `dwarf2json`, and says `ready` only when the table's own `linux_banner` is, character for character, a banner `vol` finds in the image and the stated build identity agrees (a near release is no match; a System.map has no banner and cannot be ready). It records the converter's version and argv, keeps a table only when it is ready, and promises nothing beyond the match; macOS is not handled. `dwarf2json` 0.9.0 is declared in `requires/host.json` as a pinned download for amd64 (the project publishes no arm64 build, so an arm64 image records it as not installed); where it is not on PATH the tool fails with verdict `blocked`. Run against stand-ins in this review, not against the real converter.

`minidump_map` reads a Windows process dump (a minidump, `MDMP`: what procdump, Task Manager or WerFault writes of one process), which is not a memory image and which no framework of this pack reads. It parses the header and the directory from the published layouts (standard library only, no program started) and answers one `view` a call: `summary` (flags and the kind of dump, system, process, exception, the writer's comment, handle counts, the command line through the PEB, mapped bytes), `modules`, `memory` (ranges with the protection the MemoryInfoList records, or the regions themselves), `threads` (x86 and x64 register values), `va` (address to file offset, or "not in the dump"), `read`, `module` and `find`. Three rules are built in: an address that is not in the dump is never read as zero; a module or range with gaps is written only with `allow_gaps`, then zero-filled, named `.gaps`, mapped in a file beside it and answered `partial`, with `coverage_percent` in every answer; and a search (`find`, a text needle as UTF-8 and UTF-16LE or a hex needle) reads the dump in 8 MiB pieces and reports the virtual address and file offset of each hit, bounded by `max_hits` and its own clock with a resume address. A truncated or malformed dump gives a `partial` that names the stream and the file offset. `read` and `module` write memory content only with `write_values` in a job run as secret output (`$OUT/minidump_map`, 0700/0600, digests in `manifest.jsonl`); strings from the dump go through the same SHOWN rules as the other tools. It does no symbol resolution, stack walk or disassembly. Skill: `triage/process-dumps`.

**Sensitive output.** Memory holds whatever the machine held. `mem_fs` writes file
content only when it runs as a job, only on `write_values: true`, and only under
`$OUT/mem_fs`; its answer carries the locator of each file, never its content or a
digest of it (the one digest it names is that of a file's ranges file, which holds offsets and lengths; `recovery_key_scan` of the encrypted-containers pack is the reference
implementation of that pattern). `mem_fs`, `mem_carve`, `mem_registry`, `carve_handoff`, `vol_views` and `minidump_map` declare `secret_output`
for `write_values`, so the harness seals the job as sensitive, and all six check
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
library provides. `avml` is declared, with its pinned download, so the operator has the exact binary to take
to the source host; it is not installed in the image (`not_in_image`), because run in an
analysis VM it captures that VM, not the subject.
Volatility's YARA plugins need a YARA Python binding; `requires/python.txt` declares `yara-python` (pinned with `==`; its wheels for arm64 and for the
image's Python 3.11 were not checked, and the owner's image rebuild applies it), and `vol_readiness` says whether it imports.

MemProcFS is AGPL-3.0, the same licence as this harness, which is why the one
wrapper here is for that and not for the other.

**What a program leaves behind.** The tools that run a program end, through the shared process block, what it left running after it exited, before they read, size or hash what it wrote. `vol_views`, `vol_readiness`, `isf_intake` and `mem_registry` carry it (`mem_fs` has its own search for what the engine holds, named in `clean_up`). A tool that reports files a program wrote answers at most `partial` where the host cannot show no process was left (not Linux, `PR_SET_CHILD_SUBREAPER` refused), and one that reports only what a program printed on a pipe does not; every one is `partial` for a process that was ended, and says so in `program_group` and its status basis. A process that is not a descendant of the program (started through a service manager) is not found.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/memory-forensics
    scripts/swarm.sh start --pack computer-forensics-base,memory-forensics ...
