# Packs: skills, tools and method, in one importable directory

A pack is a directory the operator installs once and then names at kickoff. It
carries four things the harness already knows how to consume, plus the record of
where they came from:

| What | How the harness consumes it |
| --- | --- |
| Skills | method notes an agent fetches by name with the `skill` tool |
| Tools | `tools/<name>/{manifest.json,run.py}`, the shape `make_tool` already writes |
| Host requirements | binaries a case needs, checked at kickoff like `--toolbox` |
| Goal templates | a `--goal-file` with its own definition of done and checks |

Packs are optional. A swarm runs with no pack, with one, or with several.
Nothing in a pack can weaken a guard: a pack ships data and scripts, and both
run inside the same sandbox, under the same write allowlist, with the evidence
held read-only exactly as before.

---

## 1. Why skills are a tree of files

The obvious design is to append a pack's method to every agent's system prompt.
It is also the wrong one. A Windows pack's method runs to tens of thousands of
tokens. Pasting it into every agent spends the context window on material most
of them never need, and spends it again on every turn for the whole run.

So a pack's skills are small files, and an agent fetches one when it needs it:

- The index is small and goes in front of the agent once: skill ids, each with a
  title and one line saying when to reach for it.
- A body arrives only when an agent calls `skill("<id>")`.
- A body may name other skills. The agent fetches those the same way, so one
  skill builds on another without either repeating it.
- Every fetch is an event on the trace. Which method a swarm consulted, and
  when, becomes part of the record the report can cite.

A skill is written for an agent in the middle of a case: what to look at, in
what order, what the answer looks like, what would disprove it, which tool to
use. It does not explain what a registry is.

### Skill file format

Front matter, then a short imperative body.

    ---
    id: windows/execution/prefetch
    title: Prefetch, and what it proves
    when: An executable's run count, its first and last run, or the files it touched.
    needs: [windows/execution/overview]
    tools: [prefetch_mam, mam_scan]
    requires_host: []
    ---

`needs` names skills this one assumes. `tools` lists the tools the body names,
and `requires_host` the host programs it names (the binaries its commands call):
a name the body uses is in the list, and a name in the list is in the body.
`mentions` lists names the body discusses and cannot depend on, such as a tool
that exists only when another pack is loaded; it is in neither of the other two
lists (section 8, "Links"). Install validates `needs`, `tools` and `requires_host`
against the pack and warns about anything it does not carry: a warning rather
than a refusal, because a Windows skill is expected to call the base pack's
`icat_extract` and the set is resolved across the dependency chain at kickoff.
A reference that no pack in the resolved set carries is a bug, and
`tests/pack-tools.test.sh` fails the build on one; `tests/pack-links.test.sh`
holds the lists against the body, and `mentions` too.

### Tool help stays out of the context window

A skill does not paste a tool's full option list. It gives the one or two
invocations that matter in a case, and names the command that prints the rest.
The agent runs that command when it needs the detail, and pays for it once, in
its own turn, instead of in every agent's prompt on every turn.

---

## 2. Directory layout

Every pack has the same shape. Later packs follow it without deviation.

    <pack-id>/
      pack.json                 identity, dependencies, secrets, checksums
      README.md                 what this pack is, for a human
      LICENCE                   the pack's own licence
      NOTICE                    third-party attribution, one block per vendored project
      skills/
        INDEX.md                generated from the front matter of every skill
        <namespace>/<name>.md
      tools/
        <name>/manifest.json
        <name>/run.py
      vendor/                   third-party code that may be redistributed
        <project>/LICENCE
      requires/
        host.json               binaries the operator installs, with why and how
        python.txt              pip requirements, pinned
      goals/
        <template>.md
      tests/
        pack.test.sh            the pack's own suite
        cases.json              published cases this pack is verified against

Nothing outside these paths is installed. A zip whose top level is not a single
directory named for the pack id is refused.

---

## 3. pack.json

    {
      "id": "windows-forensics",
      "name": "Windows Forensics Pack",
      "version": "1.0.0",
      "description": "Artefact-by-artefact method and tooling for a Windows examination.",
      "licence": "AGPL-3.0-or-later",
      "depends": ["computer-forensics-base>=1.0.0"],
      "tools": ["evtx_query", "regkv", "prefetch_mam"],
      "vendor": [
        { "name": "python-evtx", "version": "0.8.0", "licence": "Apache-2.0",
          "url": "https://github.com/williballenthin/python-evtx",
          "path": "vendor/python-evtx" }
      ],
      "requires": { "host": "requires/host.json", "python": "requires/python.txt" },
      "unreferenced_ok": [
        { "name": "olefile", "why": "imported by a tool of the pack; no skill runs it" }
      ],
      "secrets": [
        { "name": "VT_API_KEY", "title": "VirusTotal API key", "required": false,
          "why": "Reputation lookups on hashes the case finds.",
          "url": "https://www.virustotal.com/gui/my-apikey" }
      ],
      "checksums": { "sha256": { "skills/INDEX.md": "..." } }
    }

`depends` is resolved at install. A pack whose dependency is missing is refused,
named, with the version it wanted. `unreferenced_ok` is optional: a program or
Python package the pack requires and no skill names, with the reason (section 8,
"Requires and images").

### Versions

A change to a pack's files or to its manifest raises its version, the patch at
least: two different packs never carry one number. The kickoff tells an
installed pack from the one a checkout ships by version alone (it warns when
the installed one is older), so a second, different 1.3.5 would run its old
skills without a word. CI's `pack-versions` job holds the rule: every pack whose
manifest, its version aside, differs from the base's (the checksums cover every
file) must carry a version above the base's
(`python3 scripts/pack-versions.py --base <base>`). Two branches that each
raise one pack to the same number can still merge without a conflict;
`scripts/merge-prep.sh`, run when a branch is brought up to date with main,
raises the later one's patch (CONTRIBUTING.md, "Bringing a branch up to date
with main"). A version quoted in prose, in a changelog fragment or a skill,
does not follow such a raise: name the pack, not its number.

---

## 4. Secrets

A pack may declare secrets. The rule the harness holds for a provider key is
that no credential is handed to an agent's pane. A pack's secret keeps that
rule in a microVM, where only a placeholder enters. On the host it keeps it
only by withholding the secret, and hands it to the pack's tools only when
the operator accepts that the agents can reach it too.

- At install, `pack install` asks for each declared secret and writes it to
  `~/.dfirswarm/secrets/<id>.env`, mode 0600, owned by the operator — beside
  the packs, never inside one: a pack's directory is mounted read-only into
  every agent's VM, and `verify` checks it against the pack's own checksums. A
  secret that is not required may be skipped; the tools that need it say so when
  they run.
- At kickoff the secret is not exported into the pane environment and is not
  written into the sandbox. (A VM's environment gets a placeholder; below.)
- When an agent calls a pack tool on the host, the secret is passed in the
  environment of that tool's own child process. The tool reads it there. It
  is never in the pane's own environment, so `env` in an agent's shell shows
  nothing. (In a VM the environment holds a placeholder instead; below.)
- The design also put the file itself out of the agent's reach, with the
  mechanism that keeps a previous run's findings unreadable (a tmpfs over the
  directory inside the namespace, or a Landlock rule denying the read). That
  denial is not built. The extension runs inside the pane, so on the host an
  agent can read the secrets file with its own shell, and that is why a pack
  tool gets a secret there only when the operator accepts it (below).
- The trace records the call and its parameters. It does not record the secret.

A pack's secrets are handed over only when the operator passes
`--allow-pack-secrets`, on the host and in a VM alike, and a pack that
requires one is refused without it; `--local-only` withholds them all and
opens none of their hosts. The record's `pack_secrets` says, per pack, the
mode and what happened to each secret by name.

How this is implemented:

- A secret entry may name the `hosts` its value is for:
  `{"name": "VT_API_KEY", "title": "…", "why": "…", "hosts": ["www.virustotal.com"]}`.
  Each is a host name, not a suffix: a VM whose secret is bound to `*.name`
  is refused, since msb would swap the value in for any host under it.
- On the host the extension cannot be kept from what its own pane can read, so
  a pack tool gets its pack's secrets only when the operator passes
  `--allow-pack-secrets`, and a pack that requires one is refused without it.
  The run record's `pack_secrets` says, per pack, `exposed`, `withheld` or
  `not-set`.
- Under `--isolation microvm` the value never enters the VM. With
  `--allow-pack-secrets` each secret is given to the VM as a placeholder
  bound to the pack's `hosts`; the host swaps the real value in on the way to
  those hosts only, and a placeholder sent anywhere else is refused. The
  placeholder is in the whole VM's environment, so any process there can use
  it against those hosts: that is why the flag is needed here too. The
  record says `injected`. A secret with no `hosts` cannot be bound, and is
  withheld; a required secret that cannot be bound stops the kickoff.
- On the host, only the pack's own tools get the secret, in their child
  process's environment; a tool forged during the run gets none. In a VM the
  placeholder is in the environment of the whole VM, under the secret's own
  name, so any process in that VM, an agent's shell included, can use the
  secret at the pack's `hosts` (look up a hash, or upload a file there). The
  value itself never enters the VM, and the placeholder is refused anywhere
  but those hosts.
- The trace row of the call, and the output handed back to the model, carry
  `[secret NAME]` where the value would have been.

---

## 5. Third-party tools and licences

A pack carries third-party code only where the licence allows redistribution,
and says so in `NOTICE`, with the licence text beside the code in
`vendor/<project>/LICENCE`.

Anything that may not be redistributed is declared in `requires/host.json`
instead, with the reason and the install line per platform. What the kickoff
does with it depends on the mode:

- **Host runs** do not read it. The agents install what they need
  (`--allow-install`) or work without it, and the pack's tools say what is
  missing when they run.
- **Under `--isolation microvm` with the job service** (the default) the
  agents' VMs boot the base image and are not held to the packs' programs:
  the job images are. Each records the programs it holds (`tools.md`,
  `image.json`), a job image this host lacks is pulled, and the one holding
  every pack of the run missing stops the kickoff, with how to build it. A
  pack tool the agent's own VM cannot run is run again as a job in its pack's
  image by itself.
- **With `--brains-with-packs`, or with no job service,** each VM's probe looks for every program a
  pack marks as required (not `optional`). One missing from the image stops
  the kickoff, unless the agents may install (`--allow-install`), in which
  case it is a warning they are told about. An image built from another
  version of a pack is a warning, recorded in `vm/<id>.json`, not a refusal.
  `--toolbox` in a VM run also lists every program the packs name, required
  or optional, in `toolbox.json`.

The image profiles are built from the same file (`images/README.md`). A
program no package manager has says how an image gets it, as data: a pinned
`download` per architecture (a `.deb` is handed to apt), a tag's `source` with
its entry and interpreter (`run`), or a `build` from source (with pinned
`patches` and its own `commands` where it has no configure script); an apt line
with `-t bookworm-backports` comes from Debian's backports. Each is checked by
its sha256. What a program reads and is not a program (a symbol pack, a rule
set) hangs from its entry as `install.data`: one url, sha256 and size
(`bytes`), the Python `package` of the image's venv it is put inside and the
`into` directory, a `warm` command that indexes it once at build time, a
`check` that must succeed, and the `licence` it carries on its own, which the
image's NOTICE states beside the program's (with `notice`: supplier, source,
terms, derivation, restriction). It may be a list of entries, or
`{"list": FILE}`: a file of the pack with a `template` and `entries`, one
expanded entry each. An entry with `commands` and `outputs` is a source the
build converts, each output's content pinned (`canonical`, `canonical_sha256`)
for one `converter` version; `set` is what `recipe.py build --symbol-set`
selects; `acquire: "operator"` is never fetched by a build, only taken from
the operator's store (`swarm.sh symbols fetch --accept-terms`) with the
recorded acceptance of its terms. The memory pack's Volatility entry pins the
Foundation's Windows symbol pack this way, and the curated kernels
(`requires/symbols.windows.json`) as a list.
A program that belongs to another system (Apple's `log`, a collector run on
the host being collected) is marked `not_in_image` with why: no image is asked
for it, and a pack may not require it.

**A pack's `requires/host.json` runs code when an image is built:** `configure`
and `make`, `pip install`, a source's `commands`, the `patches` it applies, a
data file's `warm` and `check`. Build images only from packs you trust; the
sha256 pins say the bytes are the ones the pack named, not that the pack is
harmless.

    {
      "binaries": [
        { "name": "fls", "package": "sleuthkit",
          "why": "List files and streams in an image.",
          "install": { "brew": "brew install sleuthkit", "apt": "apt install sleuthkit" },
          "licence": "IPL-1.0 and GPL-2.0", "redistributable": false }
      ]
    }

---

## 6. Installing, and running with a pack

    scripts/pack.sh install windows-forensics-1.0.0.zip
    scripts/pack.sh list
    scripts/pack.sh show windows-forensics
    scripts/pack.sh verify windows-forensics
    scripts/pack.sh remove windows-forensics

Install refuses a pack whose checksums do not match, whose dependency is
missing, whose skill front matter names a tool or a skill it does not carry, or
whose zip holds anything above the pack directory.

At kickoff:

    swarm.sh start --pack windows-forensics ...
    swarm.sh start --pack computer-forensics-base,windows-forensics ...
    swarm.sh start ...

The last one is a run with no pack at all, exactly as before.

`--pack` seeds the pack's tools into the run the way `--tools-from` does, puts
the skill index in front of every agent, and lets `skill` fetch any body.
Under `--isolation microvm` it also picks the job images (the agents' own
image with `--brains-with-packs`) and adds the pack's host requirements to the
toolbox check and, where the agents boot the packs' image, to the VM's probe (§5). The run record names every pack,
its version and its checksum, so a reader knows which method produced the
result.

---

## 7. The packs in this repository

Twelve, all under the same AGPL-3.0-or-later as the harness, in `packs/`:
107 skills, 70 tools and 14 goal templates. Every one of them is sealed,
checksummed, and installs and verifies in the test suite.

| Pack | Skills | Tools | Goals | What it is for |
| --- | --- | --- | --- | --- |
| `computer-forensics-base` | 11 | 14 | — | the method true of any platform; everything else depends on it |
| `windows-forensics` | 24 | 20 | 3 | ten artefact families, from `$MFT` to what anti-forensics leaves behind |
| `linux-forensics` | 10 | 6 | 2 | auth logs, the journal, accounts, systemd and cron, ext4, containers |
| `macos-forensics` | 8 | 4 | 1 | property lists, the unified log, FSEvents, KnowledgeC, APFS |
| `mobile-forensics` | 7 | 3 | 1 | iOS and Android extractions, app databases, protobuf |
| `memory-forensics` | 9 | 3 | 1 | containers, what works with no framework, injection, credentials |
| `network-forensics` | 8 | 6 | 1 | captures, sessions, DNS and TLS metadata, beacons, exfiltration |
| `reverse-engineering` | 7 | 4 | 1 | static triage of a binary or a document, under quarantine |
| `encrypted-containers` | 5 | 3 | 1 | which scheme, which protectors, and where the key already is |
| `cloud-forensics` | 6 | 3 | 1 | Microsoft 365, Entra, AWS, Workspace, and the tokens behind them |
| `ransomware-response` | 7 | 2 | 1 | the order the case has to be worked in |
| `triage-collection` | 5 | 2 | 1 | a collector's output, which is how most cases arrive |

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/windows-forensics
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics ...

### Two rules the set holds to

**No pack carries a tool name another pack carries.** A run that loaded both
would collide, so the generic tools — `file_type`, `sqlite_query`,
`timestamp_decode`, `image_layout` — live in the base pack and nowhere else.
`tests/pack-tools.test.sh` fails the build on a duplicate.

**Every reference resolves inside its own pack's dependency closure**, not
merely somewhere in the repository. A Windows skill may name a base pack tool
because Windows depends on base; it may not name a network pack tool. The same
test checks that for all twelve.

### Third-party tools

Nothing third-party is redistributed in any pack. Host binaries are declared in
`requires/host.json` with their licence and their install command, and are
invoked as executables — which is why the Sleuth Kit (CPL-1.0), Suricata
(GPL-2.0-only) and Volatility can all be used by an AGPL-3.0 project without a
licence question arising. Python packages are declared in `requires/python.txt`
and fetched from PyPI.

Two consequences worth stating. The memory pack wraps **MemProcFS** and not
Volatility, because MemProcFS is AGPL-3.0 and a purpose-written driver for
Volatility would be a derived work of Volatility rather than of this
repository. And almost every host binary is marked **optional**: the packs'
own tools use the standard library, so a host with none of them still works,
and each host tool widens what can be established rather than being required.

## Tools that call programs, and tools that mount

A tool's manifest may name the programs it calls, `"requires": ["fls",
"icat"]` (the tool library's manifests do; `make_tool` takes the same list).
The image choice for a VM run counts them, and where the agents boot the
packs' image each VM's probe looks for them: a program the image lacks is said
at kickoff, the run goes on, and that tool will fail when it is called. Where
the agents boot the base, a pack tool that fails for want of a program is run
again as a job in its pack's image. In a VM an agent writes only its own
directories, so a tool that mounts something (a volume shadow copy, a
memory filesystem) mounts it under `work/<agent id>/`, which is where
`vss_stores` and `mem_fs` put theirs; the mount is that VM's alone, and what
is derived from it counts once it is a file there.

Run again as a job, a tool writes only the job's `$OUT`. Each path it was
given in the agent's own directories (`work/<id>/`, `work/extracted/<id>/`,
`work/quarantine/<id>/`, `tool-output/<id>/`, written relative or absolute)
that held nothing when the agent called it is given as a place under `$OUT`
(`work/<id>/x` as `$OUT/x`, `work/extracted/<id>/x` as `$OUT/extracted/x`,
and so on), and the answer's `written_to` names where it is now,
`store/jobs/<job>/out/…`; one that already held a file or a directory is what
the tool reads, and the job reads it where it is. The tool's own output names
the places it wrote as the worker saw them, under `<run>/.jobs/<job>/`; the
answer's `paths` maps each to where it is sealed, and the output stays as it
is. The harness knows the agent's directories and the job's, never a tool's
parameters or format.

A tool that writes where its caller says (an `output`, an `out_file`, an
`out_dir`, a mount) resolves the path first, links included, and refuses a
place outside the run directory, the run directory itself, or anything under
`inputs/` (`resolve_output` in each such tool; in a job `$OUT` is inside the
run directory). A file it then makes inside that directory is checked the
same way, so a link left there cannot carry the write out of it.

A tool or a recipe runs from the run's directory, which is read-only in an
agent's VM and in a job's worker. A program it calls that writes its log or
temp files to its working directory by default is given a path under the
output (Plaso's and Zircolite's `--logfile`) or run there (Hayabusa, Zeek, the
disk-timeline recipe's Plaso steps), and its test runs it from a read-only
directory with a stand-in that writes where the real program does.

---

## 8. Writing a pack that holds up

A pack is read by an agent in the middle of a case, with nothing to go on but
what a skill says and what a tool prints. What follows is what every skill,
tool and requirements file in a pack is held to, so that a result built on a
pack's word is one a reader can check. `tests/pack-tools.test.sh`,
`tests/pack-links.test.sh`, `tests/packs.test.sh` and `tests/recipe.test.sh`
hold the parts a test can hold; the rest is for the author.

### Voice and method in skills

1. **Observation, inference and conclusion stay apart.** A skill says what an
   artefact shows, what it does not show, and what else has to corroborate it.
   Every skill about an artefact has a short "Does not show" part.
2. **A system artefact does not name a person, an intent, a copy, a tampering
   or an exfiltration by itself.** Attribution, intent and "the logs were
   cleared" are conclusions, not readings. A skill says which corroboration
   each of them needs.
3. **A negative is bounded.** It says what was searched, in which source, over
   which period. The absence of an artefact is not the absence of the event.
   A skill never writes "cannot be recovered" after one failed route: it names
   the routes tried.
4. **Time says which clock, which zone, which epoch and what resolution.** A
   current zone offset is not applied to a past date without checking the
   zone's daylight-saving history. Grouping by clock change or by boot does
   not remove drift.
5. **A version fact is dated** ("as of March 2026") and names the system or
   tool versions it holds for. A version fact the author cannot source stays
   out of the skill.
6. **Examination wording is the defender's.** For credential, malware and
   encryption topics a skill says how to identify, preserve and use what the
   case lawfully supplies, and on what basis. It gives no attack or evasion
   walkthrough, and no recovery by guessing beyond naming the authorised
   route.
7. **Density.** A skill is for an agent in the middle of a case: decision rules
   (if X, then Y), what to record, what would disprove the reading. No padding,
   and no list of a tool's options: it names the command that prints them
   (see "Tool help stays out of the context window"). The front matter keeps
   the format in "Skill file format".

### Secrets and sensitive output

1. **The hash of a secret is never written**, in a post, the ledger, a report
   or a tool's output: an unsalted hash of a weak secret is reversed in
   seconds. Nor are characters of a password, a PIN or any short secret. Of a
   random secret of 16 characters or more, at most the first four and the last
   four. A "shape" of a secret, such as the first two digits of each group of a
   recovery key, counts as characters of it.
2. **A tool that can reach secret material reports presence, kind, location,
   length and offsets, not values, fragments or digests.** That covers
   credential stores, keys, tokens, cookies, password verifiers, recovery keys,
   browser stores, property lists that hold a verifier, command lines and
   environments that may hold a secret, the bytes a YARA or `strings` match
   prints, and decrypted content. Where a value has to be produced, the skill
   says the job runs with `secret_output: true` (a `job_run` parameter; see
   `docs/protocol.md`), and the tool writes the value only to a file output,
   never to standard output and never into a field an agent might paste.
3. **A secret never goes on a command line**, because the argument list is
   recorded in the trace. A bundled tool takes a reference to a file, and that
   file is a sealed secret output. Where a skill sends the agent to a program
   that can take its passphrase only on the command line, the skill says so and
   tells the agent to say it in the report, so that the trace can be redacted
   before it is shared.
4. **A skill that names such a tool says so**, in a "Sensitive output" line.

**The pattern, concretely.** `recovery_key_scan` (encrypted-containers) is the
reference implementation. A tool that can reach secret material copies its
`SecretValues` class as it copies `LosslessPage` (standalone tools do not
import each other), and holds to this:

- *The answer is a locator.* Per finding: a `finding_id` (a sequence number,
  derived from nothing), the source `file` and `offset`, the `kind`, the
  `length` and a structure result. No value, no character of one, no masked
  "shape", no hash, digest or fingerprint, however short or salted. "The same
  value as F000001" (`duplicate_of`) is said by comparing in memory, not by a
  digest.
- *A value is produced only on an explicit flag, in a job, in a file.* The flag
  is `write_values: true` (default false). The tool honours it only when it
  runs as a job (`JOB_ID` and `OUT` are set) and writes only under `$OUT`:
  JSON Lines, mode 0600, each row carrying the answer's `finding_id`, file and
  offset beside the `value`. The file is created exclusively at the start of
  the run, before anything is scanned: a file or link already at that name is
  refused by name, and with nothing found it stays an empty file and the answer
  says `written: 0`. Outside a job the request is refused, with exit 1 and
  nothing written, because a file in `work/` is not a sealed output.
- *A name shaped like the secret is withheld.* A path component that matches the
  secret's own pattern (a file named after the key) is replaced in every printed
  path, in the files the answer names and in the digest that names a paging file;
  only the values file keeps the real path.
- *The answer says where the values are, not what they are:*
  `secret_values.values_file` and `contains_secret_values: true`. The skill
  that names the tool has its "Sensitive output" line say the job runs with
  `secret_output: true`, and that the ledger cites the finding's file and
  offset, never the value.
- *The manifest says SENSITIVE* and names the flag. The harness reads no
  manifest-level flag yet, and a tool cannot see whether its job was run with
  `secret_output`, so what keeps a value out of an ordinary run is the refusal
  above and the skill's line; a flag the harness enforces is a follow-up.
- *The tests assert absence:* no group of the value, no run of its digits, no
  64-hex string and no masked shape in the answer or in any file it names, with
  the value planted in every encoding the tool reads.

### The tool contract

Every tool a pack bundles holds to this.

1. **Fail loudly.** A tool never turns an error, a skipped block, a malformed
   line, a failed export or an unsupported version into a clean or empty
   result. It reports counts (parsed, empty, unsupported, failed, not attempted)
   and names the first failures. Exit code 0 means the engine ran, not that the
   examination is complete: completeness is judged from artefact coverage.
2. **Bound resources, and say so.** Stream. Cap what expands (archives,
   containers, compressed streams, recursion, regular-expression time). A
   result that is cut says `truncated: true`, the cap, and where the whole is
   kept: nothing is cut without the whole being kept. A tool never holds a
   whole image or a whole output in memory.
3. **Detect the format version**, and refuse or flag the ones the tool does not
   handle. A layout is not guessed from a sample.
4. **Every record carries its provenance:** the source object (a path or an
   id), the offset or record number, and the parser's name and version. A
   timestamp carries the raw value beside the decoded one, says its epoch and
   zone, is written as ISO 8601 in UTC and keeps its fractions of a second.
5. **Evidence is hostile input.** A tool executes none of it, follows no path
   out of the directory it was given, writes only to its output directory,
   uses no network and bounds decompression.
6. **The manifest's description says exactly what is and is not measured.** A
   survey is described as a survey and a heuristic as a heuristic. A candidate
   is named a candidate; a score is not a verdict.
7. **Each fix has a regression test**, with a fixture built independently of
   the parser, from the format's specification or a known-good sample, never
   from the parser's own output. A test that shares the parser's wrong
   assumption proves nothing.

### Requires and images

1. **Every dependency is pinned.** A pip requirement with `==`; a host binary
   with its version; a download with its sha256. The licence label is read from
   the package's own metadata, not remembered. Each entry says whether it is
   redistributable, and whether it is available for arm64, amd64 or both.
2. **A program a skill tells the agent to run is in the pack's `requires`, or
   in a dependency's.** A program or Python package in `requires` that no skill
   names needs either a skill that names it, or a reason in `pack.json`:

       "unreferenced_ok": [
         { "name": "somelib", "why": "imported by a tool of the pack; no skill runs it" }
       ]

   The field is optional and written by hand; `name` is one of the pack's own
   `requires/host.json` binaries or `requires/python.txt` packages, and `why`
   says why no skill names it. Sealing keeps it, and, being part of the
   manifest, changing it raises the pack's version like any other change.
3. **A new program goes in through `images/recipe.py`**, and
   `tests/recipe.test.sh` passes. Rebuilding an image is not part of a change
   to a pack: images are rebuilt once the packs' changes have settled.

### Links

Skills, tools and programs refer to one another by name, and the names have to
agree in both directions. `tests/pack-links.test.sh` holds these rules; its
header says how it matches a name and where that is wrong.

1. **What a skill names is what its front matter lists, and it resolves.**
   Every tool named in a skill's body is in its `tools:`, and every program in
   its `requires_host:`. Each resolves in the pack's dependency closure (the
   pack, its `depends` and theirs): a tool of a pack outside it is not named,
   and an entry of `requires_host:` is a program some pack of the closure
   requires. A front matter entry the body never names is wrong the other way
   round.
2. **A name the skill discusses and cannot depend on is a `mentions:` entry.**
   A base skill that says what a tool of the Windows pack reads, where that
   tool exists only when the Windows pack is loaded, lists the tool under
   `mentions:` and in no other list. Each entry is a tool, a program or a Python
   package some pack of the repository carries or requires, and none is also in
   `tools:` or `requires_host:`. A mention is no use: it is exempt from the rules
   above, and it satisfies none of the next.
3. **Everything a pack ships is reached.** Every bundled tool is named by at
   least one skill of its pack, or of a pack that depends on it. Every skill
   that depends on a capability names the tool that provides it. A capability
   a skill needs and no tool provides is either added as a tool or taken out
   of the skill.
4. **The pack that owns a tool ships it.** Another pack names the tool and
   lists the owner in `depends`; it does not carry a copy (see "Two rules the
   set holds to").
