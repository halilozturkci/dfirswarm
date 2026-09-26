# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Added: findings name what they rest on (ledger refs)

- `record` takes `refs`: the run's objects an entry rests on —
  `input:<path>`, `job:<id>/<path>`, `import:<id>/<path>`,
  `member:<generation>#<n>`, `sha256:<hex>`, or `unresolved:<why>` when none
  can be named. Each is resolved when the entry is written; one that does
  not resolve refuses it, with the nearest names. The refs are in the
  entry's chained core when present (an entry without them keeps the core it
  always had), so one added, removed or changed later breaks the chain.
- A finding without refs is taken, with a note asking for them. Recorded
  again with refs where the standing entry has none, it becomes that entry's
  correction; with other refs than the standing entry's, it is merged and
  told its refs were not added.
- `ledger.md` and the report ("Rests on") show them. Custody resolves them
  again and counts the standing findings by what they rest on: refs (those
  that no longer resolve named), a path in the prose only, or nothing (an
  audit gap). The pilot's four runs had 2/24, 11/21, 6/27 and 3/21 findings
  citing nothing, by the prose count.
- A goal can ask that its answers rest on the ledger:
  `scripts/check-answers.ts --report work/report.md --sections 1,2,3`, called
  from `## Checks` through `$SWARM_HARNESS` (which await-done.sh now sets),
  passes when each section cites a standing finding whose refs resolve, or a
  search that found nothing. It does not ask for confidence. Decided with
  Fable and Codex in place of a hub gate: the goal owns done (ADR 0002).
- In a run with tool jobs, a shell command over `inputs/` that runs a minute
  or more is told once (three times per agent at most) that a job would
  have sealed its output (`job_hint`); a finding without refs that cites a
  file in an agent's own `work/` is told so by the file's name.
- `job_run import=work/<id>/<file>` seals a file or directory an agent made
  in its own VM: a job copies it into the store as it is now (each file
  hashed before and after the copy up to 2 GiB; links left out, named) and
  says it was copied live; one that changed while it was copied fails.
- `--derived-catalog` (off by default) offers what jobs make to the derived
  recipes, by each recipe's own `min_bytes` and `suffixes` (the harness's
  512-byte floor is gone), at most 20 detect passes a run
  (`derived_bounded`, and the agent is told).
- Four workers by default on a host with 64 GiB or more; `create_ms` in
  each job's record.
- The console has a Jobs tab (with Files and the Ledger): the run's jobs
  from the store's journal, paged, with totals, the job service's notices,
  the examiner's notes and custody's store line; a job's record, its
  journal lines, its manifest and its logs, paged or whole. "Committed"
  (sealed) is shown apart from the job's outcome, never as a success.

### Added: tool jobs in worker VMs, a sealed store, a catalogue that grows

- **The job service** (`scripts/job-service.ts`, in the hub). A tool job — a
  pack or forged tool with its arguments, a shell command, a recipe over one
  object — runs in a throwaway worker VM of the run's image. It sees what an
  agent sees, read-only (the evidence no-exec, `store/`, `catalog/`,
  `tools/`, `tool-output/`, the packs, all of `work/`), and writes only its
  own directory (`$OUT`); no network unless the job asks for the run's
  allowlist (plus PyPI with `--allow-install`, pip's list kept before and
  after), no credential, nothing of the board or the run's own records.
  Every step is a line of `store/journal.jsonl`, hash-chained, fsynced and
  anchored beside the run (`<sandbox>.journal-anchor.json`): accepted (who
  asked, with the name and doing it had given itself), started (the scope it
  declared, the mounts it was given, the network, the image, the worker's
  size; what it read is said to be unknown), finished, fenced, committed.
  Nothing of a staging directory is read before its worker is gone. A failed
  or timed-out job keeps what it wrote, and its stderr is shown whatever its
  exit; recovery after a crash finishes each job from the step it stopped
  at, and runs a job the hub's death interrupted once more only when it had
  no network. `--workers N` (default 2), `--worker-cpus`, `--worker-memory`
  (4 GiB on a host with 64 GiB or more, else 2), `--no-jobs`.
- **Agents' tools**: `job_run` (a command, or a tool with its arguments; a
  short job answers in the call, a longer one is posted when done, never
  both), `job_status` (a job's record and its stdout paged whole; cancel
  one's own), `catalog_request` (a recipe, or a detect pass that finds the
  recipes that apply, over one object of the run). A job's file is cited as
  `job:<id>/<path>`.
  The same recipe over the same object is one job: a second request is
  journalled (`job_deduplicated`) and its agent told when the job is done.
- **Workers are made by a child process, and a fence is a fence.** On Ali
  Hadi #10 every worker after the 64th failed to boot inside the hub's
  long-lived msb SDK ("insert run: FOREIGN KEY constraint failed"), while a
  fresh process made one fine, and each was recorded as fenced although msb
  listed it afterwards. The hub now makes and runs each worker through a
  short-lived `vm.ts worker-once`, one made at a time; the fence needs that
  process gone, inspect not knowing the worker and msb's list, read whole
  and understood, not showing it. A worker msb refused to start before
  anything ran is removed and made once more, the first error kept. After
  three jobs in a row that ran in no worker, every agent is told once to do
  that work in its own VM, and again when a job runs.
- **An examiner's note on the record**: `evidence-store.ts note <sandbox>
  --by NAME --text TEXT [--job ID]...` chains an attributed correction onto a
  finished run's journal, never an edit; refused while the hub runs. Custody
  counts the notes.
- **The store** (`scripts/evidence-store.ts`): a job's output sealed into
  `store/jobs/<id>/out/` — links, FIFOs, sockets and devices recorded and
  left out, names kept as bytes, files read-only and hard-linked to
  `store/blobs/<sha256>` so the same bytes are kept once — with a manifest
  of every file. Custody checks the journal against its anchor (telling an
  anchor one step behind, a crash between two writes, from one off the
  chain), hashes every committed file again against its manifest and names
  staging left unsealed, and names the findings that cite no object of the
  run (a job, an input, a path of its objects) as an audit gap; `package` exports the journal, its anchor, each
  job's record, manifest and logs, the census, the plan, every generation
  and revision, and the recipes that made them.
- **Catalogue recipes are the packs'** (`recipes/<name>/` with a
  recipe.json and an entry answering `detect` and `run`): computer-forensics-
  base 1.2.16 ships disk-volumes (The Sleuth Kit), memory-windows
  (Volatility) and archive-members (a tar, zip or 7z member list without
  extracting; names kept as bytes, duplicates as rows, zip DOS times marked
  zone unknown, a truncated tar reported partial, a name that is not UTF-8
  flagged as one macOS cannot store). The harness takes the
  census (`scripts/evidence_catalog.py`): each recipe says the smallest
  object it is asked about, so a small zip is offered to the archive recipe
  and not to the disk one. In a microVM run the census plans the recipes and
  the job service runs them while the agents work: each result is a
  generation under `catalog/gen/`, each change a new revision under
  `catalog/revisions/<n>/`, announced on the board; a disk's file list is
  also linked at `catalog/<input>/` as before.
- **catalog_search** v8 reads the newest complete revision (or the one
  named), a generation by its id, and an archive's `members`, and says which
  revision it read.

### Changed: agents run in microVMs by default (breaking)

- **`--isolation microvm` is the default.** A run with no `--isolation` and
  no `SWARM_ISOLATION` puts every agent in its own microVM, and so does
  `netcheck`. The old behaviour is `--isolation host` (or
  `SWARM_ISOLATION=host`): every agent a Pi process on this machine, held by
  the host guards. Host mode is kept and supported; the kickoff, `help`
  and the console call it unisolated wherever it is chosen.
- A host that cannot boot the VMs (an Intel Mac, Linux without KVM or glibc,
  no msb, an image that is not there and cannot be pulled, VMs that do not
  fit) is refused before anything is written, with what it lacks, how to fix
  it (the base image's build commands among them) and `--isolation host` as
  the unisolated way on. It never falls back to a host run on its own.
- A host guard's flag (`--no-write-guard`, `--no-seal-herdr`,
  `--inputs-enforce`, `--key-from-env`, `--probe-violation`) with no
  `--isolation` is refused with the hint to add `--isolation host`.
- The console's New swarm form has the microVM switch on by default and
  always passes `--isolation` explicitly; its API takes `isolation: "host"`
  for a host run.
- A registry record with no isolation (every run from before this change)
  is a host run, and `list`, `status`, the console and the report show it as
  one.
- The kickoff prints an `Isolation:` line. The quick start builds the base
  image before the first run; the keyless proofs it shows are host runs, as
  they were proven.

### Changed for host runs

What the microVM work changed for host runs as well, so a host operator is
not surprised:

- Every trace line carries its process's id and count (`sid`, `seq`) and the
  collector's `recv_ts`; the idle watchdog and the console order by the
  latter. The watchdogs spill to `traces/system-spill.jsonl`, not `work/`.
- A kickoff that stops after registering puts away what it started and
  records the run as `failed`. The registry is written under a lock. The
  host is asked not to sleep for the run (`caffeinate`, `systemd-inhibit`;
  neither holds against a closed laptop lid; one the system refuses, such as
  systemd-inhibit for a user with no login session, is said as a WARN, not
  claimed). A sandbox a running run uses is refused.
- `stop` takes custody (see Added; `--no-custody` skips it,
  `--custody-timeout SEC` bounds it, 14400 by default) and says where it was
  if interrupted. Custody re-reads every evidence file, so a stop on a large
  case takes as long as hashing the evidence once more. `reap <id>` touches
  only that run.
- The console binds `127.0.0.1` by default. It bound `0.0.0.0`, so anyone on
  the LAN could read the board and the trace without a token; `--host
  0.0.0.0` opens it to the LAN on purpose.
- The finish line `done` runs is read from the registry only. It looked for
  the registry beside the sandbox and fell back to the agent-writable
  `SWARM.md` in silence; panes now get `SWARM_RUNS_DIR`, and a finish line
  that is met but was read from anywhere else cannot certify a run
  (abandoning still ends it).
- The trace token and the console's token are masked in every trace line. A
  shell's `env` in a tool output had put both into the trace.
- Pack and library tools are registered at session start with forging off,
  and named in `--tools`. They loaded only with `--allow-tool-forging`,
  although the contract listed them as ready. A `--tools-from` tool of the
  same name no longer replaces a pack's tool: the pack's copy is kept, and
  different bytes are said.
- Pack secrets are implemented (`docs/packs.md` §4): a pack tool gets its
  pack's secrets in its own child's environment, and the trace row and the
  output carry `[secret NAME]`. On the host that needs `--allow-pack-secrets`,
  since a pane can read what its extension can; a pack that requires a
  secret is refused without it. The secrets live in
  `$DFIRSWARM_HOME/secrets/<pack>.env` (`~/.dfirswarm` by default), not inside
  the pack; a reinstall moves an old one, and a pack that declares secrets
  and still has a `secrets.env` in its directory stops the kickoff in either
  mode. Shipped packs were resealed with corrected install lines
  (`pff-tools`, `libfwsi-python`, plaso from PyPI), pinned downloads, and
  after the review with names checked against Debian 12 and PyPI (zeek,
  suricata and radare2 are manual, `libfwsi-python` is a Python library, the
  encrypted-containers pack installs pybde, pyvhdi, pyluksde, pytsk3 and
  dfvfs, and `vss_stores` and `mem_fs` mount under the seat's own
  directory).
- `--allow-install` sets `PIP_BREAK_SYSTEM_PACKAGES=1` in every pane:
  `pip install --user` was refused on a PEP 668 system. The installs still
  go under `work/.toolchain/`, and the Python install paths now reach a
  forged or pack tool's child, which could not import what an agent had
  installed. The inventory also reads a venv an agent made under
  `work/.toolchain/`.
- The inputs integrity walk no longer stops at 5,000 files and 12 levels.
  Every manifest file past it read as missing, so a KAPE-style triage set
  failed the check on every sweep.
- `start --no-start` no longer leaves the collector, the gate and the broker
  running.
- The report says when refused connections are not observable, where it said
  "nothing was refused" with no log behind it, and names each model's
  provider hosts, recorded at kickoff.
- `tools --save` keeps only sealed tools, with `provenance.json` and without a
  `pack` field; `pack.sh adopt` takes a saved tool into a pack. The toolbox's
  use column read " head -1" for every tool; fixed.
- The netguard allowlist takes a provider's host from `models.json` for a
  built-in provider too, and from Pi's model list for the providers Pi ships;
  `--provider-host` adds one. `--local-only` refuses a cloud `--compact-model`.
- The console: a `failed` state, a packs field, `*.name` allowlist entries.
- `microsandbox` is an optional dependency (`npm ci --omit=optional` for a
  host-only install).
- The idle watchdog is a host run's stop from outside the panes: past a cap
  or the wall clock it claims the stop clock (and says so on the board) when
  no pane has, and past the grace period writes the sentinel as the harness.
- Custody opens nothing through a link and waits on no FIFO; every evidence
  file is re-hashed in full whatever its size, against one deadline checked
  inside the read, and an unfinished re-hash says so rather than
  "unchanged"; the trace is read a line at a time; the ledger is held to the
  trace (an entry deleted from its end, or written without the tool, is
  named); `artifacts.json` indexes `work/`; the verdict's hash is anchored
  outside the run. `stop` bounds it from outside too.
- The ledger's chain covers each entry's provenance (source, evidence,
  confidence); an unchained line after chained ones breaks it, and so does
  a version 1 entry after version 2 ones.
- Evidence FIFOs, sockets and device nodes are recorded by their kind and
  checked by kind; the evidence manifest and its anchor are read-only on
  disk, and the manifest's hash is in the run's record.
- A peer's own directory is refused for claims and writes; the report reads
  the swarm's own report only inside the run and never through a link; the
  package copies only regular files (a link left in place of a spill had
  put a host file into the handover).
- A trace line a pane could write nowhere is said on its next line and
  counted by custody; the host spill is watched as append-only.
- Pack secrets are refused on a suffix; two packs' tools of one name keep the
  first. `tools --save` copies a tool only as its sealed version, with what
  it ran with. A forged tool may name the programs it calls (`requires`).
- `list` has a `HELD` column; run ids are six hex digits; a pane helper that
  opened a workspace no longer loses it (they ran in a subshell); a kickoff
  that fails before its record is written clears what it started.
- Warnings: a run kept in a synced folder, a Mac on battery, a suffix in the
  allowlist, writable evidence directories, a host run whose panes cannot be
  kept from a live VM run's hub, a run started as root. An IPv6 allow entry
  is written `[v6]:port`, and netguard reads it. GitHub Copilot's token host
  is allowed.
- **Event times carry their zone.** A ledger `ts` without `Z` or an offset
  is refused, and so is a form like `01/02/2024`; a date alone is that day
  at 00:00Z. A zone-less time was read in the host's own zone, so one entry
  was 12:44Z on the droplet and 09:44Z on a Mac in Istanbul. An offset is
  converted to UTC, and the text as written is kept as `ts_raw` and shown
  beside the UTC time in `ledger.md`. The agents and the run's own
  processes (the hub, the collector, the watchdogs) run with `TZ=UTC`,
  which an `--env TZ=` overrides; the registry records the host's clock as
  the run found it (`host_clock`: zone, offset, and whether it was synced,
  where the host can say).
- **The run records what produced it** (`provenance`: the harness commit and
  whether the checkout had local changes, Node, Pi, msb and the image digest
  for a VM run, the OS). The report shows it with the host clock, says that
  an AI agent swarm prepared it and that its findings are the agents'
  conclusions until an examiner reviews them, names each exhibit's model,
  and lists the tools the agents forged as not independently validated.
- **The operator is on the record.** Every `start`, `stop`, `reap`, `say`,
  `package`, `report`, `tools`, `review`, `export`, `hold`, `release`,
  `purge` and `verify` is a line in `runs/operator-audit.jsonl`
  beside the registry: when, the OS user and host, through what (the command
  line, the console, the hub's own clear-up), the arguments with `--env`
  values and the goal left out, and the sha256 of the line before. A
  `start`, `stop`, `reap`, `say`, `review`, `export`, `hold` or `release` of
  a live run is on its trace too, as `operator_action`; from a shell that is not the kickoff's it is marked
  unverified there, and custody, the report and the summary count such
  lines as the operator's actions, not as lines no pane accounts for.
- **Node 22.19 is the floor.** `engines` said 22.6, but the pinned Pi and
  its HTTP client declare 22.19.0, and on an older 22 the harness extension
  does not load. A CI job runs the typecheck and the node suites on exactly
  22.19.0.
- **A host run started as root is refused** unless `--allow-root`: root is
  not bound by the read-only modes a host run relies on. A microVM run
  started as root is warned about.
- **The caps are taken before each model call too.** A seat past its grace
  period, or whose swarm the sentinel ended, is stopped before the call goes
  out, with the same outcome as the stop it replaces and a
  `budget_precall_stop` line. On the host this is the brake; in a VM it is
  advisory, and the hub's cap stop and wall clock are the host's brakes.
- **A long command run a second time is pointed at its first run's output.**
  A shell command that took a minute or more (`SWARM_REPEAT_HINT_MIN_MS`),
  ended without error and was kept whole under `tool-output/` is
  remembered; the same agent running it again gets one paragraph naming the
  kept file to grep or read instead (`repeat_hint`, once per command). The
  harness names no tool.
- **The kickoff records whether the runs' volume is encrypted at rest**
  (`disk_encryption`: FileVault and APFS on macOS, a crypt device under the
  mount on Linux), prints it as a `Disk:` line and warns when it is off.
- **The evidence copy keeps the evidence's links as links.** `cp -RL`
  followed every link: an extracted root's `etc/hosts` became the examiner's
  own file, vouched for by the manifest. Only a link at the top of
  `--inputs` (the operator's own) is followed; links that lead out of the
  evidence are listed at kickoff. The copy is checked against its source by
  name, kind and size, and then by content: each copied file's source is read
  again and its SHA-256 compared with the manifest's (`source_checked`); a
  mismatch (names merged on a case-insensitive volume, a short read, other
  bytes) stops the kickoff. `--no-verify-copy` keeps the first check only. A name that is
  not UTF-8 is kept exactly (`path_b64`, `link_b64`) and compared as bytes
  by the agents' check and by custody, so a Windows-1254 name on ext4 is no
  longer both missing and added.
- **The manifest carries SHA-1 and MD5 beside SHA-256**, from the same read,
  to match an imager's acquisition hashes. Custody and the agents' `inputs`
  check compare them when the manifest has them; SHA-256 decides, and a
  file whose SHA-256 matches while another digest does not is listed as
  `digest_mismatch`. The report and the summary list them beside SHA-256
  and say how the copy was checked against its source.
- **A synced folder is refused, not only warned about.** A copy of the
  evidence, or the VMs' kept disks, is not put in a folder a sync client
  uploads (Dropbox, iCloud Drive, OneDrive, …) unless
  `--allow-synced-folder`, or a `.dfirswarm-allow-synced` file of the
  operator's at the top of that synced folder (or between it and the
  destination); the registry says which allowed it. The check runs before
  anything is written, where it used to run after the evidence was copied
  there. A run directory there is still warned about for what the agents
  derive.
- **Custody writes nothing through a link.** The previous verdict is set
  aside as `custody.previous-<stamp>.json` before anything is checked, and
  every file custody writes goes to a fresh file renamed into place: a host
  pane's link had made custody copy a credential file into the run and
  overwrite an operator's file with its own JSON. A custody ended by its
  deadline, a signal or an error writes what it found and names what it
  never reached (`not_reached`), so after a failed custody `custody.json` is
  that partial verdict or absent, never the older one. A directory of more
  than 125,000 evidence files, or a manifest over 256 MiB, no longer breaks
  it; a file the host cannot read is `unreadable`, not missing; the ledger
  is held to the trace whatever the trace carries, and a seat's spill fills
  only its own gaps. The report, the summary and the console say whether
  `custody.json` matches the verdict anchored outside the run, and the
  report says "NOT FULLY RE-HASHED", not "NO", when custody ran out of time.
  Custody's verdicts and `artifacts.json` are harness files no seat claims
  or writes. The artifact index is ordered by code unit, so its anchored
  hash no longer depends on the locale.
- `start --custody-timeout SEC` bounds the custody taken at the run's end,
  by the hub or by `stop`; it is recorded (`custody_timeout_sec`), and
  `stop --custody-timeout` overrides it for that stop.
- **The console shows an agent's HTML without scripts**, the report too: a
  script could navigate the frame with the file's contents to any host,
  past every allowlist of the run. **Open with scripts** runs one file's
  scripts in that view after a warning, through a one-time grant (it needs
  the console token, is bound to the file's sha256, is spent on first use
  and lapses after a minute), and each opening is on the run's trace as
  `artifact_scripts`.
- A trace that is there and cannot be read is said so, rather than shown as
  no trace: by the report, the summary, the dossier and the console's trace
  and swarm views. The report checks the chain a line at a time, so a trace
  past 512 MB is read and checked.
- `budget.json`, history's index and a ledger merge are written whole (a
  temporary file and a rename); a usage report refuses a `budget.json` it
  cannot read rather than rebuilding the run's caps from defaults. A peer's
  ledger merge (an author added) is no longer charged to a seat's shell
  call as RECORD REWRITTEN. A lost trace line is counted once.
- `stop` ends a daemon only when its pid is that daemon for that run: after
  a reboot, or with a pid file a pane rewrote, it could have named any of
  the operator's processes. A `stop` of a run nothing of which is alive
  says the host restarted or the run crashed, with the trace's last time.
  Two host kickoffs at once no longer share one netguard proxy. The
  console's host kickoff stays a host run whatever `SWARM_ISOLATION` says.
- New trace names (`operator_action`, `artifact_scripts`,
  `collector_restarted`) are reserved: no forged tool takes them.

### Added

- **Every image says what it holds, in the VM: `/etc/dfirswarm/tools.md`.**
  One line a program: its name, what it is for (its pack's own `why`), its
  pack, and the version its package record holds (a `--version` probe had
  answered "invalid option" for a third of them); then the Python libraries
  the packs and the tool library install, with the note on each one's line;
  then what a pack names that the image does not hold. `install.py` writes it
  beside `image.json`, the NOTICE and the SBOM, in the base and in every
  profile, and the image check records it in `toolbox.json` (`tools_md`).
- **The programs the sixth CTF round's agents went looking for are in the
  images.** Each had been searched for, pip-installed by hand, or forged:
  - `pdftotext` (poppler-utils, with `pdfinfo`, `pdfimages`, `pdftohtml`) in
    computer-forensics-base 1.2.13: five agents shared a forged PDF reader and
    two pip-installed pypdf because the image had none.
  - `ccl_indexeddb_dump`, a pinned source of ccl_chromium_reader 0.3.18 (not on
    PyPI) with its library in a venv of its own, in computer-forensics-base:
    Element's IndexedDB on the BelkaCTF #6 laptop had no reader.
  - `heif-convert` (libheif-examples) and `pillow-heif` in mobile-forensics
    1.0.4, for an iPhone's HEIC photos.
  - `impacket` and `dpapick3` in windows-forensics 1.2.9, for DPAPI, the
    Credential Manager and Windows Vault read offline (both were pip-installed
    on "Encrypt Them All").
- **GnuPG in the encrypted-containers images** (encrypted-containers 1.1.2):
  `gpg`, to read an OpenPGP message's packets before any key is known, import
  a private key found on the evidence, and decrypt once its passphrase is. Only
  `gpgv` was there; on the sixth CTF round an agent on "Encrypt Them All"
  spent its turns looking for an OpenPGP reader on PyPI, where `gpg` needs
  `gpgme.h` to build.

- **Every program a pack names is in the image profile that holds it, or
  said not to belong in one.** The recipe knew an apt line, a pip line and a
  pinned download, and listed everything else as manual, never installed:
  Eric Zimmerman's tools, RegRipper, Zircolite, bulk_extractor, mac_apt,
  UnifiedLogReader, iLEAPP, ALEAPP, Zeek, Suricata and radare2 were in no
  image. A pack's `requires/host.json` now says how, as data, and the harness
  knows only the kinds: a pinned `.deb` per architecture, handed to apt
  (radare2 6.2.2, Zeek 8.0.10 from the Zeek project's Debian 12 packages); a
  tag's source (`install.source`) unpacked under `/opt/dfir/src/<name>`, its
  requirements in a venv of its own, its entry on PATH through its
  interpreter (Zircolite 4.0.0, UnifiedLogReader, iLEAPP 2026.4.2, ALEAPP
  2026.4.1, and mac_apt 1.33.2 for amd64 only: on Linux arm64 it stops at
  import, and an arm64 image says so); `env` and `arches` on a source or a
  build say what its build needs and which architectures it is for; a
  program run by another the image holds
  (`run`: MFTECmd, EvtxECmd and RECmd 2026.5.0 on the .NET 9.0.20 runtime,
  which the pack pins as a download of its own); a source compiled in a
  builder stage (`install.build`), so the image carries the program and not
  the compiler (bulk_extractor 2.2.0); and an apt line from the image's own
  backports (Suricata 7.0.10 from bookworm-backports). RegRipper is Debian
  12's `regripper`. Each artefact is checked against its sha256 before
  anything is unpacked, installed or built, and is in `image.json`, the
  NOTICE and the SBOM with its kind; an optional one that fails is recorded,
  not fatal. Apple's `log` and CyLR are marked `not_in_image`: `image.json`,
  the NOTICE and a VM's toolbox check list them as not applicable, never as
  missing, the probe asks no image for them, and `pack.sh seal` refuses one a
  pack requires. Every profile was built on arm64 and each program run in
  it, in a container and in a VM (`images/README.md`). Resealed:
  computer-forensics-base 1.2.12, windows-forensics 1.2.8, macos-forensics
  1.0.3, mobile-forensics 1.0.3, network-forensics 1.0.3,
  reverse-engineering 1.0.3, triage-collection 1.0.3.

- **The examiner's review of the ledger** (`swarm.sh review <id>`): accept,
  reject (with a note) or amend (with a note) each entry, and sign off the
  ledger once the run has ended, over its current head. Kept beside the
  registry where no agent reaches (`runs/reviews/<id>.jsonl`, 0600), each
  line chained to the one before, appended and never rewritten. The report
  shows each exhibit's standing (accepted, rejected, amended, not reviewed,
  or review unreadable) on its head and in its rows, the counts, whether the
  review's chain verifies, whether the sign-off covers the ledger's current
  head, and "reviewed and signed by" on the cover; until then it says every
  finding is the agents' conclusion. The console's Ledger tab takes the
  review through the same command.
- **Ledger corrections and searches that found nothing.** `record(…,
  supersedes=<seq>)` records a correction; nothing is deleted, the corrected
  entry is marked "superseded by #N" where it stands and the correction
  "corrects #M", and the link is in the chained core, so it cannot be moved.
  An entry is corrected once. `record(kind=absence)` is a search that found
  nothing, with what was looked for, what was searched, and the query, the
  tool and its version and the scope, all required; `ledger.md`, the report
  and the summary list absences apart, valid only for that scope, never as
  findings. Both are optional.
- **Coverage and grounding** (`scripts/coverage.ts`): which evidence files no
  command on the trace named, and, for each ledger entry, whether a call
  before it named its source. Generic path matching over every call's
  arguments; it knows no tool, and "named" is not "examined", which every
  place it appears says. The report (a "Named by" column, the list of
  unnamed evidence, "not grounded in the trace" on an exhibit), the summary
  and the console carry it, and the idle watchdog posts the unnamed inputs at
  a quarter, a half and three quarters of the wall clock, assigning them to
  nobody.
- **A package that can be signed and checked.** `swarm.sh package <id>
  --sign [--key FILE]` signs the manifest with an ssh key (`ssh-keygen -Y
  sign`, namespace `dfirswarm-package`) and writes the signature, the public
  key and who signed beside it; `swarm.sh verify <dir|zip>
  [--allowed-signers FILE]` re-hashes every file (none missing, changed or
  added) and checks the signature (exit 0, 3, 4 or 1). The package also
  carries `court-set.json` (every file handed over, with its size and sha256
  or why it is absent) and this run's lines of the operator's record, and
  the report lists the files handed over with it.
- **Export**: `swarm.sh export <id> --format csv|timesketch` writes the
  ledger as CSV (every field, the entry hash, superseded by, the review,
  grounding) or as a CSV Timesketch imports. A text cell a spreadsheet would
  run as a formula gets a leading apostrophe.
- **Retention**: `swarm.sh hold <id> [--reason]` keeps a run from purge,
  from a new run in its sandbox and from the VM reaper; `release <id>` lifts
  it. `swarm.sh purge <id> --yes` deletes a finished run's sandbox, its kept
  disks and its hub directory, refuses a held or running run, keeps the run
  in the registry as `purged`, and writes a destruction record (what, with
  sizes, and the hashes of the inputs manifest, the custody verdict and the
  package manifest) on the operator's record.
- **`--notify CMD`**: a command of the operator's hears a run's
  `finished`, `finish_failed`, `stop_incomplete`, `budget_cap`,
  `wall_clock`, `evidence_changed`, `chain_broken`, `agent_dead`,
  `collector_unreachable` and `hub_down`, as one JSON line on stdin,
  detached, within 30 seconds. It is kept outside the run
  (`runs/notify/<id>.cmd`, 0600); the registry records only that there is
  one, and the command line is redacted on the operator's record.
- **`--ledger-from RUN`**: an earlier run's ledger as hypotheses to
  re-derive or refute, in `prior/ledger.md` (read-only; with the earlier
  run's review, only the entries the examiner accepted or amended; without,
  every entry marked unreviewed), never in the new ledger. The worker prompt
  says to cite the evidence, not the prior entry.
- **The model gateway (`--model-gateway`, VM runs, off by default).** Every
  model call a VM makes to a provider the gateway fronts goes through one
  process on the host. It holds the provider's key in memory, reads each
  call's usage off the provider's own answer (OpenAI chat and responses and
  Anthropic messages, JSON and streaming, priced as Pi prices them), refuses
  a stopped seat's call at once and a call past a cap or the wall clock
  three minutes after it was crossed, and is not a general proxy. The VM
  holds a seat token, never that provider's key. The hub folds the measured
  spend into `budget.json` (`metered_by: "model-gateway"`), so every cap
  reads it; `traces/model-gateway.jsonl` has one chained line per call and
  no bodies, custody checks its chain and anchors its hash, and the report
  says which spend was metered on the host. Subscriptions, Bedrock, Vertex,
  Google, Mistral, OpenRouter, Fireworks, Azure and local models keep msb's
  placeholder path, and the kickoff names each. docs/model-gateway.md.
- **VM runs: each seat's socket serves only its own VM.** The kickoff makes a
  token per seat, gives it to that VM (`SWARM_SEAT_TOKEN`) and to the hub,
  and every connection must open with it or is refused and named on the
  trace (`seat_auth`). The tokens rest in the hub directory, the VM's
  environment and msb's database while the VM lives; never in the trace,
  the registry, a VM record or a package. The hub also cuts `replies.jsonl`
  back to the answers it keeps, bounds each seat's file history
  (`SWARM_HISTORY_QUOTA_MB`, 1 GiB; past it a revision is recorded by its
  hash and the seat is told once), puts a seat that said done away when it
  was due across a hub restart, and calls `--notify`. The keeper, the stop
  the hub runs, the idle watchdog and the gateway run from the run's frozen
  copy of the harness.
- **`swarm.sh start --check`** runs every refusal and preflight of a start,
  the same code, and writes nothing (no sandbox, registry entry, hook,
  daemon, VM, pull or operator-record line): exit 0 when the start would go
  ahead, 2 when it would be refused. **`swarm.sh image-for [--pack ID]...
  [--tools-from DIR] [--playwright]`** prints, as JSON, the image a kickoff
  with those packs would boot, its digest when known, and why. The console's
  New swarm form uses both before Start.
- **`scripts/score.ts`**: an accuracy check the operator runs by hand
  against an answers file of their own; it prints found, not found or
  contradicted per question and writes nothing anywhere.
- **The console shows a microVM run as itself.** An isolation chip on every
  run; a VM panel with each probe check and what it means, what the hub
  refused, hub and collector restarts, a keeper that gave up, the kept disks
  (path, size, hash, or why not, with the remedy) and msb's database; one
  timeline of the run's life across its VMs; a seat's state from one source,
  the hub while it hears from the VM, watched where it lives; `system via
  <seat>` posts shown as that seat's; a Custody tab; coverage, corrections
  and absences in the Ledger tab; a record dialog to hold and release,
  export, package (signed or not, downloaded as a zip), verify and, behind
  the run id typed out, purge. The kickoff form checks the host can boot the
  VMs, shows the image the packs choose, and takes the new options; it never
  shows an `--env` value or the notify command. Stop takes custody's options.
- **CI**: actions are pinned by commit; a job runs the node suites on the
  Node floor; `image-boot.yml` builds every image profile once a week, boots
  each as an agent's VM (the probe, its verdict and Pi end to end), checks
  it against its packs with the kickoff's `imageFit`, and does the same for
  base on arm64 where the runner has KVM. Nothing is pushed.
- **The worker prompt** asks agents to read a tool's usage for the options
  that change what its output means before relying on it, to keep a large
  artefact's full walk under `work/<id>/` and grep it, to correct a ledger
  entry with `supersedes`, and to record a meaningful empty search as an
  `absence` with its scope. It names no tool.
- **Agents in microVMs (`--isolation microvm`).** Every agent runs Pi inside
  its own microVM (microsandbox 0.7.2; macOS on Apple silicon, Linux with
  KVM), created at kickoff through the SDK (`scripts/vm.ts`) and put away by
  `stop` with each disk kept as a snapshot msb can verify. ADR 0009.
  - The run is a read-only floor in each VM; the agent writes only its own
    `work/<id>/`, `work/extracted/<id>/` and `work/quarantine/<id>/` (both
    no-exec), `tool-output/<id>/` and Pi session. A shared file is written
    by the hub through `publish_file`, claimed and recorded. `--inputs` is
    used in place and mounted read-only; `--inputs-copy` gives the run its
    own read-only copy.
  - The board has one writer, the hub (`scripts/vm-hub.ts`); who is asking
    is the vsock port. The harness's own functions are not on the agents'
    channel, a sentinel is written only when the finish line passes on the
    host (a reason starting `ABANDONED: ` is let through unchecked, and a
    seat leaving on its own cap writes none), spend reports may only grow,
    and paths are resolved on the host without following a planted link.
    The hub keeps the wall clock itself; the caps apply to the spend each
    seat reports. A keeper (`scripts/hub-supervise.sh`) restarts a dead
    hub from its saved state until the run's stop.
  - No credential enters a VM: placeholders, swapped in by msb on the way
    to the credential's own hosts only, stopped and logged anywhere else.
    Subscriptions need `--allow-oauth-in-vm`. `--provider-host P=HOST` names
    a provider's host when the harness cannot (Pi's own model list names the
    hosts of the providers it ships); a provider with none is refused.
    msb keeps a live VM's secret values in its own database on the host: the
    kickoff makes `~/.microsandbox` its user's alone, and a finish that
    removed VMs rewrites that database without their leftover bytes
    (`sqlite3` on the host; `stop` warns when it could not).
  - The image is the smallest profile that serves the packs, pulled before
    the run starts, booted by one digest; a program a pack requires that the
    image lacks stops the kickoff. Images carry a NOTICE, pinned downloads
    checked by sha256, and refuse to bake programs marked not redistributable
    without `--allow-nonredistributable` (`images/README.md`).
  - `netcheck --isolation microvm` asks msb what a run's VMs would reach.
    The report and the console's VM panel say what each VM was given, found
    and left: probe, image fit, clock, live state, installs outside the image.
  - The console starts a VM run (`isolation`, `image`, `vm_cpus`,
    `vm_memory`, `vm_disk`, `vm_snapshot`, `allow_oauth_in_vm`,
    `provider_hosts`); its default "copy" of the evidence is sent as
    `--inputs-copy` in a VM run, and a run whose hub could not put its VMs
    away shows as `finish_failed`.
- **Host custody at stop** (`scripts/custody.ts` → `custody.json`, printed by
  `stop` and carried by the report), both modes: the evidence re-hashed in
  full against a manifest anchored outside the run, every session file
  sealed, every kept output checked against the trace, the trace and the
  ledger chains, spilled and lost trace lines by their numbers, and every
  kept VM disk checked against its record and by msb.
- **VM integration tests** (`npm run test:vm`) on real VMs, one of them end to
  end with a scripted model, and a CI job that runs them on a KVM runner with
  the base and disk images built from this repository.
- **What the final review of the microVM work changed** (ADR 0009):
  - The hub never opens a file under a seat's own directory: a revision, a
    publish and the disk side of a diff come from the VM with the call (32,
    32 and 16 MiB), a seat restores its own file in its own VM, and a
    forged tool runs only as its sealed bytes. The host's own reads are
    checked again after the open (on Linux against `/proc/self/fd`).
  - The hub bounds each seat (connections, bytes buffered, calls, a rate for
    posts and records), answers a resent call once, keeps its lines
    numbered, refuses to run twice, resumes a finish it died in, clears up
    the run with `stop --after-hub`, and is kept by `scripts/hub-supervise.sh`;
    it runs from a frozen copy of the harness. A seat that is done has its
    VM put away a grace period later.
  - `stop` exits 3 and records `stop_incomplete` while a VM of the run is up,
    and waits for a hub that is finishing. Below 4 GiB free a VM is kept
    rather than snapshotted and removed; `--vm-snapshot-dir` puts the disks
    elsewhere.
  - `work/extracted/` and `work/quarantine/` are no-exec in every VM, a
    peer's corner as well as one's own. Each VM's probe checks that, that
    the evidence is no-exec, and that it can reach its model's hosts.
  - Pack secrets need `--allow-pack-secrets` in a VM too (the placeholder is
    in the whole VM's environment); `--local-only` withholds them; a local
    model's real key is refused; credential headers are swapped at every
    depth; a LAN model's name is resolved on the host; llama.cpp gets its
    environment; Pi's model catalog goes into the guest.
  - The catalog VM leaves only files and directories, is put away on `^C`
    and reaped if left; a VM that does not come up times out; `msb` other
    than 0.7.2 is warned about; a lock pinned by tag is refused.
- **What the second review of the microVM work changed** (ADR 0009):
  - The hubs live in `~/.dfirswarm/hubs`, one directory per user, 0700, and
    refused when it is a link or someone else's (`SWARM_HUBS_DIR` moves it).
    Under the caller's `$TMPDIR` a stop from ssh, cron or sudo found no hub
    and left it and its tokens running, one `/tmp/dfirswarm-hubs` served
    every Linux user, and on macOS the six-hex run ids put an agent's socket
    past the 104 bytes a socket path may have, so every VM kickoff from a
    Mac terminal ended with "the VM hub did not come up". The kickoff now
    refuses a socket path over 103 bytes before it starts anything, and a
    reboot no longer takes the hub's state with it. The console, `watch.sh`
    and `await-done.sh` look for hubs there too, and a hub started with a
    longer socket path stops with an error naming the path and its length,
    where it died on a bare EINVAL.
  - What one seat holds in the hub counts lines waiting their turn and calls
    queued or running against its 160 MB; past it the seat's connections
    pause. A call that carries no file is refused past 8 MB. The hub, not
    the seat, picks how often `wait` polls. `done` is paced (three, then one
    a minute), and dones that arrive together share one run of the finish
    line. A `state` report is one of four states with at most 200
    characters of detail and no terminal control characters, and Herdr gets
    at most one report per seat every quarter second. A collector socket
    cut on a timeout fails only its own lines.
  - The hub stops a seat over its own or its model's cap for real: the
    seat's `done` marker is written and the stop is on the trace with its
    outcome. It had been refused in silence and retried every two minutes.
  - A harness post sent from inside a VM reaches peers as
    `from: "system via <seat>"`: the harness code in a VM is the guest's,
    so its word is that seat's, not the harness's.
  - A seat cannot publish onto the harness's own files in `work/` (the
    trace spill custody reads, the install area, the temp directory).
  - In a VM a seat's shell watch walks only its own directories, so a
    peer's large extraction no longer leaves the seat's own files unwatched.
  - The keeper also brings back a VM run's trace collector
    (`collector_restarted`) and counts crashes in a row; a keeper that gave
    up is not second-guessed by the idle watchdog.
  - A finish touches its lock as it works, and only a dead or silent
    owner's lock is broken; two finishes had worked the same VMs after half
    an hour. A second finish keeps the disk an earlier one kept until it has
    a new one, and the free-space floor counts the VM's own disk size.
  - msb's database scrub says "scrubbed" only when the checkpoint completed
    and no free page is left. The outcome is on each removed VM's record
    and on the hub's `vm_finish` line; `stop` warns about any removed VM
    whose bytes were not cleared, whoever removed it, and custody, the
    report, the summary and the console name it.
  - The hub takes custody at a run's finish within the operator's bound
    (`--custody-timeout`, `SWARM_CUSTODY_TIMEOUT`), where it was a fixed
    four hours.
  - Lower-case proxy variables in `--env` no longer reach a VM, and a failed
    `msb list` is said as that at kickoff and at reap.
  - Every shell suite runs with its own msb home and hubs directory: the
    stop suite had run the scrub on the developer's own msb database.

- **Agents compact their own context.** On by default at kickoff
  (`--no-self-compact` turns it off): each agent watches its context against
  an effective ceiling the harness sets per model (`extensions/context-ceiling.ts`:
  272k for the GPT-5.4/5.5 family, 200k for grok-4.6, 300k for a million-token
  model, the declared window otherwise), receives a transient notice at 40%
  and a warning at 50%, and at the compact line (60%) every tool except
  `self_compact`, `budget` and `done` is refused until it hands off with
  `self_compact(note_to_self)`. The context is summarized with the harness's
  own prompt (`prompts/compaction-summary.md`, written for a forensic swarm)
  and the note comes back verbatim under a header of facts read from files:
  the agent's name, its live claims, its unread posts, the ledger, the
  sentinel, its spend. The three lines take token counts or percentages
  (`--compact-notice-at`, `--compact-warn-at`, `--compact-at`,
  `--compact-prompt-file`) from the CLI and the console's kickoff form; the
  registry records them as `self_compact`. Pi's own overflow compaction stays
  as the safety net, runs with our prompt, and is recorded as one. The
  kickoff pins Pi's `reserveTokens` and `keepRecentTokens` in the sandbox's
  `.pi/settings.json`. Every crossing, hold, note and compaction is on the
  trace, with one `context` row per turn; `budget.json` carries the ceiling,
  the level, the lock, the compaction count and cost and the hand-offs per
  agent; the `budget` tool returns the same numbers to the agent; the
  summary and the report gained a Context and a Compactions column; the
  console shows the lines on the context bar, the compaction ticks on the
  activity span, and a Context section with the agent's context over time
  and its compaction history. Decided in ADR 0008; the run data behind it
  is in `docs/self-compaction-plan.md`. Proven end to end through the real
  CLI with a scripted provider (`tests/self-compact-e2e.test.ts`).
- **The trace keeps everything whole.** Arguments, results and reasoning
  are no longer clipped at 20,000, 2,000 and 2,000 characters; the collector
  and the gate accept lines up to 64 MB. The `_truncated` marker is read
  from archived runs and never written again.
- **Nothing a tool produced is dropped: `tool-output/`.** When a result
  reaches the model as a prefix, the whole output is a file in the sandbox
  and the trace row names it (`full_output`: path, bytes, lines, sha256):
  Pi's `bash` spill past 50 KB is moved in from the host's temp directory and
  the model's trailer names the sandbox path; a forged tool's stdout and
  stderr stream to it past 64 KB; `browser_check` keeps the whole page text
  the same way (`full_text`). `read`, `grep`, `find` and `ls` slices are
  recorded as such (`view`). The console links each file from the trace row
  (`GET /api/swarms/:id/tool-output/<path>`), and the forged tool's own trace
  row now carries its output, whole, where it carried a byte count.
- **No silent cut remains in the harness.** An `inbox` or `wait` row lists
  every delivered post's sender and id (the lists stopped at twenty); a
  provider's error text, a forged tool's error and an agent's `doing` are
  whole; the ledger's `source` and `evidence` (1,000 and 4,000 characters), a
  forged tool's parameter descriptions and its example (400) are refused
  over their limits with the reason, where they were cut in silence.
- **`inbox` and `wait` page by whole posts.** One delivery carries at most
  `--inbox-page-chars` characters of post text (40,000 by default, 0 for no
  bound; the console form has the field, the registry records it): a post is
  never cut, the delivery stops before the post that would break the bound,
  what stayed behind is still unread, the result says `remaining` and why,
  and `wait` returns at once while anything is unread. The two `wait` results
  of 578 posts and 64k tokens each on the Linux run s3096 are what this is
  for.
- **Per-model compaction lines.** Each of `--compact-at`,
  `--compact-warn-at` and `--compact-notice-at` takes a seat value followed
  by per-model overrides (`60%,openai/gpt-5.4-mini=55%,grok-4.6=70%`; a key
  with a slash is a `provider/id`, one without matches the model id under any
  provider). Resolved per seat against its own model; `compact_config`
  records which entry applied under `matched`. Same syntax in the console.
- **`--compact-model P/ID`: a summarizer for expensive seats.** Every
  summary call goes to that model; it is credential-checked and its provider's
  hosts join the netguard allowlist like a seat's model, and it is never a
  seat. Recorded as `self_compact.model`; `compact_config` says which model a
  seat will use and why, `compact_done` which one wrote each summary; a model
  Pi's registry does not know falls back to the agent's own with the reason
  on the trace. The console's form and goal panel carry it.
- **`swarm.sh context <id>`**, the context history of a run from its trace
  (`scripts/context-audit.ts`, Markdown or `--json`): per agent the model,
  the ceiling and the lines, the turns, the peak, the crossings, the holds,
  the hand-offs and Pi's own fallbacks with what each summary cost and which
  model wrote it, the largest climb in one turn, the outputs kept under
  `tool-output/`, the deliveries paged; then one sentence per thing the
  record says about the lines. What the defaults are revisited from.
- **The write guard reaches a pane whose login shell is bash.** The only
  hook was `$ZDOTDIR/.zshenv`, so a bash account was refused at kickoff (or,
  before that check, ran every pane unguarded). On such an account the panes
  are now given `HOME=<sandbox>/.bash`, whose `.bashrc` and `.bash_profile`
  put the panes' `HOME` back (an `--env HOME` if one was given), re-run the
  same bash under `fsguard.sh`, and then read the user's own configuration.
  `HOME` is moved for a bash account only, so a shell that reads neither
  hook keeps its own. The login-shell check now runs whenever a hook is
  written, `--no-write-guard` with `--inputs` or `--quarantine` included: a
  shell that is neither zsh nor bash is refused while the write guard or
  `--inputs-enforce on` depends on it, and warned about otherwise. A login
  shell the account database does not give is warned about rather than
  taken for zsh; before, a `getent` that exited non-zero (as it does for a
  user it does not know) ended the kickoff under `pipefail` with no message.
  Verified
  live on Ubuntu with Herdr 0.9.1 (`s5038` in `docs/verified-runs.md`).

### Changed

- **A team on a subscription is braked by tokens (breaking for such runs).**
  A seat whose provider is an OAuth login in Pi's store (`openai-codex`) no
  longer makes a team metered: Pi's dollars for it are an estimate, and on the
  BelkaCTF #6 run a Luna seat with ten million tokens read $0.13 beside a
  Daybreak seat's $14. A team with no metered seat needs `--cap-tokens`, as a
  team of local models does; `--cap-usd`, `--cap-per-agent` and a `@cap` on a
  model are said to brake nothing there. New: `--cap-per-agent-tokens`, the
  per-seat brake in tokens (budget.json and the registry as
  `cap_per_agent_tokens`).
- **Caps change while the run goes on: `swarm.sh cap <id>`** with `--usd`,
  `--tokens`, `--per-agent-usd`, `--per-agent-tokens`, `--wall-clock`. Made
  under the table lock the usage folds take, kept in `budget.json` as
  `cap_changes` with the caps each left (the shell watch no longer reports
  such a change as the agent's write, and now also watches the per-agent and
  per-model caps), put on the trace as the operator's, merged into the run
  record and said on the board. A swarm-wide stop the run is no longer over
  is withdrawn; a seat's own cap steer lifts on its next check. The run keeps
  its brake and a finished run stays finished.
- **`wait` sleeps through posts addressed only to other agents.** A post on
  `main` whose `to` names teammates and not the waiting agent no longer wakes
  it; it stays unread and the next delivery carries it, and the result counts
  it as `passed`. A post to all, to the agent by id or by the name it chose,
  or to no one on the team (a role, a word) still wakes it, as does any post
  in a side thread it is in; `every_post: true` wakes on everything, for a
  seat that follows the whole board. On the BelkaCTF #6 run 586 of 1,291
  wake-ups on posts were for posts to someone else, each a model turn with the
  whole context resent; the three GPT-6-Luna seats spent most of their 87M
  tokens that way.
- **The contract names no program when the image describes itself.** A
  microVM run whose image has `tools.md` gets one paragraph, "## Programs",
  that points at the file inside the VM; the table of sixty programs, a third
  of `SWARM.md` and read by every agent at every start, is gone for it. An
  image without the file, and a host run, keep the checked table.
- **A pack's tools are said to be in the tool list, not listed as another
  case's.** They sat under "Seeded tools (case-specific) … written against
  another case", with "baked: offset 20000" for a limit and an example
  FILETIME taken for an offset. The contract now says the packs put N tools
  in the tool list, each described there, general and fed by the arguments.
  Only `--tools-from` copies are listed as another case's, and "baked" is an
  `inputs/` path or an offset their example gives.
- **The goal's check on the trace for `inputs_check` says the harness writes
  it.** Read bare, `grep -q '"tool":"inputs_check"' traces/events.jsonl`
  sent five agents of sixteen on the sixth CTF round to forge a tool by that
  name to satisfy it (refused, as a reserved name). The contract adds, in
  prose, that `done` writes the line when it verifies the inputs.
- **A shell write in the writer's own directories takes no lease.** No peer
  may claim or write there, so the implicit claim protected nothing: one
  ileapp run was 507 of a run's 644 `claim_file` lines, each a lock file. The
  write is still snapshotted.
- **The kickoff's encrypted-volume warning is not given to a VM run that has
  `encrypted-containers`**: it told operators who had passed the pack to start
  again with it.

- The pinned `@earendil-works/pi-coding-agent` is **0.87.0** (was 0.85.1):
  npm `latest`, and what the Linux host already ran. The provider contract
  changed between the two (a transcript with system messages instead of
  `{systemPrompt, tools}`); the scripted provider behind the self-compaction
  e2e speaks both, and the suite passes on both.

### Fixed

- **Every input has a row in the catalog's coverage.** `evidence-catalog.sh`
  skipped an input under 64 KB, or one that was neither a disk nor a memory
  image, without a word: BelkaCTF #6's 5.1 GB iPhone tar had no catalogue and
  no mention in the index, and ten agents listed it with `tar -t` 59 times,
  7.2% of the run's input tokens. `catalog/coverage.tsv` now has one row per
  input with its status (catalogued, partial, segment, not catalogued, not
  probed) and why; the summary line counts them, and the index names what was
  not catalogued or catalogued in part, twenty of each and the count of the
  rest. A memory probe that finds no Windows image keeps what `vol` said under
  `catalog/probes/`. Inputs are enumerated NUL-separated, so a name with a
  newline in it is one input, and a tab, newline or backslash in a name is
  written escaped in the coverage file, the index and its notes.
- **A catalog step's stderr is kept whole.** A failed step kept 200
  characters of stderr in the index and deleted the rest; every step's stderr
  now stays beside its output as `<file>.stderr`, listed in the index, and a
  failure's note quotes its start and names that file.
- **`catalog_search` keeps every match.** It returned the first `limit`
  matches (200 by default) and dropped the rest, so an agent that wanted them
  searched again with a bigger limit: single results reached 70K characters,
  and search results were 2.7 to 12.5% of a run's input tokens. It returns 50
  by default with the count of all of them, pages with `offset` and
  `next_offset`, and when a page is not all of them writes every match, with
  its line number in the catalogue file, to
  `work/<agent>/catalog-search/<which>-<hash>.txt` and names it
  (`all_matches`). Version 7, in computer-forensics-base 1.2.14.
- **The library's catalog searches read the case in front of them.**
  `tool-library/catalog_search` was a first version that read
  `catalog/SysInternalsCase.E01` and nothing else, and `grep_filelist` read
  the AF-Case2 list on every case, while the docs hand the library to any run
  with `--tools-from tool-library`. The library's `catalog_search` is the
  pack's; `grep_filelist` (version 4) takes `path` or the only file list the
  catalogue has, and keeps every match past its hundred in a named file.
- **The agents are told the catalog's coverage.** The contract and the worker
  prompt said to read the catalog instead of running the same commands again,
  which was wrong for an input it did not cover; they now say to start from
  it, check `coverage.tsv`, and open what it did not catalogue with other
  tools.
- **A pack tool gets the timeout its manifest asks for**, up to an hour
  (`PACK_TOOL_TIMEOUT_MAX_SECONDS`). Every run clamped pack tools to the
  forged-tool ceiling of 120 s while telling the model the manifest's figure:
  26 of them ask for 300 to 3600 s, and `timeline_super` (3600 s) and
  `mem_carve` (900 s) died at 120 s. A forged tool keeps the 120 s ceiling, and
  the description and the timeout message say the timeout actually applied.
- **A failed tool call reaches the model as an error.** Pi takes a failure only
  from a throw and drops an `isError: true` a tool returns, so every refusal
  (`publish_file`, `record`, `done`, `name`, `make_tool`) and every failed pack
  or forged tool reached the model and its session as a success. The
  `tool_result` hook sets the flag from `ok: false` in the result's details.
- **A VM's probe asks the hub again.** With eighteen VMs running and a third
  run coming up, two seats of eight had their first connection close with no
  answer, twice, and the kickoff stopped with "no answer" and nothing else.
  The probe tries five times, three seconds apart, and records what the hub
  said, or that it said nothing, and how many tries it took. A close with
  nothing said reads the same whether the platform reports it as a clean
  close, a reset or a broken pipe, with the error kept beside it.
- **`regkv`, `regkeys` and `shellbags` answer a key that is not there** with
  the deepest key that is and the names under it (windows-forensics 1.2.9,
  the tool library's regkv 3 and regkeys 4). regkv printed regipy's
  traceback, twice on the sixth CTF round, for keys an agent had guessed.
- **`chunk_needles` streams what `icat` gives it** (computer-forensics-base
  1.2.13, the tool library's 3). It held icat's whole output in memory, and on
  a pagefile the VM's kernel killed it with nothing said, twice on the sixth
  CTF round. A failed icat says why, with how far the scan got.
- **`sqlite_query` gives back bytes that are not UTF-8 as `\xNN` escapes**
  where it died on a `UnicodeDecodeError` (an ActivitiesCache Payload).
- **`browser_history` runs several statements one by one** (windows-forensics
  1.2.9, the tool library's 2), each answered in `results`, where "schema;
  count" was "You can only execute one statement at a time". A `;` inside a
  string stays in its statement, every statement must still be a SELECT, WITH
  or PRAGMA, and a refused query is quoted whole.
- **`sqlite_query` says when a file is not SQLite** (computer-forensics-base
  1.2.13, the tool library's 4): its header, the first page's entropy, and
  whether that reads as an encrypted database (SQLCipher or an app's own) or
  another format, where sqlite3 said only "file is not a database". A missing
  database is a JSON answer too.

- **`sigma_hunt` passed Zircolite `--noexternal`**, which Zircolite 3
  removed and refuses. Its `auto` engine prefers Zircolite, so once the disk
  image held Zircolite it would have failed at the argument error where it
  ran hayabusa before. It no longer passes the flag (2.x without it uses its
  bundled evtx_dump).
- **`unified_log` gave UnifiedLogReader three places where it takes
  four** (uuidtext, timesync, the tracev3 files, and its output), so off a
  Mac it only ever got an argparse error. It now passes all four, for a
  `.logarchive` and for a copy of `/private/var/db`.
- The windows-forensics pack named RegRipper `rip` under "GPL". Debian
  installs it as `regripper`, and it is MIT, by its own licence file and
  Debian's copyright. computer-forensics-base called bulk_extractor MIT; its
  2.2.0 release says GPL-3.0-or-later for the code since 2015, public domain
  for the original NPS work, and bundled third-party code under its own.
- **A seat's large file froze its link to the hub, and the seat was
  stopped mid-case** (real CTF runs on macOS and Linux). Recording a file
  a seat had just extracted sent its bytes as one RPC line; msb's vsock
  path from guest to host stops moving on a single write of about 256 KiB
  (measured: ~215 KB crosses, ~262 KB stalls; the network path is not
  affected), and every later call on that connection, the liveness check
  among them, waited behind it until `hub_lost_stop`. No line on a seat's
  link is now larger than one part (32 KiB of payload, 44,716 bytes on the
  wire): larger requests, answers, trace lines and prompts travel in parts,
  each acknowledged, checked by size and sha256. A call that times out or
  a write queue that has not moved in 20 s replaces the link, and RETRIED
  calls resend with their request id. A VM test publishes 8 MiB while the
  budget answers within seconds.
- `catalog_search` (computer-forensics-base 1.2.4) failed every call on an
  unbound name; a static scan of every pack and library tool now fails on
  one.
- An installed pack older than the one the checkout ships ran without a
  word; the kickoff says so and names the update command. Pack warnings no
  longer name tools, skills or programs a dependency carries.
- An unpacked `git archive` knows its commit (`scripts/HARNESS_COMMIT`),
  and no longer claims "local changes" it cannot see. `start --check`
  names the isolation, the image and what the model gateway would front.
  `stop` no longer prints Herdr's JSON.
- **A VM seat whose Pi restarted could spend past its cap unseen.** The hub
  dropped the Pi session id from a seat's report and checked each report
  against the seat's whole row, so a restarted Pi's reports (its own totals,
  from zero again) were refused as going backwards until the new session
  alone passed the old total: a seat really at $1.5 stayed recorded at $0.8,
  under a $1 cap. The hub now passes the session id, a report is checked
  against its own session's last one, and a new session is added to the
  seat's total; the row still never goes down.
- The console no longer refreshes its claims view on the table lock's own
  files (`.probe.*`, `.table.lock.break`, a released lock's rename), and a
  pane's shell that writes `done/ALL_AGENTS_DEAD` is caught like one that
  writes the sentinel.
- **No agent could publish a shared file.** `publish_file` was registered
  but missing from the tool allowlist swarm.sh gives Pi, and in a VM it is
  the only way `work/report.md` is written. In the second CTF round the
  agents on both hosts wrote their reports under their own directories and
  abandoned the run with the finish line unmet. A test now fails on any
  registered tool the allowlist does not name.
- **A request with a `%` near its start was stopped as a leaked
  credential.** msb 0.7.2 reads the placeholder in the Authorization header
  as "in the body" when the first TLS record also holds a `%` or a `\u`
  escape of a Content-Length body, and closes the connection; Pi reports
  "Connection error." One agent's every compaction summary failed on it
  (its conversation began with a URL-encoded access log). In a VM the
  extension now sends a body to a secret's host chunked, which reaches msb
  apart from the headers; a VM test shows the plain request stopped and the
  chunked one answered. A failed compaction now names Pi's own fallback
  failure as well as ours.
- **Custody, the report and the console called every placeholder msb
  stopped "aimed at a host not its own".** The Linux CTF's 52 stops were
  all to api.openai.com, the host the credential is bound to (the
  percent-sign false positive above). The VM record now names the variable
  each secret is held under, custody marks a stop on the credential's own
  host and says it as a failed request, not a leak, with where msb found
  the placeholder, and the report and the Custody tab show the two apart.
- **On a macOS host, grep called every large mounted file binary.** msb
  passes a guest's `SEEK_DATA`/`SEEK_HOLE` to macOS unchanged, and macOS
  numbers the two the other way round, so each file under a mount looked
  like one hole and GNU grep printed "binary file matches" instead of the
  lines of a catalogue file list. The base image preloads `seekfix`, which
  swaps them back only on a FUSE file whose server answers the swapped
  pair; a VM test reads a 264 KB mounted list with grep.
- `start --pack A --pack B` kept only B: a second `--pack` replaced the
  first without a word (the Linux web-server CTF asked for
  windows-forensics and memory-forensics and ran without the former's
  twenty tools). Repeated, the flags now add up, as `image-for`'s did.
- The first prompt told each agent to read `threads/main` (a directory)
  and `done/SWARM_DONE` (absent until the end): two failed calls per agent
  at every start. It now sends them to `inbox`, which answers both.
- Pack tools the round found failing on every call: `catalog_search` looked
  for the filesystem in `p0`, where the catalogue names it by its first
  sector (`p2048`); `esedb_query` passed `esedbexport` a `-q` the Debian
  build lacks; `sqlite_query` passed `sqlite3` a `-uri` it never had, and
  lost the CSV header on a newer shell. `icat_extract` and `chunk_needles`
  now find an image without an extension by its catalogue (a raw `dd` named
  after the host) and default the offset to the one filesystem the
  catalogue lists (`icat` at sector 0 of Case4.E01 said "Cannot determine
  file system type"). `esedb_query` named each table by libesedb's
  export file (`Container_1.6`), so `table=Container_1` was "no such
  table"; it now lists and reads tables by their own names. `shellbags`
  never decoded a shell item (regipy gives a REG_BINARY as a hex string,
  the tool took only bytes), read a root folder's GUID two bytes early,
  and, like `regkv` and `regkeys`, looked keys up without a leading
  backslash, which regipy answers by dropping the path's first part: a
  UsrClass.dat's BagMRU was "not there", and an NTUSER.DAT answered
  Software\...\BagMRU under the Local Settings name. `catalog_search`
  takes a catalogue by the name the index lists (`catalog=Case4.E01`, or
  `Case4.E01/p2048`), which was a traceback; `sqlite_query` without `sql`
  and `ioc_scan` on a missing path answer in JSON instead of raising.
  With a disk and a memory image catalogued, the disk's catalogue (the one
  with `partitions.txt`) is the default instead of "several catalogues".
  `icat_extract` refuses an inode the catalogue lists only as a directory
  (an agent extracted Edge's History directory as `EdgeHistory.db`: 272
  bytes of `$INDEX_ROOT`, then "file is not a database") and answers a
  file's catalogued path with it.
  `lnk_parse` on a missing path says so instead of raising.
  computer-forensics-base 1.2.10, windows-forensics 1.2.6.
- A forged tool's environment carried the calling pane's
  `SWARM_TRACE_TOKEN` in a host run, and the tool may be another agent's
  code. The token is a credential and is kept out now, like the console's.
  From @elhoim (#36).
- **The spend brake could come off.** A seat whose Pi session restarted
  reported from zero and its row was replaced, so a swarm over its cap read
  as under it and the stop steer was cleared; the fold now keeps each
  session's last report by session id, and a seat's row only grows. (In a
  microVM the hub refuses a report smaller than the row, so a restarted
  session counts once it passes the old one.) Under Landlock alone the
  sandbox root allows no new file, so the atomic write of `budget.json`
  failed on every fold; it is written in place there. An unparseable
  `budget.json` is read once more, then left alone with a
  `BUDGET UNREADABLE` veto on the board (through the hub from a VM).
  `--cap-usd 0` is refused for a team that bills. From @elhoim (#28).
- **Two processes could be inside the table lock at once.** Two waiters
  could both break one stale lock, the second removing the lock the first
  had just taken; release removed the lock whoever held it; and staleness
  was asked of a pid, which says nothing across a Linux host's per-pane pid
  namespaces. A holder now heartbeats its lock, a break happens under
  `<lock>.break`, release removes only its own lock, and a claim, a budget
  fold, a ledger entry or a history write checks the lock is still its own
  before it commits. A pid is trusted only in the waiter's own namespace:
  pid namespace and boot on Linux, the boot session on macOS (not the host
  name, which can follow the network across a sleep). From @elhoim (#30).
- **A collector restarted mid-run fused the next line onto a torn one.** In
  a microVM run the keeper restarts a dead collector with the same anchor;
  one killed mid-append left part of a line, the keeper's own
  `collector_restarted` line landed on it, and custody called the harness's
  record "edited". A restarted collector now cuts a fragment the anchor
  accounts for into `traces/events.fragment-<ts>.partial` and says so on
  the chain (`trace_fragment_cut`, size and sha256), keeps an anchor the
  file does not match as `<run>.trace-anchor.prev.json`
  (`trace_anchor_mismatch`), and refuses a line onto any other torn tail;
  the watchdogs' shell fallback spills around one too. `package` carries
  the fragment and the kept anchor. From @elhoim (#27).
- **A run whose every agent died waited out its timeout, and in a microVM
  it was then called finished.** The reaper writes `done/ALL_AGENTS_DEAD`,
  never the sentinel, once every seat is done or dead and one is dead;
  `await-done.sh` fails at once, the watchdog and the VM hub's backstop stop
  for it instead of writing `done/SWARM_DONE` past the wall clock, and the
  summary and the report say every agent died. From @elhoim (#45).
- The report, the dossier and the console's preview took seconds on a long
  line of `|` after a table header, or of `[` or `[a](` (100,000 pipes: 11
  s). The table divider and the link are read in linear time. From @elhoim
  (#37).
- `cron_dump` took time quadratic in a timer's blank lines (about 40,000
  passed its 60 s timeout, and the sweep printed nothing), and gave an
  empty `Unit=` the next line as its value. It reads a unit line by line.
  linux-forensics 1.0.1. From @elhoim (#38).
- `file_carver`, `mem_carve` and `timeline_super` wrote wherever their
  output path pointed, `../` and `inputs/` included; like `icat_extract`,
  they refuse a path outside the run or under `inputs/`.
  computer-forensics-base 1.2.11, memory-forensics 1.0.3. From @elhoim
  (#44).
- A malware entry's checks could not tell a run without `--quarantine`: the
  flag was only in the registry. `inputs.json` says whether the no-exec
  held (`"quarantine": true` in every microVM run, and in a host run with a
  kernel guard; false with `--inputs-enforce off` or no guard, whatever the
  flag), and the five malware entries check it. From @elhoim (#40).
- `--toolbox auto` read a goal's metadata block with its text, and the
  library's common words (`gpg`, "container") asked for the crypto set in
  most entries. A goal's `toolbox:` key names its sets now (every library
  entry has one, an unknown set is a BLOCKER); without it only the body is
  read, and a VHD(X), VMDK, QCOW2 or encrypted container under the inputs
  adds crypto. A Python library is found by its import (pybde, pyvhdi,
  pytsk3 and dfvfs were always "missing"), the crypto set checks libvshadow
  (`vshadowinfo`, `pyvshadow`) and the linux set xfsprogs (`xfs_db`) and
  libvslvm (`vslvminfo`, `pyvslvm`). So on a host, `--toolbox-required`
  now also requires these VSS, XFS and LVM readers wherever their set is
  asked for; in a microVM run it still blocks only on what a pack requires.
  From @elhoim (#41).
- The Windows Q1s (host intrusion, domain controller, ransomware host, IIS)
  ask for the audit policy in force and each log's range, so an absent
  event reads as not audited, rolled over or cleared, not as never
  happened. Pack and prompt goals use the library's sign-off and
  `inputs_check` checks, and a lint holds them to it. cloud-forensics
  1.0.2, encrypted-containers 1.1.1, linux-forensics 1.0.2, macos-forensics
  1.0.2, memory-forensics 1.0.4, mobile-forensics 1.0.2, network-forensics
  1.0.2, ransomware-response 1.0.1, reverse-engineering 1.0.2,
  triage-collection 1.0.2, windows-forensics 1.2.7. From @elhoim (#43).

- **The venv was 642 claims and seven violations, and the panes' temp
  files were more.** With `--allow-install` one agent's pip created
  `work/.toolchain/`; the shell-write watch took every file in it as that
  agent's implicit claim, the next agent's pip into the same venv as seven
  `CLAIM VIOLATION` posts, and the thousands of files pushed the watch past
  its budget so every agent was told `work/` was no longer covered (run 6,
  Linux, 2026-09-22). Pi's own bash spill files, written to the panes'
  `TMPDIR` under `work/.tmp/`, were claims and a violation too. The watch
  now leaves `work/.toolchain/` and `work/.tmp/` alone (`SHARED_WORK_DIRS`),
  and the spill file is removed once its whole copy is under `tool-output/`.
- **After a hand-off, agents answered the hand-off message with a status and
  ended their turns.** All four agents on run 6 did, a few tool calls after
  their notes came back ("they only asked for a compaction hand-off"), and
  three sat idle for ten minutes. The hand-off header and the system prompt
  now say the message is the harness, not a person, that it is not to be
  answered with a status, and that a turn that ends is not waiting.
- **The idle watchdog was found dead a minute after the kickoff started
  it, on runs 5 and 6 (Linux).** An empty log, no state file, nothing in
  the journal; a probe of the same detach from the same tmux session
  survives, so the cause is not established. The kickoff now looks two
  seconds after starting it, starts it once more with stdin closed when it
  is gone, and prints which happened; `swarm.sh status` reports every
  daemon's liveness from its pid file, so a dead watchdog is a line rather
  than a silence. On run 6 the watchdog, run by hand, woke all four agents.
- `swarm.sh context` no longer lists the watchdog's `system` rows as a seat.
- **A forged tool was killed at 64 KB of output and the rest was dropped
  unrecorded.** A parser that emits a large CSV, the normal case on a
  forensic run, ended with `SIGKILL` and a prefix. The tool now runs to its
  end; the model receives the first 64 KB with a trailer naming the whole
  stream under `tool-output/`, with its size and hash.
- **A shell loop writing to a peer's file flooded the board.** On the Linux
  run s3096 one agent's loop produced 566 `CLAIM VIOLATION` posts in
  fourteen minutes, and every peer's next `wait` delivered all of them: 240k
  characters, 64k tokens, a quarter of a working context spent reading one
  sentence. The board post now comes once per path per minute and says how
  many repeats the minute held; every write is still a `claim_violation` row
  on the trace.
- **A run account with no `~/.zshrc` never started an agent on Ubuntu.** zsh
  opened its new-user wizard in every pane and read the `pi` command line as
  the wizard's menu answer; `herdr agent start` then timed out "waiting for
  agent startup" with four idle panes, and the kickoff exited 1 after the
  sandbox, the daemons and the layout were all in place (measured on the
  Linux host, 2026-09-22). The pane hook now hands `ZDOTDIR` back to the home
  only when the home has a `.zshrc`; otherwise the pane keeps the sandbox's
  `.zsh/`, where an empty `.zshrc` stands in. `docs/linux-server.md` says to
  create the file anyway.
- **On Linux the trace gate was started without its key, so every line it
  forwarded was written unverified while the kickoff recorded
  `attribution: ancestry`.** The stdin line's shape was keyed off a variable
  `start_trace_gate` clears first. The gate and the collector now read one
  schema, `{tokens, gate}`, built once when the tokens are minted; the gate
  always gets the key and the collector gets it only once the gate is up.
  Both log what they were handed, and `tests/trace-gate.test.sh` asserts it
  after a real kickoff; `tests/trace-stdin.test.sh` asserts the shapes on
  any host.
- The kickoff line and the quarantine line named the `linux` and `landlock`
  guards as `none (detect + heal only)`; every mode fsguard has is labelled.
- The custody section said the trace anchor was writable by the panes on
  every host but macOS. It is out of a pane's reach under any write
  allowlist: seatbelt, Landlock with or without the namespace, and the
  namespace mode when bubblewrap makes the root read-only.
- The unenforced terminal-socket line explained the gap as "no seatbelt"; on
  a Landlock-only host the socket is reachable because Landlock cannot mask
  a socket, and the line now says so.

### Changed

- One walk writes the inputs manifest for the copy, the bind and the
  attached image (`write_inputs_manifest`), where there were three copies of
  it. `host_caps` runs once per kickoff and feeds both the contract and the
  registry. fsguard builds the Landlock argument list as an array and passes
  it without `eval`; `--subreaper` belongs to the pane's exec, not to the
  rule set.

- **Licensed under the GNU Affero General Public License v3 or later, with a
  commercial licence alongside it.** Nothing was ever released and the
  repository has never been public, so the licence is decided once here
  rather than inherited. The AGPL asks nothing of anyone running this
  software: on their own machines, on a client's case, whatever they bill for
  the work, modified or not, as long as the modified version stays inside one
  organisation. Section 13 attaches to a single use, offering a modified
  version to other people over a network without publishing those
  modifications, which is the one use that would hollow a project like this
  out. `LICENSE` is the FSF's text verbatim, `NOTICE` carries the copyright
  and the source link, and `package.json` is `AGPL-3.0-or-later`.
  `COMMERCIAL-LICENSE.md` states when a commercial licence is needed and,
  more usefully, the common cases where it is not. The trademark policy rests
  on the licence's sections 7(c) and 7(e). Herdr (Apache 2.0) and Pi (MIT)
  are both compatible and neither is bundled. The 0.3.0 entry below still
  records the MIT `LICENSE` that version shipped.
- **The console offers its own source, because it is a network service.**
  Section 13 asks a modified version reached over a network to offer its
  users that version's source. The page footer and the server's startup
  banner both carry the link, so an unmodified run complies by default and a
  fork changes one constant.
- **Renamed to DFIR Swarm, in a fresh repository.** The name now says both
  what this is and what it was built and proven for: an agent swarm for
  digital forensics and incident response. The repository is
  `halilozturkci/dfirswarm`, started from one root commit holding the tree
  as it stood on 2026-09-19; the package is `dfirswarm`, and the wordmark,
  the page title, the server's banner and every document follow. The
  previous repository, `halilozturkci/dfir-swarm`, is kept archived: its
  pull requests are the ones this changelog and the plans cite by number.
  The extension file keeps its name — `extensions/agent-swarm.ts` is a code
  path, not the product — and the published cases keep their screenshots as
  they were taken.
- **The harness assigns nothing.** `--seats`, the `dfir` seat preset and the
  Seats table in `SWARM.md` are gone, and nothing writes a seat into
  `team.json` or into an agent's system prompt. An agent reads the goal, reads
  the board, decides what it is taking on and says so with the new `name`
  tool; `names.json` records what each one said, every post carries its
  author's name, and the console and the summary show it beside the id. Two
  agents cannot answer to the same name, and an agent may rename itself
  whenever its work changes. The only boundaries the harness draws are the
  sandbox's own: read-only inputs, the no-exec quarantine, the network
  setting, the caps and the protocol.
- The console bundle is split into a vendor chunk (React, the router) and the
  app chunk, so a UI change no longer invalidates the vendor bytes in the
  browser cache and no chunk passes Vite's size warning.
- `@types/node` follows the runtime again (22.x, as `.nvmrc` and
  `engines.node`); Dependabot no longer proposes a newer major for it.
- CI runs with no warnings: git's `init.defaultBranch` hint under
  `actions/checkout` is silenced, and the netguard suite no longer echoes the
  proxy-only fallback it already reports as the detected mode.
- **The extension is type-checked against Pi's own types.** Pi's package
  (`@earendil-works/pi-coding-agent`, pinned) is a devDependency, the ambient
  stub and the separate server tsconfig are gone, and `npm run typecheck`
  covers `extensions/agent-swarm.ts` and every node test with the one
  config. The eight type errors this found were real, small and are fixed.
  A24's fault, two functions called and never imported, is now a compiler
  error. `npm ci` grows by Pi's package; a real run still needs `pi` on
  `PATH`.
- **The change bus drops what the console cannot show, and says what moved
  per swarm.** Pi appends to its session file on every message, the netguard
  proxy logs every connection, the idle watchdog writes its state every half
  minute and every post or claim takes and drops the lock-table mutex; none of
  it changes anything on screen, and together it was most of the events a
  running swarm produced. Those writes are classified (`sessions`, `logs`,
  `internal`) and dropped at the server, so neither the clients nor the
  finish line's change stamp see them. A `change` event now carries
  `by_swarm`, the kinds that moved under each swarm, and each panel keys its
  refetch on the kinds it reads: the board on `threads`, the trace on
  `events`, the files on `history`, the tool source on `tools`, the goal on
  `contract`. The view and the finish line still refetch on any kind, so a
  panel can never be more stale than the page around it. Two more things
  the bus does now, both measured on a post to a fixture swarm: a burst
  ends 200 ms after its last filesystem event rather than its first (one
  post used to arrive as three `change` events on macOS), flushing after a
  second at most under a steady stream; and a path reported again with the
  same size and mtime is not a change (the filesystem re-reports a write
  for a second or more, and a sync client touching attributes reports it
  once more). One post is one event, one appended trace line is one event.
- **The console refetches what changed, not everything.** A swarm's page is
  keyed on that swarm's changes plus the registry's, not on every change in
  the fleet; a burst of changes is one refetch after the request in flight
  lands, not one per change; the elapsed counters tick on the client instead
  of refetching every fifteen seconds. On the server, one swarm's view no
  longer rebuilds every swarm's row to find its own, the event log and a
  thread's posts are parsed once per change and shared, and the finish
  line's shell checks run again only when something under the sandbox moved
  (`/api/health` counts the runs). Same data on screen, a fraction of the
  requests and reads.
- **The shell-write watch caches hashes and says when it is full.** Every
  `bash` call hashes every file under `work/` before and after; a run whose
  extractions reached a gigabyte paid over a second per shell call for it. A
  file whose size, mtime and ctime have not moved is not read again, and the
  watch walks eight levels deep instead of four. When `work/` holds more than
  500 files the harness says so once, on the trace (`watch_truncated`) and on
  the board, instead of leaving the files it no longer covers unwatched in
  silence.
- `npm test` runs the Pi loader suite too (it skips where Pi is not
  installed), and `npm run test:bash` runs every shell suite and reports each
  one instead of stopping at the first failure (`scripts/test-bash.sh`).
- Dead code left the console: an unused messaging timeline, an unused tabs
  primitive and three Radix packages nothing imported; the grace-clock
  formatter and the post-tag colours are defined once.
- Docs brought back in line with the code: the roadmap no longer lists local
  models and the tool library as future work, `--tools-from` reads
  `manifest.json`, the usage page names every tool the agents get, the
  protocol page describes `name:` rather than `seat:` on a post, and the quick
  start cites the Pi version the runs used.

### Added

- **A second run on BelkaCTF #6, in a clean room, and an agent that walked out
  of the network guard.** `s83fd` worked the same evidence and the same goal
  as the first run with the first run's answers denied at the kernel
  (`--no-read`) and no tools carried forward. It reached 9 high-confidence
  answers to the first run's 6, for $68.89 against $77.32, while short-handed:
  four agents had been pointed at one Azure deployment and it rate-limited.
  The isolation was proved from inside a pane before the agents started — 17
  checks — and watched for the whole hour: zero reaches toward the previous
  run across 2,339 tool calls. The run also produced the finding that names
  the limit of this platform. Given `--allow-install --no-pypi`, an agent was
  refused by the proxy eight times and then ran `env -u HTTP_PROXY … pip
  install`, which worked, because netguard on macOS is environment variables
  rather than a network namespace. Four kernel-enforced guards held; the one
  advisory guard did not. `docs/use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md`
  is the whole account, and the contract now tells the truth under `--no-pypi`
  — it had promised the agents an allowlist entry the flag had removed, which
  is why they went looking in the first place.

- **A pane writes inside its run and nowhere else.** The seatbelt profile was
  `(allow default)` with a deny under `inputs/`: it protected the evidence
  from the agents and the machine from nobody. Measured inside a real guard, a
  pane could list the examiner's home, see `~/.ssh`, see every other case on
  the machine, and write outside its sandbox — including `runs/registry.json`,
  which is where `await-done.sh` reads the definition of done from before
  `eval`-ing it as the examiner. `fsguard.sh --rw DIR` now builds a write
  allowlist: `(deny file-write* (subpath "/"))` and the run's own tree allowed
  back, plus the devices a tool needs. Reads stay open on purpose — a
  deny-default profile cannot start `/bin/echo`. `TMPDIR` moves inside the
  run, which let the per-user temp area stay closed with python's
  `NamedTemporaryFile`, git, node, sqlite3 and tar all still working. On by
  default; `--no-write-guard` turns it off; macOS only, and `fsguard` says so
  rather than pretending on a host that cannot apply it.

- **The trace has a writer the agents cannot reach.** `traces/events.jsonl`
  lived in the directory the panes can write, and the only protection was a
  size-and-prefix comparison that announces a rewrite as `blocked: false`. On
  BelkaCTF #6 it fired once — "RECORD REWRITTEN … Nothing can restore it" —
  nobody answered it, and the file turns out to be intact: 2,287 of 2,287
  lines parse. The run's loudest integrity alarm was a false positive. Now a
  collector process outside the pane's profile holds the only writable handle,
  the panes reach it over a Unix socket and get `traces/` read-only, and every
  line carries the sha256 of the line before it — so a line edited or removed
  from the middle breaks something a reader can check, which "the file grew"
  never could. Without a collector a run behaves exactly as before and the
  report says "not chained" instead of claiming a chain it does not have.

- **A record the agents cannot forge, only fail to write.** The chain closed
  an edit in the middle and left two ways round it. A line appended after the
  last one still chained, so a trace could be *extended*: the head of the
  chain is now written to an anchor beside the registry, outside the sandbox
  and out of a pane's reach, and `verifyEventChain` reports `edited`,
  `appended`, `shortened` or `head` rather than a bare boolean. And the
  socket believed whoever wrote to it — any pane could send a line as any
  agent. Each pane now gets a token in its environment (which on macOS no
  other process can read, and which Herdr's API does not expose — both
  measured), the collector takes the token map on stdin where neither argv
  nor the filesystem leaks it, and a line's `agent` is decided from the
  token. A line claiming to be someone else is still written, with
  `claimed_agent` beside it: an attempt on the record is itself a finding.
  `idle-nudge.sh` and `reap.sh` append through `scripts/trace-emit.mjs`
  instead of writing the file directly — their unchained line used to break
  the *next* collector line, so a run with the watchdog on called its own
  record edited every three minutes.

- **The terminal multiplexer's control socket is out of the panes' reach.**
  Herdr puts `HERDR_SOCKET_PATH` into every pane, and that socket
  authenticates nobody: every method is dispatched to whoever connected, and
  the 0600 mode on the file is the whole boundary — which the panes are
  inside of. Measured from within the write guard: it answered. Through it,
  `layout.apply` starts a process with arbitrary argv and environment that
  the server owns, so it is not under the pane's profile and every write rule
  was optional; `pane.send_text` types into a peer's terminal;
  `pane.report_agent` forges another pane's lifecycle state; `server.stop`
  ends the run. `fsguard.sh --no-socket` denies it (a directory denies every
  socket under it, `literal` for a single path), on by default with the write
  guard and `--no-seal-herdr` to restore the hole. The one call the harness
  made from inside a pane — waking idle peers when a `done` finishes the
  swarm — goes through `scripts/nudge-broker.mjs`, where the pane names a
  `kind` and the broker owns the words: an agent can wake a peer and cannot
  tell it anything. The run record carries `herdr_socket` and the report
  prints "Terminal socket". Agent detection is unaffected — Herdr reads Pi's
  state off the screen, and the idle watchdog runs outside the panes.

- **What two review passes found in the two entries above, and what it cost
  to fix.** The anchor did not do what it was built to do: it checked two
  relations between the record and the length it remembered and let the rest
  through, so a line appended with a correctly computed `prev` — and the hash
  that needs is the previous line, which every pane can read — still verified
  as intact. So did a whole rewrite padded past the anchor's count. Stripping
  every `prev` skipped the anchor entirely and printed as "this run had no
  trace collector", the one sentence that tells a reader to stop worrying.
  The anchor also re-read its line count from the file, so truncating the
  trace and letting one more line through moved it *down* to the shorter
  count. Every relation is now decided, the count only ever grows, and the
  collector brackets each append with two anchor writes so that a reader in
  the window between them can tell it from a deleted last line.
  `attribute()` passed the sender's own `agent_unverified` and
  `claimed_agent` straight through, which let an agent stamp its own lines
  unattributable and repudiate them later. `trace-emit` and `sendToCollector`
  reported success when the bytes reached the kernel, so a line the collector
  refused vanished and the fallback built for that case never ran; both wait
  for the collector to say it wrote. The watchdogs' fallback appended to the
  trace itself, putting an unchained line in a chained record — the harness
  raising a corruption alarm against itself — and now spills instead, unless
  the record has no chain to protect. The watchdogs had no token, so every
  line they wrote came back unattributed. The socket deny was written with
  the path as given, and seatbelt matches the resolved one: on macOS
  `$TMPDIR` is `/var/...` for `/private/var/...`, so a rule could be present
  and deny nothing. It was also skipped entirely when the socket did not
  exist yet — the ordinary case — while the run record still said `sealed`.
  The broker checked its roster against a file inside the sandbox, which
  every pane may write, and sent "the swarm is finished, stop" on request
  without checking whether it was: a run-wide kill switch reachable by any
  agent. Neither daemon had a connection limit (300 senders took the
  collector to 821 MB; now bounded and it keeps serving) and neither noticed
  when its run was deleted — 307 orphaned daemons were found running on the
  development machine, and they now exit on their own.

- **An alarm about evidence that never changed.** The integrity check
  fingerprints bytes, mode and link count together, so a returning write bit
  read as "the evidence was modified". One archived run recorded 374 of those
  on two files whose sha256 still match the manifest exactly — 27% of its
  whole trace, every one of them `healed: failed`. Content drift and metadata
  drift are now different things, with `content_ok` answering the evidence
  question on its own, different board wording, and a metadata finding
  repeated at most once per path per ten minutes.

- **The record says which guard was achieved, not which was asked for.** The
  registry said `netguard: true` while the sidecar starts `--mode proxy-only`,
  which netguard's own header calls advisory — sitting beside `inputs.guard`,
  which is measured per pane. `netguard_mode` is recorded and printed, the
  report's custody section carries "Egress enforcement" and "Egress refused",
  and the harness's own `pi.dev` telemetry is dropped from the refusals: it is
  130 of the 172 on that run and it buries the one line that matters, an agent
  resolving a `bit.ly` link it had read inside the seized phone.

- **What a run installed is recorded, and what a tool returned.**
  `--allow-install` wrote nothing down: a report citing a finding produced by
  a library could not name the library's version. The harness now reads every
  `dist-info` under the run's own prefix — name, version, installer, the index
  URL pip recorded, and the sha256 of the package's own `RECORD` — into
  `toolchain.json`, the trace, the board, the report and the handover package.
  And a built-in tool's result carries the first 2,000 characters of its
  output beside `ok`, because `ok: true` is not correctness: 27 of 28
  `bde_unlock*` calls on that run returned `ok: true, exit_code: 0` with
  `InvalidTag` in the payload.

- **The evidence is the one input an adversary wrote, and nothing said so.** A
  search of the prompts, the docs and the code for "prompt injection",
  "untrusted" or "hostile input" returned nothing. The worker prompt and the
  generated contract now say that `inputs/`, `catalog/` and `work/extracted/`
  are material and never instruction, and name the refusal: no network
  request, no install, no execution because of something read in the evidence.
  A `confidence: high` claim wants a second independent artefact, and a
  sign-off by the agent that wrote the files is not a sign-off.

- **`--inputs-image`: evidence the host kernel holds.** A `:ro` bind mount is
  not a write block — `--cap-add SYS_ADMIN`, the capability that mounting a
  forensic image needs, remounts it read-write and edits the host's file
  (measured). So the obvious "give them root in a container" design destroys
  the guarantee the platform rests on. An image attached read-only on the host
  survives the same container, and `--inputs-image FILE` makes that a run
  mode: the manifest records `guard: "image"` with the mode and link count it
  found, the mount point is read-only to the panes (a pane can unmount the
  image — measured — and must not be able to write a replacement in its
  place), and `stop` detaches. The test
  asserts **both** halves, including that the bind mount is defeated, so
  nobody simplifies it back.

- **Every long list is paged.** An agent's trace is 229 calls, the artifact
  index 131 files, the ledger 57 entries — each of them one endless column
  where, past the first screenful, scrolling stops telling you where you are
  and there is no way back to a row you saw a minute ago. One control under
  every long list now: "51–100 of 229 calls", first and last always
  reachable, 25 / 50 / 100 / 250 per page, and a control that does not grow
  with the list. The page resets when a filter makes it a different list —
  page 5 of a list that no longer has five pages is an empty screen with no
  explanation — and a live trace's **Follow** moves to the last page instead
  of fighting it. The raw trace, an agent's trace, its reasoning, the
  ledger's timeline / indicators / findings, the artifact index and the files
  with history all use it.

- **An opened trace row reads like a record, not like JSON.** It was two
  bordered boxes of pretty-printed JSON: `{ "path": "SWARM.md" }` across
  three lines beside `{ "ok": true, "duration_ms": 10 }` in another — four
  lines of punctuation around six characters of fact. Now each argument and
  each result field is its own line, name beside value, wrapping; anything
  long or structured gets a block underneath; `ok` is coloured, because
  whether the call worked is what a reader looks for first; and RAW and COPY
  are there because this is an audit trail and somebody will want the bytes.
  One row is open at a time — two open rows pushed the list so far apart
  that the first was off the screen by the time you opened the second.

- **The trace kept 80 characters of an argument, and dropped every
  structure.** `summarizeArgs` cut each string at 80 characters and discarded
  objects and arrays without a word. So a shell line went into the audit
  trail as `ls -la catalog/ work/ 2>/dev/null; ls catalog/ | head; echo
  '---'; tar tf inp...`, losing the half that said which file it read; and a
  refused `make_tool` recorded `{name, runtime}`, leaving the trace holding
  the error `param "db" must match /^[a-z][a-z0-9_]{2,31}$/` about params the
  record did not contain. An audit trail that quietly shortens what it audits
  is worse than one that says it cannot. It now keeps 20,000 characters — a valve against one
  pathological argument, not a budget; on that run the longest argument, after
  the old clip, was 80 — keeps a structure as a structure while it fits, and when it does clip
  something records the true length under `_truncated` — so the console can
  say how much of how much it holds instead of leaving an ellipsis to be read
  as the whole thing. `make_tool`'s refusal path records the params
  it was asked for, the same as the path through.

- **A trace row opens where it sits, instead of covering the page.** Clicking
  a call used to throw a dialog over the trace: reading two calls meant
  opening and closing two of them, and the list you were reading vanished
  behind the thing you asked about. The row is now a disclosure — call and
  result unfold underneath it, inside the list, as many at once as you like.
  Both panes wrap, which the dialog's did not: a path that was stored whole
  was cut at the pane's edge, so the console looked like it was hiding
  something it was not.

- **What the board adds up to.** The Every-post tab rendered one row per
  thread — on most runs, one row — a pulse line, and then half a page of
  white space, under a run whose 104 posts are the only record of how ten
  strangers divided a case between them. Under the list now: six figures
  (posts and characters, who spoke of the team and who never did, the span,
  the median gap between posts, the longest silence and who broke it); the
  tag mix as one bar and again per speaker, so a team of reporters reads
  differently from a team that asks; a **who named whom** matrix built from
  the agent ids written in post bodies, where the empty rows say as much as
  the full ones; every **hold, veto and stop** on the board, with the
  harness's own marked as its own — on BelkaCTF #6 that is three claim
  violations and a record rewrite nobody would otherwise read; the **paths
  the posts cited**, counted and linked where the run kept the file; and the
  three longest silences with the line that ended each. Every figure is
  counted from `threads/` on disk by a pure module with its own tests —
  nothing here is a model's summary of what it thinks happened. A new
  `GET /api/swarms/:id/posts` returns every post across every thread, bodies
  included, because the swarm view ships only each post's clock, author and
  tag.

- **Every line of reasoning in every run rendered blank.** The harness writes
  a reasoning event as `logEvent(cwd, agent, "thinking", {}, { text, chars })`
  — empty args, the text in the **result** — and the console read `args.text`.
  It printed the empty string, in the raw trace, in an agent's own trace and
  in the "right now" strip, for every reasoning event since the tab existed.
  Two things hid it: the row also echoed `→ {"text":"…","chars":694}` on the
  right, so it read as a formatting quirk rather than a missing field; and on
  the BelkaCTF #6 run three of ten agents — every agent on
  `azure-foundry/grok-4.6` — genuinely emitted no reasoning at all, which made
  a reader's "the thinking blocks are empty" look like a fact about the
  models. The renderer now reads `result.text` and falls back to the old args
  shape so archived traces keep working, and the reasoning row no longer
  repeats its own text as a result.

- **THINKING is a document, not a list.** Reasoning is the one thing in a
  trace written in sentences, and it was clipped to whatever fitted between
  the clock and the duration on a single line. It is now one wrapped block per
  turn, the clock in the margin, the agent's colour down the side. Where the
  harness kept only an opening, a note under the block says how much of how
  much — measured from the text in hand, so a run recorded under the old
  240-character limit is described honestly rather than by today's constant.
  That limit itself is now 2,000 characters: 240 was barely the first
  sentence, so the reason an agent changed direction was never in the record,
  and at 2,000 a ten-agent run's whole trace is still under a megabyte.

- **An empty panel says which kind of empty it is.** "No trace lines —
  traces/events.jsonl is empty for this selection" was shown to an agent whose
  model returns no reasoning, to an agent with seven hundred lines and no
  failures, and to an agent that died before its first turn. The THINKING
  empty state now asks the harness for the per-agent reasoning census — one
  request, `limit=1`, using the new `matched_by_agent` on the traces API,
  which counts the *filtered* set per agent — and says which of three facts it
  found: this model returned none anywhere in the run (naming the models that
  did, with their line counts), this agent alone was quiet while its shipmates
  on the same model were not, or nobody in the run reasoned at all. The other
  lenses get their own sentences: nothing failed, it never posted or read the
  board, it left no trace at all.

- **"Right now" is not a thing a finished run has.** The Agents tab opened
  with five unlabelled rows of raw trace above the agents themselves — on a
  run that had ended, always the same five: `session end`, `session end`,
  `done`, `inputs check`. They were written to show a live team's newest
  lines and nobody had asked what they become once the team has gone home.
  A live run keeps them, with a heading that says what they are; a finished
  one opens on its agents.

- **The run's header is the run, and the page below it is the work.** Three
  things moved. The numbers and the team now sit side by side in the band
  instead of stacked, so neither the vitals nor a box of ten agents owns the
  full width and the right half is no longer empty at every size. The four
  setting chips — Herdr panes, hard-kill, tool forging, the inputs guard —
  left the band entirely: each was already stated where it is used, and all of
  them are now together under **the frame it ran under** in "How this run was
  started", beside the command, with the network allowlist, the toolbox sets,
  the catalog, the quarantine and the per-agent cap that were never shown at
  all. And the section tabs moved up into the band as one row, groups divided
  by a rule rather than by four labels that read as tabs nobody could click.
  The white page now opens on the work itself rather than on four rows of
  navigation.

- **A name is not permanent, and the console now says so.** `name()` can be
  called again whenever the work changes, and on a real run it is: one agent
  opened as "Laptop Triage" and four minutes later was "Dependency &
  Timeline"; another asked for "iPhone identity", was refused because a peer
  already answered to it, took it a second later anyway and renamed itself
  "Docs and money" half a minute on. `names.json` keeps only the last of
  those, so an agent's page showed one title for a decision it had made three
  times. The page now carries the whole sequence — when it named itself, when
  it renamed, when it kept the name and rewrote the job, and every refusal
  with the peer that caused it, which is how two agents worked out they were
  about to do the same work. It reads the trace route rather than the view's
  tail, because an agent names itself in its first minute and a fifty-minute
  run has long scrolled past it.

- **The team, where the model identifiers used to be.** A run's header
  carried a row of grey pills reading `azure-foundry/DeepSeek-V4-Pro`,
  `lmstudio/qwen3.8-27b-uncensored` — the one fact about a mixed team a reader
  cannot act on. It said nothing about who ran on what, what those agents
  called themselves, which of them finished, or where the money went. The
  strip is now one column per model: the agents on it under their own chosen
  names, a dot each for finished / working / quiet / reaped, the model's spend
  and its share of the bill, and every name a link to that agent. Ten agents
  across four providers and one local model is the most interesting thing on
  the page, and it is finally legible.

- **Seven things the console was getting wrong, found by reading it over a
  finished run.** The ledger's timeline wanted 1,645 px and got a horizontal
  scrollbar with its last column cut off, on a screen with room to spare: the
  tables are fixed-layout with shares of the width now, machine strings break
  inside their cell, and the shell is 1,680 px rather than 1,440. The agents
  vital said "6 done" where ten had started and four had ended a provider
  error away from a marker — it reads `6 of 10 · 4 never finished`. A
  `work/*.md` was shown as a monospace block, which is the source of a
  document rather than the document; the report's own renderer moved to
  `ui/src/lib/markdown.ts` and draws them in both places. "Open in new tab"
  downloaded the file, because every artifact was served as
  `application/octet-stream`: the route sends a real content type and
  `content-disposition: inline`, `?download=1` is the one that saves, and the
  panel has a **View** and a **Download** button instead of one that did the
  wrong one. The goal library was a native `<select>` — a full-screen grey
  system menu listing names and nothing else — and is now a control this
  application drew, with a filter, each goal's check count and a warning on
  the ones with no definition of done. The kickoff's field labels wrapped and
  pushed their inputs out of line, so they are shorter and their boxes reserve
  the same height. And the Goal tab opens with **how this run was started**:
  the `swarm.sh start` command, with `--env` values redacted, recorded in the
  registry at kickoff and copyable — the first thing anybody asks of a
  finished run, and the one thing the console could not answer.

- **The forensic report is a document now, not a dump.** The old one opened
  with a key-value list and a numbered list of forty-word sentences, and its
  five-column timeline pushed the page sideways on every long evidence string.
  The cover carries the case number, one sentence of verdict and six numbers —
  findings, indicators, dated events, evidence files, elapsed, spend — so a
  reader decides from the first page how much of the rest they need. The
  findings are verdict cards grouped by confidence, each with its exhibit
  number and the source it rests on, because what a run stands behind and what
  it is only offering are not the same claim. The timeline is a rail rather
  than a table: stamp, claim, source, evidence, nothing to scroll sideways
  for. Every table is `table-layout: fixed` with breaking inside the cell, the
  contents page carries a line about what each section is for, and the print
  stylesheet gives the cover and the contents a page of their own. Two bugs
  went with it: `swarm.sh stop` deleted `netguard.allow` along with the pid and
  the port, so every report written after a run finished said "netguard
  allowlist not recorded" about a run whose allowlist had been enforced all
  along — the record is kept now, and an older run that lost it has its
  allowlist read back from the proxy log and labelled as the weaker source it
  is.

- **A run can install what the case needs, without root.** BelkaCTF #6 found a
  BitLocker volume hidden in an alternate data stream, recovered its recovery
  key from a note inside an iTunes backup, and then spent half an hour failing
  to open it: no `dislocker`, no libbde, no libvhdi on the host. The agents
  never asked for root — they ran `brew install dislocker` and then
  `pip3 install dislocker`, and netguard denied `pypi.org` seventeen times.
  B14 had already found this half of the problem on challenge 9 and only the
  toolbox half was fixed. `--allow-install` fixes the other half: `pypi.org`
  and `files.pythonhosted.org` join the allowlist, `PYTHONUSERBASE` points at
  `work/.toolchain/` inside the sandbox, and what a run installs goes when the
  run goes. Off by default, stated in the contract, recorded in the ledger,
  and offered as a switch on the console's Case card. Root stays refused on
  the examiner's host — these panes are the examiner's own processes, and the
  read-only guard over `inputs/` is exactly what root would undo; a case that
  genuinely needs a mount wants a disposable container (B17), and most do not,
  because libbde, libvhdi, libluksde and pytsk3 read those volumes in place.

- **The crypto toolbox set names the class, not one tool of it.** It gains
  libbde (`bdeinfo`, `pybde`), libvhdi (`vhdiinfo`, `pyvhdi`), libluksde and
  `qemu-img`, all of which read a volume without mounting it. `--toolbox auto`
  now reads the goal document and adds the sets it asks for, and the evidence
  catalog warns when it has just seen a BitLocker or virtual-disk signature on
  a run with no crypto set. The BelkaCTF run was started with `--toolbox dfir`
  and nothing connected "the goal says encrypted container" to "you did not
  ask for crypto" until minute forty.

- **A segmented image is catalogued once.** libewf resolves a whole set from
  any one segment, so `--catalog` was producing an identical partition table,
  body file and timeline for `.E01` through `.E06` — six catalogues of one
  8.7 GB disk, and six times the minutes. The continuations are counted and
  named in `catalog/README.md` instead, so the gap does not read as a file
  that was skipped.

- **A provider failure is an event, not a silence.** Both `deepseek` agents on
  the BelkaCTF run died six seconds apart on `402 Insufficient Balance`. The
  console counted them among "10 working" for the rest of the hour, the board
  said nothing, and the idle watchdog spent all three of its nudges on each of
  them against retries that could only fail the same way. A turn that ends in
  a provider error now writes `agent_error` to the trace and posts the
  provider's own words to the board, and the watchdog leaves that agent alone
  until it works again.

- **A local model gets its first turn.** The LM Studio seat took about four
  minutes to read a 10 KB contract and was nudged twice before it had emitted
  a token; `--idle-sec` is tuned to cloud latency. A seat on a locally served
  model now has `--local-first-turn-sec` (600) before its first silence counts.

- **The package stops carrying the evidence it says it leaves behind.**
  `package` excludes `work/extracted/` and `work/quarantine/` and then wrote
  35 MB of registry hives and browser databases from the agents' own scratch
  directories. Provenance from the trace was tried and dropped — it identified
  0 of the 15 files it had to — so the rule is what a handover is for: binaries
  over `SWARM_PACKAGE_MAX_BINARY_KB` (256 by default) stay in the sandbox and
  are named with their hashes in `LEFT-BEHIND.txt`, next to the hash every one
  of them already has in `artifacts.json`.

- **The swarm page's tab strip stops pretending.** `THE RUN`, `EVIDENCE`,
  `THE FRAME` and `OUTPUT` were small-caps spans inline with the pills in one
  wrapping row: four things that looked like tabs, were not clickable, and
  could wrap away from the tabs they labelled. Each group now has its own row
  with the label in a column of its own. The Tools tab's empty state says
  which of three states it is in — forging off, forging on with N hints and
  nothing forged, or nothing seeded — because on this run an operator read it
  as "the agents are not forging" while the harness had asked five times.

- **The console can start a case, not just a task.** The kickoff form had the
  team, the caps and the read-only inputs, but none of the settings that turn
  a goal into an investigation, so every forensic run so far had to be typed
  at a terminal. `/new` now carries a **Case** card: the evidence catalog
  (the first pass over the inputs, refused without an input set, because a
  first pass over nothing is a kickoff that fails three minutes in),
  quarantine, the toolbox sets, a per-agent USD cap, the case id and the
  examiner. They reach `swarm.sh` as `--catalog`, `--quarantine`,
  `--toolbox`, `--cap-per-agent`, `--case-id` and `--examiner`, and the
  command preview shows them; a per-agent cap above the swarm's own cap, an
  unknown toolbox set and a case id or examiner that has no business on a
  command line are all refused in the browser rather than in a shell job
  somebody has to go and read. First used to start the BelkaCTF #6 run from
  the console.

- **A mark, drawn on the palette the console already had.** Two brackets
  holding five peers: the brackets are the harness, the part that is not
  negotiable, and inside them five agents of five specialisms, all the same
  size because none of them outranks another and nothing was handed out. The
  five colours are `brick`, `slate`, `saffron`, `kelp` and `moss` from
  `ui/src/index.css`, so the mark and the product it belongs to use one
  palette rather than two. `brand/` holds it for a dark ground, for a light
  one, and in `currentColor` for print and for anywhere colour is lost, with
  the usage rules beside them. The console header carries it, reading those
  tokens as CSS variables rather than repeating their hexes, so a retuned
  palette moves the mark with it; the tab icon, until now three dots on a
  teal square that matched nothing, is the same mark on the console's own
  band colour; and the README shows it above the title, switching with the
  reader's theme.

- **What a repository needs before it is public, and not a line more.** The
  Apache licence covers the code; two things it deliberately does not cover
  are now written down. `CLA.md` is the contributor agreement: it leaves the
  contributor's copyright with them and keeps a later decision about the
  project's own terms with the maintainer, which is a decision that stops
  being the maintainer's the moment one outside patch lands without it. It is
  referenced from the contributing guide and ticked in the pull-request
  template. `TRADEMARK.md` says what section 6 of the licence means in
  practice: fork freely, give the fork its own name, and use the name
  truthfully to refer to this project. A forensic tool has a reason to care
  which build a result came from.
- An issue chooser (`.github/ISSUE_TEMPLATE/config.yml`) that routes a
  vulnerability to the security policy rather than to a public issue.
- The upstream licences in the credits: Herdr is Apache 2.0 and Pi is MIT,
  both permissive, and neither is bundled here. Worth stating in a repository
  that cannot run without either of them.

- **Local models.** A team served from this machine or this network — a
  `models.json` provider on loopback, a private range or `.local`, or Pi's
  `llama.cpp` provider — is recognised at kickoff. It bills nothing and Pi
  reports its cost as an exact $0, so the USD cap could never stop it: such a
  team must be given `--cap-tokens N`, `budget.json` records `metered: false`
  and `cap_tokens`, the cap machinery brakes on tokens (`TOKEN_CAP_STEER`),
  and the summary speaks in tokens rather than "$0.00 spent". Before any
  pane opens the kickoff probes the server: that it answers, that it has the
  model, and, for Ollama, the context it will really give against what
  `models.json` declares; a missing `compat` block is warned about. A keyless
  local provider gets a BLOCKER with the placeholder `apiKey` to add rather
  than a pointer to `pi /login`, and `--key-from-env` is refused for it. The
  allowlist takes the literal host from `baseUrl` and its other spelling
  (`127.0.0.1` ↔ `localhost`); IPv6 literals no longer break `host_of_url`.
  `--local-only` turns the allowlist into the local endpoints alone
  (`netguard --only`) and sets `PI_OFFLINE=1` in the panes; the registry
  records `net: "local"`, `metered`, `cap_tokens` and `local_models`.
  `--cap-usd` is now checked to be a number. The console follows: the model
  picker lists every local provider from `models.json` even when Pi omits it
  for want of a key, readiness says "local · needs a placeholder apiKey"
  instead of "not logged in", the kickoff form has a token cap and a
  "Local only" network mode and refuses the wrong combination before
  `swarm.sh` has to, the budget tab speaks in tokens and says "free" when
  nothing was charged, and the fleet's spend line counts free runs
  separately rather than as "$0.00 of $0.00". Plan and evidence:
  `docs/local-models-plan.md`.
- **A forged tool can outlive its sandbox.** `--tools-from DIR` seeds `tools/`
  from a library of tools written in earlier runs — one directory per tool with
  its manifest and script — so they are in every agent's list from the first
  turn with their author and version kept. `swarm.sh tools <id>` lists what a
  run forged and `--save DIR` copies it into such a library. Six Windows cases
  rewrote an event-log filter and two rewrote a prefetch parser under different
  names, because tools died with the sandbox.
- **`make_tool` answers a near-duplicate.** Before anything is written it looks
  for a tool that already does this: the same runtime, overlapping parameter
  names and a description made of the same words. The refusal names the tool
  and its author, so the agent calls that instead of forging one capability
  under a second name — which two seats did six seconds apart on the Azure run,
  before either announcement reached the board.
- **Three network settings at kickoff instead of one switch.** The console's
  kickoff form asks what the panes may reach: *Guarded*, netguard's allowlist
  and nothing else, which stays the default; *Guarded + hosts*, the same
  allowlist plus the names you give, one `--allow-host` each; or *Open*, which
  takes the guard off and says so. Host names are validated before they reach a
  command line, at most twenty, and the old `netguard: false` body still means
  *Open*. The registry records the setting, so a run can be asked afterwards
  what network it had — which a forensic report has to be able to answer.
- **The seat travels with the post.** Every board post carries the author's
  seat in its front matter, and the console shows it under the agent id on the
  board and beside the author in the ledger. An agent id (`s864a06`) belongs to
  one run; the seat ("Key material and cryptography") is what a reader follows
  and the only part of the identity that means the same thing in the next run.
- **Forensic runs.** `--catalog` runs the standard first pass over the inputs
  once, before the agents start (partition tables, body files, MAC
  timelines, path lists; Volatility's process, command-line, network and
  injection lists for a memory image) into a read-only `catalog/` rendered
  into `SWARM.md`. `--toolbox dfir` checks the forensic tools on the host
  into `toolbox.json` and the contract, with install commands for what is
  missing (`--toolbox-required` makes that a blocker). `--quarantine` makes
  `work/extracted/` and `work/quarantine/` no-exec at the kernel
  (`fsguard.sh --noexec`) and strips execute bits there. `record` and
  `ledger` tools keep a shared ledger of dated events, indicators and
  findings with their evidence, deduped across authors, rendered by the
  harness into `ledger/ledger.md` after every record. `--seats dfir` (or a
  `## Seats` list in the goal) gives every agent a seat before the first
  post. `--cap-per-agent USD` stops one seat over its own budget without
  stopping the swarm. `--allow-host` adds a host to the netguard allowlist.
  `--case-id` and `--examiner` go into the contract, the registry and the
  summary. `swarm.sh summary` prints a run summary from the files;
  `swarm.sh package` writes the hand-over with a hashed manifest. See
  `docs/improvement-plan.md` for where each of these came from.
- **Azure OpenAI** as a team provider: `azure-openai-responses/<model>` in
  `--models`, the key variable and the resource host known to the kickoff
  (from the shell or Pi's credential store, with a warning and
  `--allow-host` when neither has it), the Azure settings forwarded to the
  panes. Any provider defined in Pi's own `models.json` — an Azure AI
  Foundry resource serving Grok or DeepSeek deployments, a gateway, a local
  server — now contributes the host of its `baseUrl` to the netguard
  allowlist, so a mixed team of third-party models on one Azure resource
  needs no `--allow-host`. See `docs/credentials-and-teams.md`.
- **Lessons from the first forensic run.** A shell write to an unclaimed
  `work/` file becomes the writer's claim instead of a notice; the agent
  whose `done` creates the sentinel prompts every idle peer once through
  Herdr (`await-done.sh --nudge` does the same from outside); the eighth
  `bash` call with the same command word earns a hint to forge a tool;
  `swarm.sh stop` records `done` when the sentinel exists; the Budget tab
  shows spend by model and marks agents over their own cap; the agents'
  prompt sends scratch files to `work/<id>/`; an idle watchdog
  (`scripts/idle-nudge.sh`, `--idle-nudge-sec`) prompts an agent that has
  made no tool call for three minutes to continue, and to hold `wait` open
  instead of ending its turn. The evidence catalog also reads a logical
  volume image with no partition table (the second challenge's raw NTFS
  volume was skipped at first). A change seen across a `bash` call is
  charged to it only when the command names the path or the file has
  stopped changing and is not a peer's scratch file: a peer's long shell job
  no longer gets every overlapping call blamed for it. The
  console's swarm page gains a Ledger tab: the events, indicators and
  findings the agents recorded, with authors, seats and evidence, live.

- **Read-only inputs** (`--inputs DIR`): hand the swarm a directory it can
  read and never change. The kickoff copies it into `inputs/` with no write
  bits, keeps a pristine clone and a hashed manifest; `edit`/`write`/
  `claim_file` refuse it, a shell write is detected and healed from the clone
  and announced, and where the host can (macOS `sandbox-exec`, Linux mount
  namespace) the whole pane runs with `inputs/` read-only at the kernel
  through `scripts/fsguard.sh` and a `ZDOTDIR` hook. Each agent records what
  guarded it (`inputs_guard`), an `inputs` tool lists the files, `done`
  records an `inputs_check`; a forged tool gets the same bracket as `bash`,
  and a sweep at every turn end heals what a background process changed. The console offers sets from
  `SWARM_INPUTS_ROOT` on the kickoff form and shows the inputs, the guard per
  pane and the healed writes on the Files tab. `--inputs-enforce on` refuses
  to start without a kernel guard. See `docs/inputs.md` and ADR 0005.
- **Forged tools** (`--allow-tool-forging`, off by default): an agent writes a
  tool with `make_tool` — python3, node or bash, JSON on stdin, stdout as the
  result — and every peer's harness registers it as a real tool on its next
  `inbox` / `wait`. `tools/` is harness-owned; names are exclusive; the author
  owns replacements while active; scripts must match their manifest's hash to
  run; timeouts kill the process group; output is capped. A Tools tab in the
  console shows each tool's script and calls; the trace marks forged calls.
  Proven with the real Pi loader and with two Pi agents on the scripted
  provider. See `docs/forged-tools.md` and ADR 0004.

- **A documented use case**: `docs/use-cases/dfir-web-server-case/` — seven
  agents on two providers investigating a 26 GB forensic case handed over
  as read-only inputs, with the board, the trace, the report, the forged
  tool, console and pane captures, and the bill.

### Added

- **`swarm.sh report <id>`: one self-contained document to hand over.** Cover,
  summary of findings, scope and evidence with a sha256 per file, the timeline
  and the exhibits, the method, the artifacts with their hashes, the
  limitations and the chain of custody — plus the swarm's own
  `work/report.md` reproduced verbatim with its headings demoted so the
  document keeps one outline. Exhibit numbers are the ledger's own `seq`, so
  the console, `ledger.jsonl` and the report all name the same row. It fetches
  no stylesheet, script, font or image: it is read in a room that may have no
  network, years after the run. There is no Markdown library either — none of
  the eighteen delivered reports contains an image, a link or raw HTML, so a
  hundred-line renderer covers the vocabulary and the repo keeps its one
  runtime dependency. `--pdf` prints it through Chrome, Chromium or Edge when
  one is installed; `--lint` checks the citations; `package` writes it too.
- **The print stylesheet, which is where "excellent PDF" actually lives.** A4
  page box, `break-inside: avoid` on every exhibit and row, `break-after:
  avoid` on headings, widow and orphan limits, `thead` set to repeat so a
  forty-row timeline carries its column headers onto every page, a 64-character
  hash that wraps instead of overflowing, and chips that keep their ground
  under the printer's "no background graphics" default. What it does *not* do
  is claim page numbers: `@page` margin boxes are unimplemented in Chrome and
  a `position: fixed` running head is anchored to the first page there, so the
  browser numbers the pages and the document asks to be cited by section. The
  document says so rather than being quietly different.
- **`artifacts.json`: every file under `work/`, hashed.** Walked to any depth
  and streamed, so the extracted tree does not have to fit in memory.
  `work/extracted/` and `work/quarantine/` are hashed and listed with
  `packaged: false` — the ledger cites those paths and sometimes their hashes,
  and a reader has to be able to check one without the package carrying live
  material. Symlinks are named and skipped, never followed.
- **The dossier as files, from the console.** `/api/swarms/:id/dossier/`
  serves `report.html`, `summary.md`, `artifacts.json`, `ledger.jsonl`,
  `ledger.md` and `trace.jsonl` with a filename. Nothing is newly exposed; the
  view routes already returned all of it without a token. What is new is that
  the trace arrives whole — `/traces` clamps to the last 5000 events, which on
  a long run drops the beginning of the case — and that the path says
  "dossier" rather than "download", which is a common content-blocker pattern.
- **A Report tab, and a tab strip in four groups.** The panel shows the report
  at A4 proportions beside every dossier file with its size and hash. The
  strip had grown to eleven tabs with no order to it and the evidence hashes
  were hidden inside `files`; it is now *the run*, *evidence*, *the frame* and
  *output*. `docs/improvement-plan.md` B8 claimed the console linked the
  package; after this it does.
- **`HashChip`, `EvidenceRow`, `DownloadRow`, `FileFacts`, `PrintSheet`.** The
  design system's new pieces, so an input, an artifact and a dossier file all
  say the same thing the same way. `HashChip` falls back to a hidden textarea
  when `navigator.clipboard` is missing, which is exactly the case over plain
  http to a LAN address.
- **The design system carries the evidence components.**
  `ui/src/design-system.ts` and `.design-sync/` are on the same branch as the
  components now, which is where they have to be: the barrel is
  hand-maintained, and a component added to `ui/src/components/` and not added
  there is invisible to every future sync with no warning. `HashChip`,
  `EvidenceRow`, `DownloadRow`, `FileFacts` and `PrintSheet` are in the barrel
  and the `componentSrcMap`, each with a preview, and the conventions header
  states the rule they exist for: anything that names a file names its sha256
  beside it. `cssEntry` is re-pointed at the rebuilt stylesheet — a stale hash
  there ships the old CSS and renders unstyled with no error.
- **The sixteen use-case goal documents are in the goal library**, each with a
  header naming the run it came from and the filenames to change. The library
  went from three, two of which draw a pelican, to nineteen.

- **Six tools for the gaps the corpus left.** `esedb_query` closes the one a
  delivered report recorded in its own words — *no `esedbexport`, so
  `WebCacheV01.dat` and `spartan.edb` could not be parsed as tables* — and the
  same wrapper opens SRUDB.dat and Edge's database. `browser_history` copies a
  database and any `-wal` beside it and opens the copy read-write so the
  write-ahead log is replayed rather than ignored, which is what made
  `sqlite_query` fail on those files in one case. `usn_journal` parses
  `$UsnJrnl:$J`, skipping the sparse front and saying where it started.
  `amcache_apps` reads whichever of the two Amcache layouts the hive has and
  names it. `recyclebin_i` parses `$I` metadata and refuses to decode a path
  from an unknown header version. `yara_scan` sweeps with rules the caller
  names — no rule set ships here, because a stale rule reads like a finding.
  `esedbexport` joins the `dfir` toolbox set.

### Changed

- **`record` requires `source` and `evidence`.** Across fifteen cases all 1501
  ledger entries already carried both, so this costs a working run nothing;
  what it stops is the entry that reads like a conclusion and cannot be
  checked.
- **The fixture is a forensic case.** A compromised web server with hashed
  evidence, an attack path, extracted material, a Prefetch timeline and a
  ledger whose entries cite their source; then a USB policy question, a
  ransomware triage, a single-hive triage and a carve stopped by its cap. The
  run ids and the shapes they exercise are unchanged, so the console coverage
  is the same. What changed is that somebody evaluating a forensic tool no
  longer opens it on `pelican-svg` and `raytracer-stopped`. Re-seeding the
  same directory works now, too: `seedInputs` leaves the tree read-only and
  `rm` could not clear it.
- **The corrected report-citation rule.** `docs/improvement-plan.md` B10
  proposed "every `## N.` section cites at least one path under `inputs/`,
  `catalog/` or `work/`". Measured against the eighteen delivered reports that
  rule rejects **60 of their 127 numbered sections**, because a forensic
  citation is usually not a path — it is an inode, a record id, an event id or
  a registry key. The rule that ships accepts any of those, and all 127 pass.
- **`--color-moss-ink` and `--color-slate-ink` are tokens.** `Chip` had been
  hard-coding `#2f5a1c` and `#2c4660` while every other tone used a token;
  two other call sites moved onto them.
- **Every library tool works on more than one case.** `icat_root`,
  `master_icat` and `hdfs_node_icat` hard-coded the image they were written
  for, so they were unusable anywhere else. Those filenames are defaults now
  and `image` and `offset` name any other. Measured over the eighteen traces
  under `docs/use-cases`: `catalog_grep` was called 152 times, `regkv` 84,
  `evtx_query` 64, and four tools never. That is in the library's README as a
  measurement, not a verdict — three of the four were written late, and one is
  the only AES Crypt implementation here. Nothing was deleted.
- **`split_failures` reaches the console.** A pane that fell back to its own
  tab is a pane the operator is not looking at, and the kickoff has always
  recorded it.

### Fixed

- **Who last wrote an artifact is the snapshot, not the trace.** The index
  treated `claim_file` as a write, so a lease looked like authorship. It now
  reads `history/`: a claim is a lease, the snapshot names the writer.
- **The Report tab's download rows had no hash.** They were a hardcoded list
  with no size and no sha256, while the component next to them exists to
  carry both. `GET /api/swarms/:id/dossier` now returns the handover as one
  product — the HTML, the artifact index, and every file with the hash of
  the bytes it is — so the number beside the button is the number of the
  file the button writes. `package` builds that set once instead of three
  node processes hashing `work/` twice.
- **Four icat writers could land under `inputs/`.** A prefix check on the
  path the caller typed misses `work/../inputs/x` and an absolute path.
  `icat_extract`, `icat_root`, `hdfs_node_icat` and `master_icat` now resolve
  the destination the way `aescrypt_v2_decrypt` already did, and refuse
  before `icat` runs.
- **`.jsonl`, `.yaml` and `.xml` were text in the artifact index and binary
  on the console's work/ list.** One table now answers both.

- **`package` shipped less than the run produced.** It globbed
  `work/*.md`, so a timeline CSV, a JSON export and anything in a
  subdirectory were left out of the handover without a word, and it never
  copied `tools/` although the improvement plan said it kept the run's tools.
  It now copies every regular file under `work/`, the run's `tools/` with
  their manifests, `layout.json` and `netguard.allow`, and hashes all of
  them. `work/extracted/` and `work/quarantine/` stay in the sandbox on
  purpose — that material came out of the evidence and may be live — and the
  command says how many files it left behind. Symlinks are not followed, so
  a link an agent dropped cannot pull an outside file into the package.
- **The ledger and the trace are watched for growth, not for equality.** A
  peer recording a finding while another agent's shell call was running
  changed `ledger/entries.jsonl`, and the watch, which compared hashes,
  reported that peer's `record` as this call's unattributed write to a
  protected path. The two append-only files are now marked by length and by
  the hash of that prefix: a file that only grew is the swarm working, and a
  file whose existing bytes changed is a rewrite, reported as
  `record_violation` on the board with the path named.
- **Three library tools answered confidently when they had failed.**
  `extract_stream` ran `icat … 2>&1 | base64`, so an error message came back
  base64-encoded as if it were file content and the pipe made every call exit
  0; failures are now JSON carrying icat's status and its stderr.
  `sigscan_e01` fell back to a hard-coded 42949672960 bytes whenever
  `img_stat` failed and reported that as the image's media size, so on any
  other image it walked a range that does not exist and called the result
  "no hits"; it now refuses unless the caller bounds the scan with `length`,
  says where the size came from, and lists ranges it could not read.
  `regkeys` decoded every `REG_BINARY` value as UTF-16LE with
  `errors="replace"`, turning a ShimCache or UserAssist blob into mojibake
  that reads like text — and because `"replace"` never raises, the hex
  fallback beneath it was unreachable; values are now rendered by their
  registry type, with binary as hex, matching what `regkv` and
  `reg_hive_query` already answered for the same value.
- **Two claims in `docs/improvement-plan.md` that were not true.** B8 said
  the console links the handover package and B12 said the console offers the
  tool library at kickoff; it does neither. Both rows now say what ships and
  what does not.

- **Three claims in the documents that were not true.** The security policy
  told a reporter to email the address on the maintainer's GitHub profile,
  and there is no public address there; it now names private vulnerability
  reporting first and the profile's own contact route as the fallback. Its
  out-of-scope entry said the console's reads are open to the LAN without
  saying what that returns: the goal document, the board, the whole trace,
  every revision of every `work/` file, any artifact, and the `swarm.sh`
  output of each start, stop and reap. The release checklist claimed no
  personal paths were in tracked files, while the maintainer's home path
  appears 2,594 times in the published pane captures and custody sections;
  the row now says what is there, that it is `~/DFIR/SampleCases` and
  nothing else, and why rewriting a verbatim terminal capture would cost it
  the thing it is published for.
- One broken relative link, out of every link in 259 Markdown files: the
  browser-policy case pointed at pane captures that were not kept for that
  run.

- **Six correctness bugs in the seeded tool library, and a test that keeps
  the library honest.** These are the tools agents wrote during the published
  cases and that every later run is handed, so a wrong answer from one of
  them is a wrong answer in a report.
  - **The BitLocker parser read four fields from the wrong offsets** and
    still printed well-formed JSON — the worst way for a forensic tool to
    fail. It took the metadata size from the block header's own size field,
    fell back to a `uint32` at the same offset when that looked too small
    (yielding the size and the version read as one number), took the
    encryption method 20 bytes past where it lives, took the VMK protection
    type 2 bytes short of it, and started entries at 64 rather than 48. Every
    offset now follows the layout libbde documents, the metadata size is read
    from the metadata header and checked against the copy the format keeps 12
    bytes later, and a disagreement is a refusal rather than a walk over
    arbitrary bytes. The fixture in the test was built to the parser's own
    layout, so it agreed with whatever the parser did; it is rebuilt from the
    documented layout, and the old parser cannot read it at all.
  - **The AES Crypt tool's `inputs/` guard was a string prefix**, which
    `work/../inputs/x` and any absolute path walked straight past. It
    resolves the destination and refuses anything landing in the read-only
    inputs or outside the run directory. A truncated file raised `IndexError`
    where the harness can only relay a traceback; lengths are checked and
    named instead. The manifest's example carried a real case password, which
    an agent would copy into a live call; it is a placeholder now.
  - **`icat_root` exited on `icat`'s code with nothing on either stream**, so
    a failure reached the agent as a bare non-zero with no way to tell a bad
    inode from a missing image. It reports the exit code and `icat`'s stderr.
  - **`grep_filelist` raised on an invalid pattern and on a missing catalog**;
    both are JSON refusals now, the pattern is compiled once, and a result set
    cut to the first 100 says so instead of reading as the whole answer.
  - **`master_icat` read stdin twice**, so the second reader got EOF and, under
    `set -e`, the script died before `icat` ran — the tool never worked. It
    reads its arguments once, validates the inode, refuses an output that
    escapes the run directory, and its refusals reach stdout instead of being
    swallowed by command substitution.
  - **Five manifests no longer matched their scripts** after these edits, and
    the harness refuses a tool whose bytes disagree with its manifest. All are
    rehashed and their versions bumped, the library README is regenerated from
    the manifests (its `fls_root` row had described a tool two versions old),
    and two new tests assert both: every manifest hashes the script beside it,
    and the table says what the manifests say. That drift was invisible until
    a run needed the tool.

- **Thirty-two findings from a second review, one commit each.** The ones
  that changed what the harness does:
  - **A per-agent cap stop wrote the swarm's sentinel**, so `--cap-per-agent`
    ended the whole run instead of one seat — the opposite of what the flag
    documents, and live from the moment the cap first armed. `done` treats
    `reason: agent_cap` as one seat leaving, and the harness stop passes the
    same. The 15-second cap timer now checks the per-agent cap too, so a seat
    inside a long shell call or a `wait` is steered when it passes its own
    ceiling rather than at the next turn end.
  - **A post's `to` field could forge board frontmatter.** A newline in it
    wrote further keys, and the last key won, so a peer's post could read as
    `from: system`. Values are flattened to one line, the first key wins, and
    a post's id comes from its filename rather than from the text.
  - **A forged tool inherited the pane's whole environment**, provider API
    keys included. It now gets PATH, proxy, locale and the run's own `SWARM_`
    context; the console's mutation token is denied by name, and the console
    no longer hands that token to the `swarm.sh` it spawns.
  - **A manifest's `sha256` could be empty or a stub**, which made the
    bytes-match check vacuous; it must be a 64-hex digest, a tool seeded by
    `--tools-from` is sealed into file history at kickoff so its hash is the
    harness's, a directory named after a reserved tool cannot load, and a
    rewritten tool no longer counts as a peer's forge.
  - **Allowlisting a host opened every port on it.** `127.0.0.1` for a local
    model admitted a CONNECT to SSH, to this console, to anything listening.
    An entry with no port is 443 alone; local endpoints carry `host:port`.
  - **The console's API answered any origin** (`access-control-allow-origin: *`
    on every route and the event stream), so a page the operator had open
    could read a run's board, trace, goal and spend. The header is gone, the
    token is a bearer header rather than a query parameter, and an artifact
    page is served under a CSP that cannot fetch.
  - **The reaper killed working agents**: a 300-second silence is normal for a
    `vol` or `fls` over an image, and `swarm.sh status` reaped as a side
    effect of looking. The threshold is 960 seconds, above the catalog's own
    step, a pane Herdr reports as `working` is never reaped, and `status`
    does not reap at all.
  - **Forged-tool output was capped after the child finished**, so a runaway
    script could fill memory first; it is capped as it is read.
  - **`done` could skip the late-correction check** by naming an output file
    that does not exist, or one outside the sandbox.
  - Claims follow the real path rather than a symlink alias; `names.json` is
    harness-owned; the bash watch fingerprints the token cap and the metered
    flag, so a shell cannot lift a local run's only brake; `--env
    SWARM_FSGUARD` is refused whether or not `--inputs` was passed; the
    inputs size and file caps follow the links `cp -RL` will copy; a leftover
    netguard sidecar or idle watchdog from an earlier run is stopped at
    kickoff; the goal library skips a symlink; the overview labels a harness
    stop from the sentinel's own frontmatter instead of inferring it from
    spend.
  - **The evidence catalog** keeps a filesystem whose start sector is 0,
    names its output after the path under `inputs/` rather than the basename
    (two images with the same name no longer overwrite each other), and runs
    Volatility only on files that look like memory.
  - **The tool library**: `icat` and `grep` tools parse JSON instead of
    calling `eval`, extract and catalog tools fail loudly when the image or
    the catalog is missing rather than printing nothing, AES Crypt writes
    plaintext only after both HMACs verify, and the BitLocker parser reads
    the FVE metadata from the volume header offsets.
  - `--toolbox crypto` recognises `pyAesCrypt` as the AES Crypt tool, and
    `SWARM.md` lists a seeded library tool as case-specific.

- **The console's artifact route followed a symlink out of the sandbox.**
  `GET /api/swarms/:id/work/<path>` checked the path lexically and then served
  whatever it pointed at, so a symlink an agent's shell planted under `work/`
  was readable by anyone on the LAN, no token needed. The route resolves the
  file and serves it only when it really lives under `work/`; a test plants
  the link.
- **A forged tool's manifest could name an entry outside its directory.** The
  runner refused that already; the console's read route did not, so a
  manifest a shell rewrote with `entry: ../../..` disclosed the file it
  pointed at. Both go through one check now, an entry is a plain file name,
  and a symlink out of the tool's directory is refused to read and to run.
- **`names.json` was not a harness-owned path.** An agent could claim it and
  rewrite what its peers called themselves through the guarded `write` tool.
  It is in the protected list now.
- **`swarm.sh say` posted without the lock-table mutex**, so an examiner's
  post and an agent's could take the same id. It takes the same mutex as the
  protocol and the reaper.
- Console: an undefined colour token left error notes uncoloured; the
  ledger's names went stale when only the names changed; two running swarms
  were never ordered against each other; a spend past the cap rounded to a
  whole multiple ("2×" at 150 %); the team panel keyed its fragments wrongly;
  and the kickoff form refuses a wall clock above 240 minutes and more than
  twenty extra hosts before the server has to.
- **The per-agent cap never fired.** `--cap-per-agent` was written into
  `budget.json` at kickoff and dropped by the first fold of session usage,
  because the record was rebuilt without the field; the cap then read as zero
  for the rest of the run. Nine forensic runs reported "0 cap steers" while one
  seat finished $1.26 over its cap. The field survives the rebuild now, and a
  test seeds a cap, folds usage, re-reads from disk and asserts the cap fires.
- The published run costs were wrong in both directions, and the case
  documents now carry the invoice rather than the harness's estimate. The
  Azure run was configured with a DeepSeek rate four times below Azure's, so
  it cost $37.03 and not the $24.68 it reported. The eight runs on DeepSeek's
  own API were billed at DeepSeek's peak rate, which is what Pi's catalogue
  carries, while all of them ran outside the peak window, where DeepSeek
  charges half; their DeepSeek seats cost half of what the console showed.
  A `cost` block holds one number, so the reported figure is an upper bound
  whenever a provider's rate depends on the hour.
- `herdr agent start` could hit `agent_pane_busy` on a pane whose shell was
  still starting (more likely with the fsguard hook) and abort the kickoff;
  the launch now waits for the pane to be at a prompt, up to 30 s.
- A large input (a 25 GB disk image) was read whole to hash it; hashing
  streams now, the manifest records mtime and ctime so an unchanged input
  is never re-read, and the inputs copy is an APFS clone where the
  filesystem allows it.
- `swarm.sh start` failed to write the registry on jq 1.6 (Debian 12,
  Ubuntu 22.04), where `label` is a keyword and can be neither a bare key nor
  a variable name; the key is quoted and the variable renamed.

## [0.3.0] — 2026-09-17

The open-source release. Renamed from "Simple Swarm" to **Agent Swarm**.

### Added

- Run a swarm on a Pi **subscription** (OpenAI Codex, Anthropic) with no API
  key, through Pi's own credential store; `pi auth check` gates every model
  before a cent is spent.
- **Mixed-model teams**: `--models "provider/id=count,…"` puts several models
  in one swarm; each agent's model is on the board and in `team.json`.
- A whole swarm end to end with **no provider at all** (`tests/mock-provider.mjs`,
  scripted turns), used for the cap-breach and runaway proofs.
- **Post-sentinel termination**: once `done/SWARM_DONE` exists every agent's
  session is ended at its next tool call, in-flight call included.
- The done sentinel is created with an exclusive `wx` write, so two agents
  finishing at once cannot both claim to have written it.
- **Goal library** (`prompts/goals/`, `/api/goals`), the live contract route,
  and `await-done.sh --checks-json` so the console and the CLI certify a run
  the same way.
- The console redesigned as a warm editorial control room: vitals band, the
  board as a story, the finish line, leases with expiry, team spend, the
  harness panel with a grace clock, the activity strip.
- The console, complete: per-agent colours, thread
  pulse lanes, agent chips with calls, thread overlays with compute budget and
  members, post sizes, the agents page with activity spans, failure ticks,
  token splits and context windows, trace filter chips, a CALL / RESULT modal,
  `/` to find, readiness-aware kickoff.
- One netguard sidecar **port per swarm**, so concurrent swarms never share a
  proxy.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, CI,
  issue and PR templates, Dependabot.

### Changed

- The goal document owns the definition of done; a goal without one is refused.
- Harness-owned paths cannot be written by agents; leases have expiries; threads
  have members and purposes; file history is content-addressed.
- Shell writes are detected, snapshotted and announced on the board rather than
  silently allowed.
- Threads are listed main first, then by most recent post.
- The README is a guide again; the protocol, usage, verified runs and
  troubleshooting moved to `docs/`.

### Fixed

- bash 3.2 empty-array expansions in `swarm.sh` and `netguard.sh`.
- A `pi auth check` failure exit that killed the preflight before it could
  print its blocker.
- The check-then-write race on the sentinel.

## [0.2.0] — 2026-09-16

- Web app: JSON API, SSE change bus, `swarm.sh` actions, fixture seed, API
  tests; Vite + React + Tailwind client; artifacts preview; model picker
  parsing `pi --list-models`.
- Stall reaping, the netguard egress allowlist (unprivileged netns or a local
  proxy), a real Playwright tool driving headless Chromium.
- Pane grid to N=30 across Herdr tabs and workspaces.

## [0.1.0] — 2026-09-16

- V1 N=2 local swarm: file mailbox, exclusive locks, done sentinel, event log,
  live Pi budget, `swarm.sh` kickoff, LAN debugger, file history and restore.

[Unreleased]: https://github.com/halilozturkci/dfirswarm/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/halilozturkci/dfirswarm/releases/tag/v0.3.0
[0.2.0]: https://github.com/halilozturkci/dfirswarm/commit/d8e7e70
[0.1.0]: https://github.com/halilozturkci/dfirswarm/commit/04399a3
