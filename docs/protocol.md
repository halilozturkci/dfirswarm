# The protocol

What is on disk and on the wire: the sandbox layout, posts, claims, the write guard, the done sentinel, the budget, the event log, file history and the registry. This is the contract the harness enforces.


Everything below is enforced or written by `extensions/protocol.ts`.

### Sandbox layout

```
runs/<id>/
  SWARM.md                     the contract (rendered at start)
  team.json                    {swarm_id, n, agents:[{id, role, model?}], models}   the spawner writes `worker`
  names.json                   {names:[{id, name, doing?, at}]}: what each agent said to call it, through `name`; harness-owned
  budget.json                  live spend, see below
  layout.json                  Herdr pane ids, tabs, split failures (spawner)
  netguard.pid                 sidecar pid while running; the last agent to finish stops it
  netguard.port                the sidecar's port (one per swarm)
  idle-nudge.pid               the idle watchdog's pid while running (scripts/idle-nudge.sh)
  .pi/SYSTEM.md                worker system prompt
  .pi-sessions/<id>/           Pi session files per agent (also a reaper activity signal)
  bin/pi                       netguard PATH shim
  tools/<name>/manifest.json   a forged tool: name, description, params, runtime, entry, by, version, sha256
  tools/<name>/run.py|mjs|sh   its script (harness-owned; written only by make_tool)
  inputs/                      read-only copy of what --inputs named (no write bits; harness-owned)
  inputs.json                  its manifest: source, every file with size, sha256, sha1 and md5, enforce, guard, quarantine
  .inputs-pristine/            the clone the harness heals inputs/ from
  catalog/                     --catalog: the first pass over the inputs (partitions, body files, timelines, memory lists), read-only
  toolbox.json                 --toolbox: the forensic tools found on the host, and the missing ones with install commands
  ledger/entries.jsonl         `record`: one line per event, indicator or finding, append-only
  ledger/ledger.md             the ledger rendered by the harness after every record: timeline, indicators, findings
  work/<agent id>/             an agent's own scratch and extracted evidence (no claim needed)
  work/extracted/, work/quarantine/   --quarantine: no-exec at the kernel, execute bits stripped
  package/                     `swarm.sh package`: the hand-over with MANIFEST.txt
  .zsh/, .bash/, .fsguard/     the pane hooks (zsh, bash) and plan for the kernel guard (when one is available)
  threads/main/000001-<id>.md  posts, append-only, one file each
  threads/<name>/meta.json     {name, purpose, created_by, created_at, members}
  inbox/<id>/cursors.json      per-agent, per-thread: highest post id read
  work/                        the artifact(s); work/.browser/*.png from playwright
  locks/<sha256(path)>.json    live claims
  locks/.table.lock/           mkdir mutex for lock-table changes (pid, ns, owner token inside)
  history/<sha256(path)>/      000001.bin … + index.json (rev, ts, agent, bytes, sha256)
  done/agents/<id>.done        this worker exited
  done/agents/<id>.dead        this worker was reaped
  done/SWARM_DONE              the collective is finished
  done/ALL_AGENTS_DEAD         reap.sh: every seat is marked done or dead and there is no sentinel (reason all_agents_dead); a failed stop, never a finish
  traces/events.jsonl          append-only event log
  traces/netguard.log          ALLOW/DENY lines
  tool-output/<id>/<stamp>-<tool>.{out,err,text}.log
                               the whole output of a tool call whose result reached the
                               model as a prefix; named on the trace row with bytes and sha256
runs/registry.json     {runs:[…]} written by swarm.sh
```

Agent ids are spawner-assigned: `<swarm id><2-digit index>`, e.g. `s1a2b00`, `s1a2b01`; the violation probe is `<swarm id>pv`. Ids must match `[a-z][a-z0-9_-]{0,31}` (Herdr-safe). Callsigns agents pick in chat are cosmetic; locks and done files use ids.

### Posts (`post`, `inbox`)

`post(body, tag, thread?="main", to?="all")` appends `threads/<thread>/<000001>-<from>.md` under the table lock, id = max id in that thread + 1:

```markdown
---
id: 7
thread: main
from: s1a2b01
to: all
tag: claim
name: disk-triage
---

Taking work/hello.txt. Will append my id and release.
```

`name` is what the author has said to call it, through the `name` tool, and
it is written only once the agent has said. An id belongs to a single run;
the name is what a reader of the board is actually following, so it travels
with every post and the console and the summary show it next to the id.
Nobody assigns it: the agent reads the goal and the board and decides.

A post the harness writes is `from: system`. Under `--isolation microvm` the
harness code that announces a violation or a notice runs inside the seat's
VM, which the seat's guest root controls: such a post carries `via: <seat>`
in its frontmatter, and `inbox` and `wait` give it to peers as
`from: "system via <seat>"`, the seat's word and not the harness's.

Tags: `intro`, `ask`, `claim`, `result`, `hold`, `veto`, `stop`. Unknown tags are rejected on write and read as `ask`. Thread names are sanitised to `[a-zA-Z0-9_-]`. Posts are never edited; `threads/` is not in the write path anyway because posting is a tool, and the prompt forbids `edit`/`write` there. Posts carry no timestamp; the file mtime is the clock the UI and reaper use.

`inbox()` with no argument returns unread posts from the primary thread plus
every thread the agent belongs to, advances that thread's cursor, and reports
`swarm_done`. Cursors are **per agent, per thread** (`inbox/<id>/cursors.json`):
a single counter used to advance past unread ids in other threads and hide them
for good. `inbox(thread)` reads one thread. Agents may also just `ls
threads/main` — the unstructured escape hatch is the point.

One delivery carries at most `--inbox-page-chars` characters of post text
(40,000 by default, `SWARM_INBOX_PAGE_CHARS` in the pane, `inbox_page_chars`
in the registry), **whole posts only**: a post is never cut, the delivery
stops before the post that would break the bound, and only the delivered
posts move the cursors, so what stayed behind is still unread. The result says
`remaining` and, when it is above zero, a `note` that nothing was cut and the
next call brings the rest; `wait` returns at once while anything for the agent is unread. A post on `main` addressed only to other agents (its `to` names teammates and not this one) does not wake a `wait`; it stays unread and the next delivery carries it, and the result counts it as `passed`. A post to all, to this agent by id or by the name it chose, or to no one on the team wakes it, and so does any post in a side thread it is in; `every_post: true` wakes on everything. On the BelkaCTF #6 run 586 of 1,291 wake-ups were for posts addressed only to someone else.
The event row lists every delivered post's id and sender, whole, and
`remaining`. On the Linux run s3096 two `wait` results carried 578 posts each,
64k tokens, which is what this bound is for; `0` removes it.

`thread_open(name, purpose)` starts a side thread and joins it; `thread_join(name)`
subscribes without posting, which is how a reviewer follows a slice it is not
working on. Posting to a thread joins it. Membership is what decides whose
inbox a thread reaches, so a thread nobody joined is visibly abandoned rather
than silently ignored.

`wait(seconds)` blocks until a post lands in one of your threads, the sentinel
appears, or one of your leases lapses — and returns the unread posts. Idle
agents used to spend a full provider round on every `bash sleep 30; cat
done/SWARM_DONE` poll; on the last live run here a third of all tool calls were
that loop.

### Claims (`claim_file`, `release_file`)

Claim key = sandbox-relative path (escaping the sandbox throws). Lock file `locks/<sha256(key)>.json`:

```json
{ "path": "work/hello.txt", "owner": "s1a2b00",
  "reason": "appending my id", "seconds": 120,
  "claimed_at": "2026-09-16T08:24:39.280Z", "expires_at": "2026-09-16T08:26:39.280Z" }
```

`claim_file(path, reason, seconds?)`. A claim is a **short lease with a
reason**, not an open-ended lock:

- `reason` is required and public. Peers see it on a conflict, `claims` lists
  it, and a violation report quotes it. It also forces the agent to say what it
  is about to do before it does it.
- `seconds` defaults to 120, caps at 600. Re-claiming renews; a legal
  `edit`/`write` renews on the owner's own terms. A short lease means a dead
  agent's claim clears in two minutes instead of blocking the swarm.
- Another owner with a live lease → `{ok:false, conflict:true, owner, reason, expires_at}`.
  A conflict is normal traffic, not a violation.
- A **protected path** — the sentinel, the board, the locks, the traces, the
  contract, `team.json`, `budget.json`, `names.json` — is refused outright. An
  agent that could write `budget.json` could lift its own spend cap; one that
  could write `names.json` could rename its peers.
- Symlinks are resolved before the check, and protected names match
  case-insensitively, so `work/b -> ../budget.json` and `BUDGET.JSON` are both
  refused.
- `claims()` lists every live lease with its reason and remaining seconds.
- `release_file` drops your own lease. `done`, `session_shutdown` and the
  reaper drop everything an agent owns.
- All lock-table mutations run under `locks/.table.lock` (exclusive `mkdir`,
  10 s wait). The holder rewrites `beat` inside it every 3 s, so a lock that
  has not changed for 15 s has no live holder unless that holder has stalled (SIGSTOP, swap, a
  laptop asleep). A stale lock is broken, except that a holder is kept while
  its pid is live and it recorded the same `ns` as the waiter: the pid
  namespace and boot id on Linux, the boot session (`kern.bootsessionuuid`) on macOS. A
  waiter that cannot check the pid — another pane's pid namespace, another
  VM, a lock with no `ns` — goes by age alone. A break happens under
  `locks/.table.lock.break`, which re-checks the lock first, so two waiters
  cannot both break one lock. Age is read on the filesystem's clock: the
  lock and `beat` are stamped by the filesystem, and so is a probe file
  (`locks/.probe.<token>`) the waiter writes next to them, so a lock stamped
  through an NFS client is not aged on the host's clock. (In a microVM run no
  guest takes this lock: the run is read-only in the VMs, and only the hub,
  `reap.sh` and `swarm.sh say` take it, on the host.) The
  heartbeat stops once the lock is no longer its holder's. A holder removes only a lock whose `owner`
  token is its own, and warns (`DFIRSWARM_TABLE_LOCK_LOST`; on stderr from
  bash) when it finds its lock was taken over. `reap.sh` and `swarm.sh say`
  use the same mutex from bash, and hold it for a few seconds at most.
- What the table lock does not guarantee. Each of these needs a process to
  stall or die inside a window of a few filesystem calls:
  - A holder that stalls past 15 s where its pid cannot be checked (another
    pane's pid namespace, another VM) loses its lock. It finds out before its
    next write in `claimFile`, the budget fold, `record` and file history,
    which fail with `TableLockLostError` rather than commit, and at release,
    which warns. The check and the write are still two steps.
  - A holder whose recorded pid is reused by another live process in the
    same namespace keeps a dead lock standing; waiters time out after 10 s.
  - Clearing a stale `.break` repeats the break race one level down: two
    waiters that both judge it stale can both remove it, the second removing
    a `.break` the first has just taken.
  - Release renames the lock to `<lock>.released.<token>` before judging it,
    so it removes only what it judged its own. If the renamed lock turns out
    not to be its own, it is renamed back unless a new lock has appeared at
    the path meanwhile; that step has a gap of its own.

### Write guard and `claim_violation`

The prompt asks agents to claim before writing; the guard is what makes it true. `pi.on("tool_call")` in `agent-swarm.ts` intercepts `edit` and `write`, extracts the path (`path`, with `filePath`/`file_path`/`file` as fallbacks) and calls `guardWrite`. The call is **blocked** (`{block:true, reason}`) and a `claim_violation` event is logged when:

- `AGENT_ID` is unset,
- the tool input has no path,
- no live lock exists for the path (`claim violation: work/hello.txt (no lock)`),
- the live lock belongs to someone else (`result.owner` names them).

On a legal write the hook first copies the current bytes into history and
renews the lease; `tool_result` records the result and logs `file_history`. If
the renewal comes back a conflict — the lease lapsed and someone else took the
path while the agent was thinking — the write is refused rather than allowed to
stomp the new owner's work.

**`bash` cannot be guarded this way.** A shell command can write anything, and
reading the command text to guess whether it will both misses and
false-positives. So the harness brackets every shell call with a hash of the
paths worth watching — every live claim, plus `SWARM.md`, `team.json`,
`layout.json` and the sentinel — and compares afterwards. A change that is not
accounted for by a recorded revision is snapshotted, logged as a
`claim_violation` with `via: "bash"`, and announced on the board by `system`:

> ⚠ CLAIM VIOLATION: `s1a2b01`'s bash call modified `work/pelican.svg` while
> `s1a2b00` holds a live claim on it ("landing v2"). The result was snapshotted
> as rev 7 (`2f7b1230`). The previous revision is in file_history and can be put
> back with file_restore.

The write is **not** reverted: the claim's owner decides, and reverting from the
harness would also undo whatever else that command legitimately wrote. See
[ADR 0001](adr/0001-detect-bash-writes-rather-than-block-them.md).

`budget.json` is not content-watched — every agent rewrites it every turn, so
watching its bytes would blame whoever happened to be running a shell at the
time. Its **caps** are fingerprinted instead, which the harness never changes
mid-run, so lifting your own spend cap through the shell is still caught.

The watch reads a file again only when its size, mtime or ctime has moved
since the last snapshot; a run whose extractions reach a gigabyte would
otherwise pay over a second of hashing per shell call. It covers at most 500
files under `work/`, eight levels deep. Past that the harness says so once
per agent, as a `watch_truncated` event and an `ask` post to that agent: a
shell write to a file the watch left out is not detected or snapshotted.

### Read-only inputs (`inputs/`, `inputs.json`, `inputs`)

`--inputs DIR` copies a directory into `inputs/` and the harness keeps it as it was: `edit`, `write`, `claim_file` and `file_restore` refuse any path that is or resolves into `inputs/` (`read-only input: …`); the bash watch covers every file there through a stat cache, and a change, deletion or addition found after a shell call is healed from `.inputs-pristine/` and logged as `inputs_violation` with a `veto` post on the board; where the host allows it the pane runs with `inputs/` read-only at the kernel (`scripts/fsguard.sh`), and each agent records what it measured as `inputs_guard`. The `inputs` tool lists the manifest. `done` records an `inputs_check`. The whole design is in [inputs.md](inputs.md) and ADR 0005.

### Ledger (`record`, `ledger`, `ledger/`)

`record(kind, value, ts?, source?, evidence?, confidence?, supersedes?, refs?)` puts one fact in the swarm's ledger with its provenance. `kind` is `event` (a dated event; `ts` required: ISO 8601 with its zone, `Z` or an offset such as `+03:00`, or a date alone, which is that day at 00:00Z; a time without a zone is refused rather than read in the host's zone, since the zone is part of the evidence; stored as UTC, with the text as written kept as `ts_raw` and shown beside it in `ledger.md`), `ioc` (an indicator: an address, a hash, a path, an account), `finding` (a conclusion) or `absence` (a search that found nothing: `value` is what was looked for, `source` what was searched, `evidence` the query, the tool and its version, and the scope, such as allocated files only or unallocated space and slack too, and the time range; all three are required, since an empty result holds only for that query and that scope; optional to use, and nothing asks for it); `confidence` is `high`, `medium` or `low`. An entry equal in kind, value and time to one already there is merged: the second author is added, missing evidence or source filled in, nothing duplicated. Every entry lands in `ledger/entries.jsonl` (append-only, under the lock table's mutex) and the harness re-renders `ledger/ledger.md` — the timeline in time order, the indicators, the findings, each with its authors — after every record. `ledger(kind?, limit?)` lists the entries. A correction is a new entry with `supersedes` set to the `seq` it corrects (a number, `"7"` or `"#7"`): nothing is deleted, `ledger.md` marks the corrected entry "superseded by #N" where it stands and the correction "corrects #M", and `ledger` lists `superseded_by` on the corrected entry. `supersedes` is part of the entry's chained core, so a correction cannot be moved to another entry without breaking the chain. `refs` names the run's objects the entry rests on (at most 20): `input:<path>`, `job:<id>/<path>`, `import:<id>/<path>`, `member:<generation>#<n>`, `sha256:<hex>`, or `unresolved:<why>` when none can be named. Each is resolved when the entry is written (the input in `inputs.json`, the file in the job's sealed manifest, the member in the generation's list, the blob in the store); one that does not resolve refuses the entry, with the nearest names. `refs` is in the chained core when present, so a ref added, removed or changed later breaks the chain. A finding with no refs is taken, and the answer carries a note asking for them; the same entry recorded again with refs, where the standing one has none, becomes its correction (it cannot be merged into a core that has none), and with other refs than the standing one's it is merged and told that its refs were not added. `ledger.md` and the report show the refs; custody resolves them again and counts the standing findings by what they rest on: refs (those that no longer resolve named, those that only say why none can be named counted), a path of the run's objects in the prose only, or nothing, which it names as an audit gap. Refused, with the reason: a `seq` that does not exist (the entry's own included), an entry already superseded (correct its correction instead, so the corrections stay one line), a correction that repeats its target word for word, a value that is not a whole number. A correction is never merged into an equal entry. `ledger.md` gives the timeline and indicators a `#` column, counts the corrections in its header, and lists absences in a "Searched, not found" table. The report and the summary keep a corrected entry as recorded and mark it, and show absences in their own section, never as findings. Both directories are harness-owned: a shell write there is a `claim_violation`. An entry over the limits is refused with the reason, never cut: the value at 2000 characters, the source at 1000, the evidence at 4000; the ledger holds 5000 entries.

### Catalog, toolbox, quarantine (`catalog/`, `toolbox.json`, `work/extracted/`)

Three kickoff options for evidence work, all recorded in the registry:

- `--catalog` takes the census of the inputs (`scripts/evidence-catalog.sh`, a wrapper for `scripts/evidence_catalog.py`) and catalogues them with the packs' recipes (`recipes/<name>/` in a pack: a `recipe.json` — id, version, object, order, min_bytes, runtime, entry, `auto` triggers, limits, outputs, what it covers — and an entry answering `detect --target T` and `run --target T --out DIR`, writing its own `index.tsv` and `coverage.json`). computer-forensics-base ships `disk-volumes` (for a disk image: `partitions.txt` and, per filesystem partition, `fsstat.txt`, a body file, a path list and a `mactime` timeline; an image with no partition table read at sector 0 under `p0`), `memory-windows` (Volatility's `windows.info`, `pslist`, `psscan`, `cmdline`, `netscan`, `malfind`, `dlllist`) and `archive-members` (a tar, zip or 7z member list, `members.tsv`, nothing extracted). Every input gets a row in `catalog/coverage.tsv` with its status and why; each step is time-boxed (`SWARM_CATALOG_STEP_TIMEOUT`, default 900 s) and keeps its stderr whole beside its output. In a microVM run with the job service the census only plans (`catalog/plan.json`) and the recipes run as jobs once the hub is up: each result is a generation (`catalog/gen/<g>/`, with `generation.json`), each change a revision (`catalog/revisions/<n>/`, `MANIFEST.json` written last), announced on the board with the tag `result`; a disk's files are also linked at `catalog/<input>/`. Otherwise the recipes run before any agent starts, into `catalog/<input>/`. `catalog/README.md` starts with a `Summary:` line and indexes every file with its row count and size; `SWARM.md` gets the same under "Evidence catalog". The census files are `chmod a-w`, and every VM sees `catalog/` read-only.
- `--toolbox dfir` runs `scripts/toolbox.sh`: `toolbox.json` holds `present` (name, version, use) and `missing` (name, use, install command) for the Sleuth Kit, Volatility 3, regipy, python-evtx, yara, exiftool, sqlite3, strings and python3; `SWARM.md` gets a "Toolbox" section so the agents start knowing what they have. `--toolbox-required` turns a missing tool into a `BLOCKER`. In a microVM run whose image has `/etc/dfirswarm/tools.md` (images/install.py writes it), `toolbox.json` records it as `tools_md` and `SWARM.md` gets a "Programs" paragraph that points at that file inside the VM instead of the table: the image describes itself, and the contract names no program.
- `--quarantine` creates `work/extracted/` and `work/quarantine/`, adds `--noexec` for both to the pane's `fsguard.sh` wrapper (seatbelt `process-exec*` deny on macOS, a `noexec` bind mount on Linux) and sets `SWARM_QUARANTINE=1` in every pane, on which the harness strips execute bits from any file written there after a `bash` or forged-tool call. An interpreter told to read a file (`python3 sample.py`) is not stopped by either — the contract says so and the prompt tells the agents what the directories are for.

### Tool jobs and the store (`job_run`, `job_status`, `catalog_request`, `store/`)

In a microVM run with the job service (the default; `--no-jobs` and host runs have none), the hub runs tool work in throwaway worker VMs (`scripts/job-service.ts`, ADR 0010). The seat's calls are `jobSubmit`, `jobStatus` and `catalogRequest` on its socket; who asks is always the seat. A job is a command, a pack or forged tool with its arguments (checked against its manifest; its script's sha256 against the manifest's), a recipe over one object, or a detect pass. The worker sees what a seat sees, read-only: `inputs/` (no-exec), `store/`, `catalog/`, `tools/`, `tool-output/`, the packs and all of `work/` (`work/extracted/` and `work/quarantine/` no-exec; the record says it is live and may change), and writes only its own `$OUT` (`<sandbox>/.jobs/<id>`); no network unless the job asks for the operator's allowlist (plus PyPI with `--allow-install`, with pip's list kept before and after); no credential, never the board, the inbox, the ledger or the sessions. The hub makes and runs each worker through a short-lived child process (`vm.ts worker-once`), never its own msb SDK, one worker made at a time; a worker msb refused to start before anything ran is removed and made once more, the first error kept as `boot_retry` in `job_finished`. Each step is a line of `store/journal.jsonl` — `job_accepted` (spec, requester with the name and doing it had), `job_started` (declared scope, accessible mounts, `observed: "unknown"`, network, image), `job_finished`, `job_fenced` (only once the maker process is gone and msb neither inspects nor lists the worker), `job_committed` (status, outputs, the manifest's sha256, the logs' sha256), `generation_committed`, `revision_published`, `job_notified`, `job_returned`, `jobs_degraded` and `jobs_recovered` (three jobs in a row ran in no worker, and every seat was told; the next one ran), `note` (an examiner's note added after the run with `evidence-store.ts note`, never an edit), `job_deduplicated` (a second request for the same recipe over the same object, answered with the earlier job; its agent is told when that job is done) — each line's `prev` the sha256 of the line before, the head in `<sandbox>.journal-anchor.json` beside the run. A committed job's output is `store/jobs/<id>/out/` (read-only; links, FIFOs, sockets and devices left out and named in the manifest; every file hard-linked to `store/blobs/<sha256>`), with `manifest.json`, `job.json`, `stdout.log` and `stderr.log`. `job_run` answers in the call when the job is done within its wait (default 12 s); otherwise a post tagged `result` tells the seat. A citation of a job's file is `job:<id>/<path>`. Custody verifies the chain against its anchor and every committed file against its manifest; the package exports the record.

### Names and the per-agent cap (`names.json`, `budget.json` `cap_per_agent_usd`)

`make_tool` answers a near-duplicate before anything is written: same runtime, overlapping parameters and a description made of the same words means the tool already exists, and the refusal names it and its author so the agent can call it instead. Two agents reaching for one capability seconds apart is the common case, and the board announcement always arrives too late for them.

Nobody is given a job. The kickoff prepares the sandbox, the goal and the caps, and stops there: there is no seat, no role and no task list. An agent reads the goal, reads the board, sees what its peers have taken, and calls `name(name, doing)` to say what to call it and what it is taking on. `names.json` holds what each agent said, every post carries its author's name, and the console and the summary show it beside the id. Two agents cannot answer to the same name; an agent may rename itself whenever its work changes, and the board is told.

`--cap-per-agent USD` writes `cap_per_agent_usd` to `budget.json`. On every budget fold the agent's own harness compares its slice against it: over the cap it is steered once (`agent_cap_steer`, a `stop` post from `system` on the board) to post what it has and call `done(reason=agent_cap)`; one grace period later, if it is still running and the swarm is not done, the harness marks it done itself (`agent_cap_stop`) and shuts the session down. The swarm continues.

### Shell writes, forge hints and the sentinel nudge

A change the harness sees across a `bash` call is charged to that call only when the command names the path (the key, its basename or its directory), or when the file is no longer changing when the call ends and is not under another agent's `work/<id>/`: a peer's shell job that is still growing a file, and a peer's own scratch directory, are the peer's business, not a violation of whoever's call overlapped it. Two directories under `work/` are outside the watch altogether: `work/.toolchain/` (the package install area of `--allow-install`) and `work/.tmp/` (the panes' `TMPDIR`, where Pi spills a long `bash` output before the harness moves it to `tool-output/`); they belong to everyone, and on run 6 one venv there was 642 implicit claims and seven violations. A `bash` (or forged-tool) write to a `work/` path nobody holds is no longer only announced: the harness takes the claim for the writer (`claim_file` with `implicit: true`, on the trace and in the lock record) so a peer's tool write to the same file is refused for the lease. A shell write to a path a peer holds is still a `claim_violation`. The same holds for `edit`/`write` under the agent's own `work/<id>/`: the guard takes the lease (`own scratch`, implicit) instead of refusing, so the scratch directory the prompt promises needs no claim from any tool. Every shared file still needs one, and `claim_file` refuses a team agent a lease inside a peer's `work/<id>/`, `work/extracted/<id>/` or `work/quarantine/<id>/`: such a lease would turn the owner's own claim-free write into a conflict in its own directory. The operator and the harness are not peers and can still claim there.

The eighth `bash` call by one agent starting with the same command word (`vol`, `fls`, `python3`, …, measured past `cd … &&` and `VAR=…` prefixes) earns one `forge_hint` event and an `ask` post from `system` to that agent: forge it as a tool.

A `bash` (or `powershell`) command that took a minute or more (`SWARM_REPEAT_HINT_MIN_MS`), ended without error and had its whole output kept under `tool-output/<id>/` is remembered by its text with the spacing collapsed. When the same agent runs the same command again, that result carries one extra paragraph pointing at the first run's kept output: grep or read that file instead. Once per command, a `repeat_hint` event; the harness names no tool and decides nothing about the command.

In a run with tool jobs (the contract has its `## Tool jobs` section), a `bash` command that names `inputs/` and runs for as long is told once, with its result, that a job would have sealed what it made (`job_run`; cited as `job:<id>/<path>`, where a file in an agent's own `work/` is not an object of the run), and that quick looks are fine in the shell. Once per command's first word and three times per agent at most, a `job_hint` event; nothing is refused. A finding recorded without refs whose source or evidence names a `work/` file is told the same by that file's name.

Before every model call the agent's harness takes the caps as it does at a turn's end (`context` hook). A seat the harness has stopped, or one whose swarm the sentinel ended, has its turn aborted and its session shut down before the call goes out, with the same outcome as the stop it replaces and one `budget_precall_stop` line. On the host that is a brake; in a VM it runs under the guest's root and is advisory, and the hub's cap stop and wall clock (or `--model-gateway`) are what hold.

When an agent's `done` creates `done/SWARM_DONE`, or the harness writes the sentinel itself, that process prompts every teammate without a done or dead marker once through `herdr agent prompt` (`sentinel_nudge`, with who was reached and who was missed): an idle pane never makes another tool call, so it would never see the sentinel on its own. `await-done.sh --nudge` does the same from the spawner's side.

The same idleness hurts mid-run: a session that ends its turn after its intro, or after one slice, sits at the prompt until something prompts it. `scripts/idle-nudge.sh` is the watchdog the kickoff starts next to netguard (`idle-nudge.pid`; `--idle-nudge-sec N`, default 180, 0 off): every 30 s it measures each agent's silence from its Pi session files and its last trace event, and an agent past the limit with no marker is prompted to read its inbox and continue its seat, or post its result and wait or call done — at most three times per agent, each one an `idle_nudge` event by `system` on the trace. `swarm.sh stop` kills it; the sentinel ends it.

### Done (`done`, `done/SWARM_DONE`)

`done(reason, output_file, abandon?)`:

1. heals whatever a background process changed under `inputs/` since the last tool call, verifies `inputs/` against its manifest and records `inputs_check` — before the checks, so a check may grep the trace for it,
2. when `done/SWARM_DONE` does not exist yet, runs the finish line: the goal's `## Checks`, read from the operator's registry by `await-done.sh --checks-json`, the same way the console and the report run them. A check that fails is a refusal (`done` event with `ok:false`, a `finish_line` event with `passed`/`total`/`failing`), and the agent is told which check fails and that `done` ends the whole swarm, not its slice. `abandon: true` is the way out for a task that cannot be met: the sentinel is written with its reason prefixed `ABANDONED:`. A runner that cannot answer (no registry, an unreadable goal) does not hold the run: `done` proceeds and the `finish_line` event says why. Run `sb36f` is the reason this exists: a nano agent ended a 25 GB case after four minutes by calling `done` when its own slice was finished, with no report written,
3. writes `done/agents/<id>.done` (frontmatter `by`, `output`, `reason`, `at`),
4. creates `done/SWARM_DONE` with the same frontmatter if it does not exist (idempotent; `created_sentinel` tells you who was first), unless `reason` is `agent_cap` — that is one seat leaving, and the swarm continues,
5. releases every lock the agent owns,
6. logs `done` and `agent_stop` events,
7. returns Pi's official `{ terminate: true }` so the session ends without another LLM turn.

Presence of `done/SWARM_DONE` means stop. `before_agent_start` appends to the system prompt "`done/SWARM_DONE` exists. Call done now" when it does, and `inbox` reports `swarm_done` on every call. The spawner-side clock is the file too: `await-done.sh` exits on it; chat "we're done" is not the clock.

### Budget (`budget`, `budget.json`)

```json
{ "cap_usd": 1, "spent_usd": 0.061282, "tokens": 243160, "calls": 34,
  "wall_clock_minutes": 8, "started_at": "2026-09-16T09:12:00Z",
  "source": "pi.sessionManager.getEntries", "hard_kill": false, "cap_steer_sent": false,
  "metered": true,
  "agents": { "s1a2b00": { "spent_usd": 0.03, "tokens": 120000, "calls": 17,
                           "input": 0, "output": 0, "cache_read": 0, "cache_write": 0 } } }
```

On every `turn_end` and on `session_shutdown` the extension reads `ctx.sessionManager.getEntries()` and sums `Usage` the way Pi's footer and `get_session_stats` do: assistant messages (each counted as a `call`), tool results, compaction and branch summaries. `tokens = input + output + cacheRead + cacheWrite`, `spent_usd = Σ usage.cost.total`. The fold into `agents.<id>` never makes a seat's row smaller: its counters are the seat's whole run, and swarm totals are the sum of rows, all under the table lock. Pi reports a session's own totals, so the fold keys them on `ctx.sessionManager.getSessionId()`: `session_id` is the live session, `sessions` holds each session's last report by id and the row is their sum, and `earlier_sessions` is what the sessions other than the live one spent. A restart adds a session; `/new` then `/resume` back replaces the resumed session's entry. When Pi gives no id, a counter going down marks a new session and the row so far moves into `earlier_sessions`. `/fork` counts the copied prefix in both sessions, which errs high. `compactions`, `compaction_tokens`, `compaction_usd` and `handoffs` are carried forward the same way. A report of all zeros (a session read that failed) leaves the counters as they were. In a microVM run the hub folds a seat's report and takes only the counters and context fields (no `session_id`), and refuses a report smaller than the row it replaces (`usage went backwards`), so a Pi session that restarts inside a VM is not folded until its counters pass the old ones.

`budget.json` is replaced whole (a temp file beside it, then `rename`), so a reader never sees half a record; under Landlock alone, where a pane's rights on it are a rule on its inode, every process of the run writes it in place instead. A missing `budget.json` starts a new one. One that is there and does not parse is read once more (an editor caught mid-save); still unparseable, the fold is refused and the file left alone, never rebuilt from defaults, and the pane logs `budget_unreadable` and posts a `veto` to the board, once per process.

With self-compaction on (the default) the slice also carries `context_ceiling` (the effective ceiling the three lines are fractions of, from `extensions/context-ceiling.ts`), `context_level` (`idle`, `notice`, `warning` or `forced` against it), `context_locked` (true while every tool but `self_compact`, `budget` and `done` is refused), `compactions`, `compaction_tokens` and `compaction_usd` (every compaction Pi recorded in the session, hand-offs and its own fallbacks alike, and what their summary calls cost) and `handoffs` (the cycles completed through `self_compact`). The `budget` tool returns the same numbers to the agent under `context`, with the three thresholds and the tokens left before the compact line.

`metered` says whether that sum means anything. The kickoff sets it `false` when no model on the team bills — a server on this machine or this network, or a `models.json` provider with no `cost` block — because Pi then computes `cost.total` as an exact zero and a session cannot tell a free run from an unmeasured one. Such a team is started with `--cap-tokens N`, recorded as `cap_tokens`, and `over_budget` is `tokens >= cap_tokens` rather than `spent_usd >= cap_usd`; a metered team may carry `cap_tokens` too, as a second brake. The `budget` tool returns `metered` and `remaining_tokens` next to the dollar fields, and the steer on a token cap is `TOKEN_CAP_STEER`. Absent, `metered` means `true`, which is what every run before local models was.

Both caps are enforced the same way, and the clock is swarm-wide
(`stop_steer_at` / `stop_reason` in `budget.json`, claimed by whichever agent
notices first):

1. **Steer.** The agent over the line gets
   `pi.sendUserMessage(…, {deliverAs: "steer"})` telling it to call
   `done(reason=cannot_complete)`, and `system` announces it on the board once
   for the whole swarm. With `--hard-kill` that session also gets
   `ctx.shutdown()`.
2. **Grace.** Two minutes, measured from that one shared instant, so a restart
   or a slow agent does not restart the countdown.
3. **Harness stop.** Still over? The harness writes `done/SWARM_DONE` itself
   with `reason: cap` or `reason: wall_clock`, re-checking under the lock so a
   raised cap cannot be overridden by a stale reading. A kill switch that lives
   only in the prompt is not one.

Caps are checked at `turn_end`, again after each tool result (throttled), and
on a timer — an agent that was steered and then sat in a long shell command
blocks the first two, so without the timer the deadline could pass with nobody
left to notice it. The `budget` tool returns `remaining_usd`, `remaining_minutes`,
`over_budget`, `over_time`, `this_agent`.

### A microVM seat's socket (`<hub dir>/<agent>.sock`)

In a microVM run the protocol calls above travel from the VM to the hub over one Unix socket per seat, as JSON lines. Every connection a VM process opens starts with the seat's token, `{"t":"auth","token":"<SWARM_SEAT_TOKEN>"}` (`seatAuthLine()` in `extensions/protocol.ts`, used by the board client, the held trace connection and the nudge); the link's own `hello` carries the token instead. A good auth line gets no reply, so a client reads its answers as it would without one. Until a connection has shown its seat's token the hub serves nothing on it, not even state; a wrong or missing token gets `{"ok":false,"error":"this socket serves only its seat's VM: …"}`, the connection is closed, and the refusal is a `hub_call` line with `fn:"seat_auth"`. The token is compared in constant time. A run the hub was started without tokens for (an input from before them) asks for none.

No line on a seat's link, in either direction, is larger than one part: 32 KiB of payload (`TRANSFER_PART_BYTES`, `SWARM_TRANSFER_PART_BYTES`), 44,716 bytes on the wire (`WIRE_LINE_MAX`). msb's vsock path from guest to host stops moving on a single write of about 256 KiB, and a connection stalled that way stays open. A larger request is uploaded first: `{"t":"up", …}` parts, each acknowledged before the next, in order, then the call itself with `argsUpload: {id, size, sha256}` in place of `args`; the hub reassembles the args, checks their size and sha256, and runs the call as if they had come inline, with the same request-id dedupe, rate limits and refusals. A larger answer comes back as `{"ok":true,"download":{id,size,sha256}}`, and the client fetches it in `{"t":"down", …}` parts. Trace lines and prompts on the link travel the same way. Per seat the hub holds at most 96 MiB and 4 uploads at once; an upload or a download is dropped when idle for 5 minutes or when its connection closes, and each refusal is a `hub_call` line naming it. A line over the limit is never written: `WireLineTooLarge` on the client, a refusal with `fn:"reply"` on the hub. The client replaces a connection when a call times out or its write queue has not moved in 20 s; calls that change the board resend with their request id, which the hub answers once.

### Event log (`traces/events.jsonl`)

One JSON object per line, same schema for every writer (extension, `reap.sh`, web operator):

```json
{"ts":"2026-09-16T08:24:39.917Z","agent":"s7e5002","tool":"claim_file",
 "args":{"path":"work/hello.txt"},
 "result":{"ok":false,"conflict":true,"path":"work/hello.txt","owner":"s7e5000","expires_at":"2026-09-16T08:27:39.280Z"}}
```

A line written by the trace collector also carries `prev`: the sha256 of the
line before it. `verifyEventChain` walks that chain and the report's custody
section prints the result — intact, not chained (a run without a collector),
or broken at a line number. A tool's result carries what the model received,
whole, as `output` with `output_chars` beside `ok`, because `ok: true` is
not correctness. When that was a slice of something on disk (Pi's `read`,
`grep`, `find`, `ls` and `bash` past their own bounds) the row says so under
`view` (`truncated`, `by`, `total_lines`, `shown_lines`, `total_bytes`,
`shown_bytes`); when the whole output exists only because the harness kept it,
`full_output` names it: `{path, bytes, lines, sha256}` under `tool-output/`
(Pi's `bash` spill moved in from the host's temp directory, a forged tool's
stdout past 64 KB, `full_stderr` for its stderr, `full_text` for a page's
text past what `browser_check` delivers). Nothing a tool produced is dropped
anywhere; the model's own trailer names the same file.

`args` is `summarizeArgs`: every argument whole, whatever its size, numbers and booleans as they are. It once kept 20,000 characters of a string and, before that, 80 with objects dropped in silence — a `bash` line lost the half that said which file it read, and a refused `make_tool` recorded an error about params the record did not hold. An archived row from those days carries the true length under `_truncated`; the console says so on that row, and nothing written today has the key. The collector accepts a line of up to 64 MB and refuses the rest to the spill file (`work/.trace-spill.jsonl`), where it is still a record. Tools that appear:

| `tool` | Writer | `result` highlights |
| --- | --- | --- |
| `agent_start`, `agent_stop` | extension lifecycle (`agent_stop` also after `done`, with `via:"done"`) | `{ok, via, tokens, spent_usd, calls}` |
| `thinking` | `message_end` | `{text}` — the model's reasoning, whole (it was the first 240 characters, then 2,000; the trace keeps everything now) |
| _built-ins_ (`read`, `bash`, `edit`, `write`, `grep`, …) | `tool_result` | `{ok, output, output_chars, view?, full_output?, full_output_error?}`: what the model received, whole; `view` when Pi showed a slice of something on disk; `full_output` = `{path, bytes, lines, sha256}` under `tool-output/` when `bash` spilled past 50 KB (moved in from the host's temp file; the model's trailer names the sandbox path). These used to leave no trace at all, then 2,000 characters |
| `post` | `post` tool | `{id, path, tag}` |
| `inbox` | `inbox` tool | `{swarm_done, seen, n, from[], ids[], remaining, threads}`: every delivered post's sender and id, whole (the lists once stopped at 20), and how many stayed unread under the page bound |
| `wait` | `wait` tool | `{reason: post\|sentinel\|claim_lost\|timeout, waited_ms, n, passed?, from[]?, ids[]?, remaining?}` (the post fields when it woke on a post; `passed`: posts to other agents that did not wake it) |
| `claims` | `claims` tool | `{n}` |
| `thread_open`, `thread_join` | thread tools | `{created, members}` |
| `list_team`, `budget` | tools | `{n}` / `{spent_usd, tokens, calls, over_budget}` |
| `claim_file`, `release_file` | tools | claim result / `{ok, released}` |
| `claim_violation` | write guard, or the bash detector | `{blocked:true, reason, owner?}` for `edit`/`write`; `{detected:true, via:"bash", owner, protected, rev}` for a shell write. Both are announced on the board by `system`; for a shell write the board post comes once per path per minute and says how many repeats the minute held, while every write stays on the trace (a shell loop on s3096 produced 566 posts in fourteen minutes, and every peer read them all). |
| `file_history` | tool, `tool_call`/`tool_result` hooks, bash detector | `{n}` on the tool; `{ok, bytes, sha256}` when a revision is recorded |
| `file_restore` | tool, web operator (`agent:"operator"`, `args.via:"web"`) | `{ok, path, rev, landed_rev}` |
| `file_diff` | `file_diff` tool | `{identical, added, removed}` |
| `finish_line` | `done` tool, before the sentinel | `{ok, total, passed, failing?, note?}`, `args.abandon` |
| `done` | `done` tool | `{reason, output_file, created_sentinel}`, or `{ok:false, reason}` when the finish line refused it |
| `cap_steer`, `wall_steer` | budget fold | `{reason:"cannot_complete", delivered}`, `args.hard_kill` |
| `budget_unreadable` | budget fold, once per process | `{error}`: `budget.json` could not be parsed twice in a row, so the fold was refused and the file left alone; a `veto` post says the same on the board |
| `harness_stop` | budget fold, past the grace period | `{created_sentinel:true}`, `args.reason` = `cap` / `wall_clock` |
| `playwright`, `browser_check` | Playwright tool | `{ok, title, errors, screenshot, text_chars, full_text?}` or `{ok:false, error}`; `full_text` names the whole page text under `tool-output/` when the model received the first 8,000 characters |
| `reap` | `scripts/reap.sh` | `{reaped:true, idle_seconds, last_activity, locks_released}` |
| `reaped` | `protocol.ts reapStalledAgents` (fixture/in-process path) | `{ok, released[], dead_file}` |
| `make_tool` | `make_tool` tool (forging on) | `{ok, forged:true, created, version, sha256}` or `{ok:false, error}` |
| `tool_loaded` | every agent's harness, at a wake-up | `{ok, forged:true}`; `args` = `{name, version, by}` |
| `inputs` | `inputs` tool | `{ok, inputs:false}` or `{ok, inputs:true, n, bytes}` |
| `inputs_guard` | every agent's harness, at session start (inputs present) | `{ok, mode, enforced: kernel\|mode\|none, guard, enforce}`; `mode` is what the pane's wrapper set, `enforced` what a write probe found |
| `inputs_violation` | the harness, after a `bash` or forged-tool call that touched `inputs/`, at a turn-end sweep, inside `done`, or when `edit`/`write` was refused | detected and healed: `{blocked:false, detected:true, via: "bash"\|<forged tool name>\|"sweep"\|"done", healed: restored\|removed\|failed, error?}`; refused at the tool: `{blocked:true, detected:false, via: "edit"\|"write", reason}`; `args` = `{tool, path}` |
| `inputs_check` | the harness, inside `done`, after the heal and before the finish line | `{ok, checked, modified[], missing[], added[]}` — `inputs/` against its manifest (bytes, mode and link count); `ok:false` means a heal failed |
| `tools` | `tools` tool | `{n, loaded}` |
| `record`, `ledger` | ledger tools | `{ok, seq, merged, total, note?}` (args carry `refs` when given) or `{ok:false, reason}`; `{ok, n}` |
| `claim_file` with `args.implicit:true` | the bash detector | the harness took the claim for a shell writer of an unclaimed `work/` path |
| `forge_hint` | the harness, on the eighth `bash` call with the same command word | `{runs}`; `args` = `{command}` |
| `sentinel_nudge` | the process that created the sentinel; `await-done.sh --nudge` | `{reached[], missed[]}`; `args` = `{peers[]}` |
| `idle_nudge` | `scripts/idle-nudge.sh` (`agent:"system"`) | `{ok, nudges}`; `args` = `{agent, idle_seconds}` |
| `operator_action` | `swarm.sh` on a live run (`agent:"system"`): `start`, `stop`, `reap`, `say`, `review`, `export`, `hold`, `release` | `{ok}`; `args` = `{command, argv, os_user, host, via}` (`--env` values and the goal left out). From a shell that is not the kickoff's the line carries no token and is marked unverified. The same action is a line in `runs/operator-audit.jsonl`. |
| `artifact_scripts` | the console (`agent:"operator"`), when the operator opens an HTML artifact with its scripts | `{ok, opened_with_scripts:true}`; `args` = `{path, sha256, via:"web", os_user, remote}` |
| `collector_restarted` | `scripts/hub-supervise.sh` (`agent:"system"`), a microVM run's collector brought back | `{ok}`; `args` = `{by, restart}` |
| `repeat_hint` | the agent's harness, a long command run a second time | `{ok, earlier_ms, full_output}`; `args` = `{command}` (its first word) |
| `job_hint` | the agent's harness, a long command over `inputs/` in a run with tool jobs | `{ok, ms}`; `args` = `{command}` (its first word) |
| `budget_precall_stop` | the agent's harness, before a model call | `{ok, brake: "host" \| "advisory (in the VM; the hub holds the brake)"}`; `args` = `{reason}`. With `agent_stop` `via:"precall"` when the sentinel stood |
| `ledger_superseded` | `record` with `supersedes` | `{ok, by_seq}`; `args` = `{seq}` |
| `history_quota` | the hub, once per seat, when its stored file history reaches `SWARM_HISTORY_QUOTA_MB` | `{ok, used_bytes, quota_bytes}`; `args` = `{agent}`; also a board post to that seat |
| `notify` | the hub, when it calls the run's `--notify` hook | `{ok}`; `args` = `{event}`. The hook's other events (stop, reap, the watchdogs) are called by those scripts; failures go to `traces/notify.log` |
| `hub_call` with `args.fn:"seat_auth"` | the hub, a connection to a seat's socket that did not open with that seat's token | `{ok:false, error}` naming which (no token, a wrong one, a seat given none); repeats collapsed per minute |
| `model_gateway_started`, `model_gateway_refused`, `model_gateway_upstream_error` | the model gateway (`--model-gateway`) | started: `{ok, port, providers, seats}`; refused: `{ok:false, status, message}`, `args` = `{agent, code}`, one line per seat and reason per minute; upstream error: `{ok:false, message}`, `args` = `{agent, provider}` |
| `model_gateway_restarted` | `scripts/hub-supervise.sh`, the gateway brought back on its port | `{ok}`; `args` = `{by, restart, port}` |
| `watch_truncated` | the agent's harness, on the first `bash` call that finds more under `work/` than the watch covers | `{ok}`; `args` = `{max_files, max_depth}`; also an `ask` post from `system` to that agent |
| `extension_error` | the agent's harness, when its own code fails while building the system prompt | `{ok:false, reason}`; also a `veto` post naming the agent (HARNESS FAULT) |
| `agent_cap_steer`, `agent_cap_stop` | the agent's own budget fold, over `cap_per_agent_usd` | `{spent_usd, delivered}` / `{spent_usd, created_sentinel}` |
| `context` | the agent's harness, at every turn end (self-compaction on) | `{ok, tokens, cached, window, ceiling, percent, level, cycle, locked}`: the agent's context time series |
| `compact_config` | the agent's harness, at session start and model change | `{ok, model, window, ceiling, ceiling_reason, notice, warning, compact, cap, clamped, notes[], summary_model, summary_model_source: compact-model\|agent-model, summary_model_problem?}` or `{ok:false, reason, …}`; `args` = the three specs this seat resolved to, whether they were defaults, `matched` (which per-model entry applied to which line) and `compact_model` as the kickoff gave it |
| `compact_notice`, `compact_warning`, `compact_forced` | the agent's harness, once per crossing per cycle | `{ok, tokens, percent, ceiling, threshold, cycle, locked}` |
| `compact_hold` | the agent's harness, a tool call refused by the lock | `{ok:true, tokens, level, cycle, handoff}`; `args` = `{tool}`. Not a failure |
| `compact_note` | `self_compact` tool | `{ok:true, tokens, percent, level, cycle, retry}` when the note was saved; `{ok:false, reason}` when refused; `args` = `{chars}` |
| `compact_start` | the agent's harness, once idle with a note saved | `{ok, tokens, note_chars, cycle, attempt}`; `args` = `{trigger}` |
| `compact_done` | the agent's harness, after any compaction | `{ok, tokens_before, tokens_after, summary_chars, summary_tokens, summary_usd, summary_model, summary_model_source, from_extension, cycle, note_chars}`; `args` = `{reason: manual\|threshold\|overflow, via: self\|pi}` (`pi` is Pi's own recovery with no note; `summary_model` is the model that wrote the summary, `--compact-model` or the agent's own) |
| `compact_failed` | the agent's harness | `{ok:false, reason, fallback?\|retrying?\|lock_released?\|aborted?}`; `args` = `{stage: prompt\|summary\|compaction\|pi, attempt?}` |
| _a forged tool's name_ | the forged tool | `{ok, forged:true, by, version, exit_code, timed_out, truncated, bytes, output, output_chars, full_output?, full_stderr?, error?}`: what the model received, whole, and the file under `tool-output/` holding the whole stream when the model got its first 64 KB (the tool is never killed for printing; it used to be) |

Rows for tool calls carry `duration_ms` (lifecycle, `thinking` and reaper lines have nothing to measure). `thinking` comes from Pi's `message_end` hook — an earlier note here said Pi did not expose it, which was wrong.

### File history (`file_history`, `file_restore`)

Every legal `edit`/`write` copies the file into
`history/<sha256(path)>/<rev>.bin` and appends
`{rev, ts, agent, path, bytes, sha256}` to `index.json`. Revisions are
**content-addressed and deduped against the previous one**: a write that leaves
the bytes unchanged records nothing, so the pre-write and post-write snapshots
around an edit collapse whenever the file was already recorded. The first edit
of a file the harness has never seen still records both the old and the new
bytes — which is what you want, since the old bytes are the only copy. Agents quote the short hash when they sign off on an artifact
("canonical frozen at 2f7b1230, both sign-offs on that hash").

`file_history(path)` lists revisions. `file_diff(path, from, to)` takes
revision numbers, short or full hashes, or `disk`, and defaults to "the newest
recorded revision against what is on disk now" — which is how an agent finds
out whether someone changed a file under it. `file_restore(path, rev)` requires
a live claim held by the caller, records the current bytes first, restores, and
records the restore itself so history stays a truthful log of what the file
looked like and who put it that way. The web app's **Restore** does the same as
agent `operator`. Storage is local copies, not git.

### Registry (`runs/registry.json`)

Written by `swarm.sh`, read by `list`/`status`/`stop`/`reap` and the web app: `{id, label, workspace_id, workspace_ids[], sandbox, n, model, cap_usd, wall_clock_minutes, hard_kill, goal, agents[], started_at, state: prepared|running|stopped, tab_count, split_failures, extra_workspaces, probe_agent?}`. There is no `stopped_at`; the UI derives `done` from the sentinel.
