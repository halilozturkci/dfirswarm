# Tool work runs in worker VMs, is sealed into a store, and the catalogue grows by recipes

A brain — an agent's Pi in its own VM (ADR 0009) — keeps its shell, its
scratch and its read-only view of the evidence. Work that parses evidence,
takes long, or produces something to cite or share runs as a **job**: in a
throwaway **worker VM** of the run's image, made for that job and removed
after. What a job writes is **sealed into the store**, independent of the VM
it ran in, and every step is a line of a **hash-chained journal**. The
**catalogue** of the evidence is written by one authority, the hub's job
service, from **recipes** the packs ship; it grows while the agents work.

Status: accepted, 2026-09-25. Designed by Claude and Codex (GPT-6-Astra)
over three rounds, reviewed independently by a third model (Fable), and
approved by the owner. The flow below is the one the two designers signed;
what was deferred until the first CTF round is listed at the end.

## Context

- Agents parsed evidence in their own VMs, so a tool's output lived where
  the agent ran and was cited by path in the agent's scratch. Nothing said
  which program with which arguments produced it, from which input, in which
  image.
- The kickoff catalogue was a fixed TSK/Volatility script in the harness:
  format knowledge where the owner's rule says it must not be, and silent
  about what it could not read. BelkaCTF #6's 5.1 GB iPhone tar had no
  catalogue and no mention; ten agents listed it with `tar -t` 59 times,
  7.2% of the run's input tokens.
- Nothing in the harness could run work on behalf of an agent, record it,
  and hand the result to another agent.

## Decision

1. **The job service** is a module of the hub, the one writer of shared
   state. A job is a pack or forged tool with its arguments, a shell command,
   a recipe over one object, or a detect pass (which recipes apply to which
   objects).
2. **Durable steps.** A job is `accepted` on disk before any work, then
   `started`, `finished`, `fenced`, `committed`. `fenced` is written only
   when the worker is gone: the process that made it has exited, msb's
   inspect does not know it, and msb's list, read whole and understood, does
   not show it. Until then no byte of its staging directory is read, so
   nothing the worker could still write is sealed. After a crash each job
   resumes from the step it last recorded. A job interrupted by the hub's
   death runs once more only when it had no network.

   The hub makes and runs each worker through a short-lived child process,
   never its own msb SDK. On the third CTF run (Ali Hadi #10) every worker
   after the 64th failed to boot inside the hub's long-lived SDK process
   (msb 0.7.2: "insert run: FOREIGN KEY constraint failed"), while a fresh
   process made one fine. Each failure was recorded as fenced on inspect's
   "not found" alone, and msb listed those workers afterwards. The cause
   inside msb is not known. msb 0.7.2's source has the runtime (another
   process) insert its run by the id of a sandbox row the SDK wrote on its one
   connection: a row the SDK saw and no other process did. 90 workers made
   the same way from one process on an idle host did not fail. The child process, the stricter fence, one
   retry of a boot refused before anything ran, and a notice to every agent
   after three jobs in a row that ran in no worker are containment. The
   run's journal carries an examiner's note that corrects those eight
   fences, appended, not edited.
3. **A worker sees what its brain sees, read-only, and writes only its own
   directory.** It mounts the evidence (no-exec), `store/`, `catalog/`,
   `tools/`, the packs, all of `work/` (every agent's live scratch and the
   shared files; the extracted and quarantined corners no-exec) and
   `tool-output/` read-only. Its own `$OUT` is its only writable place.
   - It gets no network unless the job asks. Asked, it gets the operator's
     allowlist, plus PyPI with `--allow-install`; never the model providers.
   - It has no credential, and nothing of the board, the inbox, the ledger,
     the sessions or the budget.
   - A job with network keeps what pip held before and after it.
   - Those mounts are the job's **accessible** scope, recorded beside the
     scope the agent **declared**.
   - What it actually read is not measured, and the record says **unknown**.
     What the agent was shown is recorded as **returned** pages.

   The first CTF run first gave a worker only its requester's own scratch. A
   job that named a peer's scratch, as its agent could see it, then failed.
   Parity with the brain was agreed with Codex after that run: read-only
   material is still readable and interpretable, and the record says it is
   live. Since 2026-09-27 that is the view of a job that declares nothing;
   one that declares what it reads is given only that ("A job sees what it
   declared", below).
4. **The store.**
   - A committed job's output is `store/jobs/<id>/out/`: links, FIFOs,
     sockets and devices recorded and left out, names kept as bytes, files
     read-only.
   - Every file is hard-linked to `store/blobs/<sha256>`, so the same bytes
     are stored once while every occurrence keeps its own record.
   - A manifest names every file.
   - A failed or timed-out job keeps what it wrote.
   - Agents share work by path: one job materialises (extracts, decrypts,
     unpacks), and any number of later jobs and peers read its output.
5. **The journal** (`store/journal.jsonl`) chains each line to the one
   before it. Each line is fsynced before the anchor beside the run moves.
   Opening the journal keeps a torn tail byte for byte and records the
   repair. An anchor one step behind (a crash between the two writes) is
   told apart from one off the chain. Custody re-checks the chain, the
   anchor and every committed file. The package exports the record.
6. **The catalogue has one authority and many recipes.**
   - A recipe (`recipes/<name>/` in a pack) says whether it applies to an
     object and catalogues it, with its own coverage. Its id in a run is
     `<pack>/<recipe>`, and its entry's sha256 is sealed with the pack.
   - The harness takes only the **census**: every input gets a coverage row.
   - In a microVM run the census plans the recipes, and the job service runs
     them after the agents start: no barrier.
   - Each result is a **generation** (`catalog/gen/<g>/`), and each change is
     a new numbered **revision** (`catalog/revisions/<n>/`, never a renamed
     pointer). Both are announced on the board.
   - An agent asks for more with `catalog_request`. The same recipe over the
     same object is done once for everyone.
   - A forged tool that declares the recipe protocol can be run as an
     **experimental** recipe on request, never by a trigger.
7. **Agents** get `job_run`, `job_status` and `catalog_request`.
   - A short job answers in the call.
   - A longer one is announced by a post tagged `result` when it is done, and
     not while its agent still waits for it.
   - Agents cite a job's output as `job:<id>/<path>`.
   - Roles stay free and change at will. Each job records its requester's
     name and doing at the time: as context, never as authority.

## Consequences

- An agent's evidence work is on the record: which program, with which
  arguments, in which image, from which scope, producing which bytes.
- Sharing is by path under `store/`, so a result outlives the VM and the
  agent that produced it.
- Worker VMs cost a boot per job: about half a second on the Mac with the
  full image, plus 0.2 s for the process that makes it. They count against
  the host's capacity with the seats (`--workers`, default 2; more on a
  large host, below).
- A host run and `--no-jobs` keep the previous behaviour: the kickoff builds
  the catalogue before the agents start, with the same recipes.
- APFS refuses a name that is not UTF-8: on a Mac, a worker cannot write
  one, so such a member name must be renamed on extraction (its bytes kept).

## What the pilot changed

Four runs on the Mac (BelkaCTF #6, Ali Hadi #9, #10 twice), reviewed after
with Fable and Codex, changed these parts of the decision above:

- Workers see what a brain sees (point 3), not the requester's own scratch
  alone.
- Workers are made by a child process and a fence needs msb's list to agree
  (point 2).
- A job with network reaches PyPI when the run allows installs, with pip's
  list kept.
- Workers get 4 GiB on a large host, and 4 of them by default there.
- Stderr is shown whatever the exit.
- A second request for the same recipe is journalled and its agent told.
- Two whole-file reads left the hub's heap.

After the review:

- Findings name what they rest on (`refs` in the ledger's chained core,
  resolved when written and again by custody).
- A goal may check that its answers rest on the ledger
  (`scripts/check-answers.ts`; the goal owns done, ADR 0002, so there is no
  hub gate).
- Imports became a job kind.
- Derived cataloguing became opt-in, by each recipe's own measure, capped; then, after its trial and a second review by Fable and Codex of every run's record, **on by default** (see below).
- Sparse hints point long evidence work and work/ citations at jobs.

## Still deferred, and the gates

- **The tool-mode A/B** (pack tools only through jobs): after the queue
  changes are measured. The deciding numbers are named before it runs:
  findings with refs, tokens, and answers. A pilot exists since 2026-11-01:
  `--pack-tools-as-jobs PACK` takes one pack's tools out of Pi's tool schemas
  and runs them through `job_run`; the comparison itself is still to be run.
- **Result caching**: not built. Identical requests are measured first
  (`job_deduplicated` lines, and identical commands in the journal).
- **Exclusive sessions** (a worker kept for iterative work): not built.
  Chaining through store paths worked in every run, and a worker boots in
  about half a second. Revisit when a case needs a stateful tool.
- **A dedicated catalog agent**: not built. `catalog_request` was used 1,
  1, 0 and 0 times, and no experimental recipe was written. A
  harness-appointed agent would also be a role the harness assigns.

## A job sees what it declared, and a brain's own output a finding cites is sealed (2026-09-27)

Agreed with Fable and Astra over two rounds (D3 and D4 of the plan that also
brought ledger version 4). Point 3 gave every job what its brain sees, and
the record said what it could reach, not what it read. A finding could rest
on a job whose reach was the whole run, and on a file in an agent's own
tool-output/ that the agent could still rewrite.

- **Three scopes, kept apart.** `inputs` left out is `default-all`,
  `["all"]` is `all`, and a list, an empty one too, is `declared`. The spec,
  `job_accepted` and `job_started` keep which; a job accepted before reads
  as `default-all`. A list is resolved when the job is submitted: the
  evidence through `inputs.json` and the set it belongs to (never a flat
  `inputs/`), the store through its sealed manifests, a generation through
  its record, an agent's file by lstat. One entry that does not resolve
  refuses the job, with the reason and what to declare instead. Nothing
  widens a scope to fit it.
- **Segment sets come from the census's record.** The census writes every
  segment set it saw into `catalog/plan.json` (`collections`, planned or
  not), the store journals each as `input_collection`, and a job that
  declares one member is given the rest; inputs.json may list collections of
  its own. The harness knows no format. A hive's transaction logs or a tar's
  own index come with a declared directory, or are named.
- **A view per job.** The hub builds it beside the job's staging directory,
  outside every VM, and mounts it at the run's path, read-only, with its
  evidence no-exec.
  - A declared directory of the evidence, a job's whole output or a
    generation is bound whole, up to eight per job.
  - So is an evidence set, or any directory of it, whose every name in
    inputs.json is in the scope: the common set of one image, or of one
    image's segments, is bound as it is, and scope.json says why. The
    kickoff's recipes and the derived passes take the same rule.
  - Only a scope that covers part of a set is given file by file. A file of
    the evidence is cloned from a descriptor (APFS clonefile, a reflink).
    Where the file system cannot clone, it is linked from the one copy the
    hub makes of it for the run, checked against inputs.json; with no room
    for that copy the job is refused, with the reason.
  - A file of the store is linked, cloned or copied.
  - An agent's file or directory (work/, tool-output/) is cloned or copied
    from a descriptor opened without following a link, the path held to the
    same inode afterwards, and hashed: the job reads that snapshot while the
    live file goes on changing. A link under a declared directory is named
    and left out.
  - Never a hard link to the evidence (its link count and ctime are the
    examiner's, and the inputs guard counts a second name) and never to live
    scratch.
  - `tools/` and the packs are mounted as code, `$OUT` and `/job` writable.
  - No parent directory is mounted that would show a sibling.
- **Recorded apart.** `store/jobs/<id>/scope.<attempt>.json` holds what was
  declared (as said), what it expanded to (each object, what the record says
  of it, and why it is there) and what the worker could reach (each file of
  the view, how it got there, its sha256 and where that sha256 comes from).
  Its sha256 is on `job_started`, and custody holds the manifest to it and
  counts the jobs by scope: "declared scope enforced; reads within it not
  observed".
- **The binding is checked.** `vm.ts` holds every share before msb binds
  it: plain absolute paths, a directory, the view's device and inode as the
  hub built it, a view holding only directories and regular files, and a
  descriptor on each so its inode cannot be reused meanwhile. After the VM
  is made, before anything runs, each is checked again. A substitution in
  between leaves the job not run.
- **An import is a declared job of its source.** The worker copies the
  hub's snapshot, and the record says so (`copied_live: false`).
- **Observation stays open.** What a job read within its scope is not
  observed. A prototype observes opens with fanotify inside the worker
  (`scripts/job-observe.py` and `scripts/job-observe.ts`, on with
  `SWARM_JOB_OBSERVE=fanotify-experimental`, off by default): the job runs
  unprivileged, the collector keys its log, a canary must be seen, and
  dropped events, an unmarked mount or a stall read as partial, a dead
  collector, a forged line or no fanotify as unknown, never complete. It was
  written without booting a VM and is untested in one. Its acceptance tests
  (`tests/job-observe-vm.test.ts`) run on the host's own kernel and
  virtio-fs; until they pass, nothing it says is evidence. LD_PRELOAD, or a
  log the job could write, never is.
- **A brain's own output a finding cites is sealed.** `tool:<seat>/<file>`
  names a whole output the harness kept under tool-output/<seat>/, and
  `trace:<sha256>` one line of the trace.
  - Either is found on the chained trace: the line attributed by the
    collector to that seat, whose result names the file with its sha256, or
    the line with that hash. Either line must be on the chain.
  - The bytes are hashed at once and refused when they differ from the
    trace's digest.
  - An import job over the hub's snapshot, checked against the digest again
    at its start, seals them. `store/imports/<job>/` publishes them with the
    trace provenance (seat, tool, the tool's sha256 where the line records
    one, args, both clocks, the line) and a `brain_output_sealed` line.
  - The record cites `import:<job>/<file>` in its place.
  - What the trace did not capture is not sealed: the work is run again as a
    job. `catalog_search` needs no seal: its `member:` is cited.

## Lanes, room on the host, and the image a job that names none runs in (2026-09-27)

In the three runs after the basic flow (s306463, s2a59b2, s6895a8; three
runs at once on the 128 GiB Mac, the kickoff fitting 3, 2 and 2 workers),
the queue waited p95 16, 106 and 85 s (max 180, 143, 156 s), though 231 of
236, 68 of 69 and 85 of 89 jobs ran in two minutes or less; a worker boots
in about half a second. Replayed over those arrivals and run times, 4
workers put the p95 wait at 0-2 s and 6 at 0 s.

- **More workers where they fit**: unset, 6 on a host with 128 GiB or
  more, 4 with 64 GiB or more, 2 otherwise; the kickoff's capacity check
  still lowers the default to what fits beside the seats.
- **A lane for short jobs**: from 3 workers one is kept for an agent's job
  that declares `timeout_seconds` of 120 or less, and it is stopped there,
  so a long job cannot hold that worker by claiming otherwise. Such a job
  may take any free worker; an agent's other jobs and the kickoff's recipes
  take the rest; the derived catalogue stays the lowest lane. An agent's
  limit of running jobs counts each lane apart, so its quick look does not
  wait behind its own long parse. With 2 workers none is kept: replayed,
  keeping one put the longer jobs' p95 wait at 354-1951 s against
  71-210 s. job_run and SWARM.md ask for the short timeout; only 31 of 236,
  8 of 69 and 8 of 89 jobs declared one, so the lane is only as good as
  that text. `job_started` names the lane, so the wait is measured per lane
  (target: p95 under 10 s).
- **Room on the host**: a worker starts only while the host keeps 15% of
  its memory free beside it (Linux's MemAvailable; macOS's memory-status
  level), asked before each start, since runs share a host and the kickoff
  fitted its workers once. Until then the job waits, said once on the
  journal (`job_waits_for_host`), and its `job_started` carries the wait.
- **The queue counts what it handed a worker**: an agent's limit and the
  derived lane's one-at-a-time counted jobs whose `job_started` line was
  written, and a job picked a moment earlier was not one yet, so one pass
  of the queue could start them all. The derived catalogue then ran two
  recipes at once past a ceiling of one generation (a test that timed out
  on a Linux runner). The count is now of the jobs handed a worker, and one
  pass of the queue runs at a time.
- **A command that names no profile** (61 of 236, 16 of 71, 12 of 90 in
  those runs, all in the image that holds every pack) runs in the smallest
  job image whose own record holds every program it runs: the first word of
  each simple command, and every word naming a program some image holds and
  another does not (a program run through timeout, xargs or `bash -c`).
  Whenever that is not sure — a heredoc, a quoted script, an import, a
  program named by an expansion or a path, a file of the agents' scratch —
  the job keeps the default image; `job_started` says which image and why.
  The records are the images' own: install.py now writes `on_path`, every
  program on the image's PATH, beside `binaries`, the packs' programs. An
  image built before lists only the packs' programs, so a command that
  runs a shell utility keeps the default until the images are rebuilt.

## The agents boot the base; the programs are in the job images (2026-09-26)

The owner's basic flow: each agent's own VM is the base image (a shell,
Python, the tool library), and the forensic programs are in an image per
profile (images/profiles.json). An agent names the image the work needs
(`job_run profile=disk`); a pack tool runs in its pack's image and a recipe
in its pack's (or the one its recipe.json names); a job that names none runs
in the image that holds every pack. The job service writes the run's images
on the journal (`job_images`) before any job runs, records each job's image
and profile in `job_started`, and custody holds every job to the declared
images and each image name to the digests it booted. The kickoff reads each
image's `tools.md` into `images/<profile>/` so an agent in the base knows
which programs an image holds. `--brains-with-packs` keeps the earlier
layout (the agents boot the packs' image).

## The derived catalogue, on by default (2026-09-26)

The BelkaCTF #6 trial showed the payoff and the flaw. The catalogue of the
vault an agent decrypted was used by 5 agents, 14 jobs and 8 of 24 findings,
but derived cataloguing did not make it: its cap of 20 detect passes went on
noise in the first three minutes, 18 of them on files no recipe took,
because a size floor alone decided what was offered. The owner decided it
runs by default. Fable and Codex reviewed every run's record and agreed on
the design:

- **The unit is an object, by content, not a job.** Every file of a tool,
  command or import job (whatever its status) is offered to the derived
  recipes whose `min_bytes`, `suffixes` or `magic` take it, and only to
  those. A sha256 already known (an input, an earlier offer, a catalogued
  object) is skipped, named. A recipe over a store object is deduplicated
  by that content. Recipe and detect outputs are never offered: no
  automatic recursion. Extraction stays the agents', in jobs, and what they
  extract is offered in turn.
- **The lowest lane, a budget that refills, ceilings that say so.**
  - Derived work runs as its own requester, one job at a time, started only
    when no other job waits, the largest objects first.
  - Its budget is 300 worker-seconds each 10 minutes, so early noise cannot
    spend it for good.
  - A run makes at most 50 derived generations and 2 GiB of them: the
    ceilings count what the catalogue costs, not the objects it asked about
    (a replay of the trial showed 477 gzip media blobs spending a 400-object
    ceiling before the decrypted vault came). What waits is named in the
    journal, and a ceiling is told to all. The generations' ceiling is the
    operator's since 2026-10-01 (`--derived-limit N`, `SWARM_DERIVED_LIMIT`,
    recorded as `isolation.jobs.derived_limit`): the Breadcrumbs run reached
    it. It is checked before each pass, so a pass in flight finishes past it
    (that run made 52 against 50); bounding a pass to what is left was not
    done, since what waits stays offered and named either way.
- **Nothing is lost.** A pass's answers are read whatever its status; a pair
  it did not answer is asked once more, then named. Replay rebuilds the
  queue, and recovery reads a committed pass or offers a committed job that
  never was.
- **Partial and readable.** A recipe's partial answer over an encrypted
  container goes to its maker with the recipe's reasons. When a readable
  form (a decrypted volume, within three jobs of lineage) is catalogued
  complete, the two are linked (`generation_related`), not called wrong:
  ciphertext and plaintext are different objects.
- **Discovery and audit.**
  - A complete derived generation is posted to all.
  - `catalog_search which=generations` lists them, with why a partial one is
    partial.
  - Custody holds every revision and generation to the journal and sums the
    derived work.
  - What a worker writes (index.tsv, coverage.json) is read only for files
    its sealed manifest lists.

Deliberately not built: an event bus (the commit is the event), recipe-declared
costs, extraction recipes, and autonomous recursion.

## The kernel's symbol table is in the job image, made by the operator's build (2026-10-01)

A Windows memory image of a CTF run had a kernel (Windows 10, build 19041
family) that neither the Volatility Foundation's 2019 bundle nor JPCERT/CC's
collection holds; in a worker with no network, Volatility's Windows plugins
could not read it. Claude, Fable and Astra agreed the design, and the owner
decided the table is baked into the local memory and `full` images:

- **Pinned input and pinned content, never pinned table bytes.** A pack lists
  the exact kernels (`packs/memory-forensics/requires/symbols.windows.json`):
  PDB name, GUID, age, the PDB's sha256 and size, the converter version
  (`volatility3` 2.28.2, pinned in the pack), and the content hash the
  converted table must have. `pdbconv` writes the time it ran into the table,
  so its bytes differ at every conversion; the content is compared by a
  versioned rule, json-canon/1 (decompress, refuse duplicate keys and
  non-finite numbers, remove `metadata.producer.datetime`, sorted keys,
  ASCII, default separators). The repository holds identifiers and hashes,
  never a Microsoft file.
- **Two steps, the first the operator's act.** `swarm.sh symbols fetch`
  puts each PDB into the host's store (`$DFIRSWARM_HOME/symbols`, by sha256,
  never in a synced folder), from a copy the operator holds (`--from`) or from
  Microsoft's symbol server with every hop bounded; it is refused without
  `--accept-terms` and a name, and the store records who accepted
  Microsoft's terms, when, for which bytes, and whether a person at a
  terminal did (a build takes a process's acceptance only when told to). The image build takes the PDB
  from the store, converts it with no network, checks the content, keeps the
  table where Volatility looks and drops the PDB; a curated PDB or an
  acceptance the store does not have stops the build before Docker. The
  image records the source, the transform, the table and the acceptance.
- **Generic in the harness.** `install.data` gained `commands`, `outputs`
  (with `canonical`), `converter`, `set`, `acquire` and list files expanded
  from a template; the harness knows no PDB. `--symbol-set curated|broad|none`
  chooses, and an omitted set is recorded apart from a failure. CI builds with
  `none` (a pull request) or `broad` (the weekly boot): it never fetches a
  Microsoft PDB and never builds the curated set.
- **A missing table stops the start.** The base pack's `memory-windows`
  recipe, whose detect already asks Volatility offline about each memory
  input, names the kernel whose table the image lacks, and says when its probe
  did not answer (one probe and one generation per input, not two); the census writes what a recipe says is missing to
  `catalog/missing.json`, and a missing symbol table is a BLOCKER at
  `start --check` and at the start unless `--allow-missing-symbols`.
- **Not decided here.** Microsoft's terms grant use for debugging and testing
  your software; whether examining a third party's memory image falls inside
  that is not decided here. Building locally reduces exposure to the sharing
  clause and is not a permission to use.

Deliberately not built: a seat or job that fetches symbols, a socket grant
or adapter for the symbol server, a per-run symbol import as case material,
Linux and macOS tables, and a CI cache of the Foundation's bundle.
