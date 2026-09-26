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
   live.
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
  the host's capacity with the seats (`--workers`, default 2).
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
  findings with refs, tokens, and answers.
- **Result caching**: not built. Identical requests are measured first
  (`job_deduplicated` lines, and identical commands in the journal).
- **Exclusive sessions** (a worker kept for iterative work): not built.
  Chaining through store paths worked in every run, and a worker boots in
  about half a second. Revisit when a case needs a stateful tool.
- **A dedicated catalog agent**: not built. `catalog_request` was used 1,
  1, 0 and 0 times, and no experimental recipe was written. A
  harness-appointed agent would also be a role the harness assigns.
- **A short-job lane**: after the four-worker default is measured, and only
  with job_run text asking for a declared short timeout. Short jobs queued
  up to p95 189 s behind long ones on the confirmation run.

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
    journal, and a ceiling is told to all.
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
