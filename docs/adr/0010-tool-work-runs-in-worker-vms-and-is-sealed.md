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
   inside msb is not known: 90 workers made the same way from one process on
   an idle host did not fail. The child process, the stricter fence, one
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

## Deferred until after the first CTF round (plan v3)

- Imports of a brain's local file (a race-safe design is needed first).
- Derived cataloguing of every committed file (the code exists, off by
  default).
- Structured references in the ledger. Findings without them are accepted;
  custody and the report are to count them.
- The tool-mode A/B (pack tools only through jobs).
- Exclusive sessions (a worker kept for iterative stateful work).
- A dedicated catalog agent: gated on measured demand.
