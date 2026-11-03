# Data protection

Evidence usually holds personal data: names, messages, locations, health or
financial records of people who are not party to the case. This page says
where a run sends that data, where it keeps it, and what the harness leaves
to the operator. It describes the harness; what the law requires of a given
case (under the GDPR or any other law) is the operator's to
establish, and nothing here settles it.

## What leaves the machine, and to whom

- **The model provider of each seat.** An agent's model sees what the agent
  reads: the contract (`SWARM.md`, the goal and the catalog's index in it),
  the board, and the output of every tool it runs, file contents included.
  That is evidence content, sent to the provider's hosts over the provider's
  API. A long output is delivered in part, with the whole kept on disk and
  named, and the agent can read the rest.
- **The summary model.** Self-compaction (on unless `--no-self-compact`)
  hands an agent's context to a model to summarise: the agent's own, or the
  one `--compact-model` names. That provider receives the whole context.
- **Every other allowed host.** netguard's list (host runs) and each VM's
  allowlist (`--isolation microvm`) name where traffic may go: the model
  hosts, `--allow-host` entries such as a symbol server, and the package
  index under `--allow-install`. Anything an agent can send to an allowed
  host can leave, evidence included ([safety.md](safety.md)).
- **With `--model-gateway`,** a fronted provider's calls leave through one
  process on the host rather than from each VM; what the provider receives
  is the same. The gateway writes no request or response body: its log
  (`traces/model-gateway.jsonl`) holds seats, models, statuses, token
  counts, costs and byte counts.
- **With `--network dynamic`,** a lookup an agent asks for is sent by the
  fetch service on the host to the adapter's service: rdap.org and the
  registries it refers to, crt.sh, NVD, CISA, CIRCL, RIPEstat, Nominatim,
  Overpass, YouTube's oEmbed, the host of an evidence URL for a HEAD, and
  VirusTotal where the operator configured a key ([ADR
  0012](adr/0012-a-dynamic-network-decided-by-rules-and-made-on-the-host.md)).
  What leaves is the adapter's typed values (a domain, an address, a hash, a
  coordinate, a place name) and nothing else of the case. Each adapter
  declares the class of case data it carries, and the case policy says which
  classes may leave: `standard` lets hashes and public indicators go to
  passive reference services and nothing else, `internal` nothing at all,
  and personal data or an internal name leaves under no preset unless the
  operator's case policy says so. Even a hash or a coordinate tells a third
  party what the case is interested in; the policy is where the operator
  decides that. A value the run marked sensitive, and anything that looks
  like a credential, never leaves. Every request, decision and answer is
  kept in the run (`network/`, `store/net/`), so the record of a run says
  what was sent where.
- **The operator's `--notify` targets.** Every event leaves the host as an
  envelope of identifiers only, whatever the event and whatever the target:
  the event, the run's id, the time, an event id, and of its details only
  what is an identifier (a request's `R-n`, its kind, a lead's or question's
  id, an urgency, a state), a number or a yes/no; a list becomes its count.
  No file name, summary, command output or request text is in it: the
  details stay in the run (`traces/notify-events.jsonl`, under the event
  id), where the operator reads them. The operator's own command gets that
  envelope on stdin; a typed target (`desktop:`, `ntfy:<topic>`, which goes
  through ntfy.sh unless the operator names a server of their own,
  `mailto:<address>`, one mailbox, never an option to the mail program)
  receives the event and the run's id alone
  ([ADR 0014](adr/0014-the-case-contract-says-what-comes-in-and-what-is-asked.md)).
  Where a target sends them is the operator's choice.
- **Nothing to the harness's authors.** The harness sends no telemetry. Pi's
  own startup calls to `pi.dev` are not on netguard's list or a VM's
  allowlist and are refused; on a host run with `--no-netguard` they go
  out. Pulling an image or installing a pack reaches its registry and
  carries no case data.

The report names each seat's model and the hosts it was served from, and
the summary model with them, so the record of a run says who received its
content. `--local-only` keeps every model on this machine or this network
and narrows netguard to those endpoints; the evidence then reaches no cloud
model. [Credentials and teams](credentials-and-teams.md) covers local
models.

## What stays on the machine, and where

- **The run directory** (under `runs/` in the checkout unless `SWARM_RUNS_DIR`
  or `--sandbox` says otherwise): a copied `--inputs` with its pristine
  clone, `work/` with `work/extracted/` and `work/quarantine/`,
  `tool-output/` (every tool's whole output), `.pi-sessions/` (every agent's
  whole conversation with its model), the trace, the board, the ledger and
  `catalog/`. All of it can hold evidence content.
- **Beside the run directory:** `<sandbox>.custody-anchor.json`, and under
  `--isolation microvm` each VM's kept disk and logs in
  `<sandbox>.vm-snapshots/` (a link to `--vm-snapshot-dir` when that is
  given). A kept disk holds whatever the agent left in its VM. Under
  `--network dynamic`, `<sandbox>.netraw/` holds what the fetch service
  received and delivered to no seat: a filtered adapter's whole response and
  headers (a video's author, say, when only its title was delivered), a
  transfer stopped or broken off, an answer withheld because its grant
  ended. It is in no VM's reach, is packaged under `network/raw/`, and can
  hold personal data.
- **What was asked of the operator, and what came in later.** The
  operator requests (`requests/requests.jsonl`, rendered to
  `operator-requests.jsonl`) hold what each request asked in the agents'
  words, which can name the case's subjects. Evidence added after the
  kickoff (`swarm.sh evidence add`) and material the operator supplied
  (`swarm.sh material add`, `swarm.sh tool-supply` for a program, a question's attachment) are copied into the
  store (`store/imports/ev-<n>/`, `mat-<n>/`) and are evidence content like
  `inputs/`; each record says who supplied it, when and from where. Material
  added with `--sensitive` is held to the same rule as a sensitive entry: no
  name, label or question may carry what it says.
- **The package** (`swarm.sh package <id>` → `<sandbox>/package/`): the
  report, the summary, everything under `work/` except `work/extracted/` and
  `work/quarantine/`, the ledger, the trace and the board, `court-set.json`
  and this run's lines of the operator's record. It is what gets handed
  over, and it carries evidence content too. `--sign` adds the examiner's
  signature and public key. `--redact` takes out what the sensitive entries
  say and withholds the outputs of jobs whose output is sensitive (run with
  `secret_output`, or made from such an output) whole, wherever their bytes
  sit, naming each by a keyed id (never a hash a low-entropy value could be
  brute-forced from; the key and the real digests are in a private sidecar
  kept outside the hand-over), then scans every file it hands over — and the
  filenames — for what should not be there; without `--redact`, `HYGIENE.json`
  names what in the package is sensitive.
  `--with-sessions` adds `.pi-sessions/` for an **internal handover** only:
  regular files copied at a cutoff, every recorded sensitive value (a
  sensitive entry's words, a sensitive output's text, its digest) replaced by
  its keyed id, one lossless archive and a manifest of each file's size and
  sha256, checked by `verify`. It is refused together with `--redact`, so a
  disclosure copy never carries sessions. A session file larger than 1 GiB is
  not masked in one piece, and the component carries nothing and says so. Masking removes the recorded
  sensitive values, not the evidence text the models read: a session still
  holds what they saw of the case, and the archive is to be treated as
  evidence content. The key and the id map are in a private sidecar
  (`<dir>.sessions.private.json`) outside the package.
  What a package may carry under GDPR or similar laws is the operator's to
  decide; these are the means.
- **Exports** (`swarm.sh export`, under `<sandbox>/exports/` by default):
  the ledger as CSV, values in full.
- **Who ran it.** `runs/operator-audit.jsonl`, beside the registry, has a
  line for each `start`, `stop`, `reap`, `say`, `package`, `report`,
  `tools`, `review`, `export`, `hold`, `release`, `purge` and `verify`: the
  time, the examiner's OS user name and host, and the arguments. The
  examiner's review (`runs/reviews/<id>.jsonl`) holds the examiner's name
  and notes on each entry. The trace carries the same for a live run (`operator_action`,
  and `artifact_scripts` with the console client's address), so the
  package carries it too. The registry records the host's time zone
  (`host_clock`) and what produced the run (`provenance`). These name the
  examiners, not the case's subjects, and are personal data all the same.
- **Credentials:** provider logins in Pi's own store (`~/.pi/agent/`), pack
  secrets in `~/.dfirswarm/secrets/<id>.env` (mode 0600). Under
  `--isolation microvm`, msb also keeps a live VM's configuration, the
  secrets' values included, in its database (`~/.microsandbox/db`); the
  kickoff makes `~/.microsandbox` its user's alone, a finish or reap that
  removed VMs clears their leftover bytes when the host has `sqlite3`, and
  `stop` warns about any it could not clear.
- **The console** binds `127.0.0.1`. Started with `--host 0.0.0.0`, anyone who
  can reach it can read the board, the trace and every `work/` file
  ([SECURITY.md](../SECURITY.md)).

The harness deletes none of this on its own. `swarm.sh purge <id> --yes`
deletes a finished run's directory, its kept VM disks, its hub directory and
its `<sandbox>.netraw/` when the operator asks, keeps the anchor and the review (hashes,
verdicts and notes, not material), and leaves a destruction record on the
operator's record; a held run (`swarm.sh hold`) is refused. Purge removes
files the ordinary way and knows nothing of copies elsewhere: a package
handed on, a synced folder, a backup. The kickoff records whether the
volume that holds the runs is encrypted at rest (`disk_encryption`) and
warns when it is not. A run directory inside a synced folder
(Dropbox, iCloud Drive, OneDrive, Google Drive) is uploaded by that folder's
client. The kickoff refuses to put a copy of the evidence or the VMs' kept
disks in a folder it recognises as synced unless `--allow-synced-folder`
(or a `.dfirswarm-allow-synced` file the operator placed in that folder)
says they may go, and warns about a run directory there for what the agents
derive.

## What the operator decides

- **The case policy** (`--policy`, or `policy:` in the goal's metadata
  block): which classes of case data may leave the run and to what kind of
  service, whether the subject's infrastructure may be contacted, and the
  legal text the run records beside it (`legal:`, for instance "GDPR or
  similar laws" and the scope of the authority the examination runs under)
  and what the operator knows of the providers' retention
  (`provider_retention:`), whether evidence may arrive while the run goes on
  (`more_evidence:`) and what supplied or captured material may be used for
  (`material_use:`). The harness records these, anchors and seals them, and
  enforces the network part and the material use; it does not decide what
  the law of a case requires.

- **Whether the evidence may be processed this way at all**, and on what
  basis: who the controller is, and what the engagement or the law allows.
- **Which providers may receive it.** Each provider's terms for API data:
  whether prompts are retained or used for training, where they are
  processed, and whether a data processing agreement covers the case. A
  transfer to a provider abroad has its own conditions under the GDPR and
  similar laws. Where no cloud provider is acceptable, run `--local-only`.
- **How much evidence to hand the run.** `--inputs DIR` hands the run what
  is in `DIR`; give it what the question needs rather than the whole
  acquisition when the rest is not needed.
- **Who can read the runs:** the account on the host, anyone who can reach
  the console, anyone with the synced folder or the backup the runs land in.
- **How long each run, its snapshots and its packages are kept**, and when
  they are destroyed, under the case's retention rules and any legal hold
  ([safety.md](safety.md), "What a run leaves on disk"). Deleting a run
  means the run directory, `<sandbox>.vm-snapshots/` or the directory it
  points to, the anchor beside it, and every copy of the package that was
  handed on.
- **Protection at rest.** Deleting a file does not overwrite what it held,
  and on an SSD nothing the harness does could guarantee that it did.
  Full-disk encryption on the host (FileVault, LUKS) is what protects a run
  on a lost or retired disk.
- **A leak.** A run directory, a package or a provider key that reaches the
  wrong hands can be a personal data breach; notifying it, and to whom, is
  the controller's duty under the GDPR and similar laws.
