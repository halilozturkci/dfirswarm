# Safety

> Forged tools (`--allow-tool-forging`, off by default) are agent-written scripts that run as subprocesses in the sandbox with exactly the containment described here for `bash` — no more. Their own rules are in [forged-tools.md](forged-tools.md).

The product requirements inverted from the incident write-up, and exactly what the harness enforces, detects, and cannot contain. Read with [SECURITY.md](../SECURITY.md).


These are product requirements, inverted from what OpenAI's [Hugging Face incident write-up](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) describes: a hidden channel, goals adopted from peers, no safe exit from impossible tasks, a grader to game, and no harness or monitor on the evaluation. The mapping is in [Why: the incident, inverted](why-the-incident-inverted.md); the mechanisms are below.

Every agent runs in its own microVM unless the run says `--isolation host`.
What a VM holds is the bullet "In a microVM (the default)" below. The other
mechanisms are a host run's (`--isolation host`, unisolated): every agent is
a process on this machine, and they are all that holds it. A host that
cannot boot the VMs is refused with what it lacks; the kickoff never falls
back to a host run on its own.

- **Isolated cwd, and a write allowlist.** Every agent's cwd is `runs/<id>/`.
  Claim keys, history and artifact serving all reject paths that escape it, and
  `edit` / `write` outside it are blocked. `bash` still cannot be stopped
  mid-command — but on macOS the pane's seatbelt profile now denies
  `file-write*` everywhere and allows it back only under the run and Pi's own
  agent directory (`--no-write-guard` turns that off). A shell command can no
  longer write the examiner's home, another case's sandbox, or
  `runs/registry.json` — the file `await-done.sh` reads the definition of done
  from and then `eval`s. `tests/write-guard.test.sh` asserts each of those. On
  a host without seatbelt the guard cannot apply, the kickoff says so on
  stderr, and the run record carries `write_guard`.
  **What is still writable outside the run**: Pi's own agent directory, because
  a provider token refresh has to land somewhere and a run that cannot refresh
  dies at the hour mark. Its `extensions/` is denied — that would be code
  loading in every later Pi run — but `models.json`, `settings.json`,
  `auth.json` and `sessions/` in that directory are not. Reads are not
  restricted at all: a pane can still read anything this user can. **This is
  still not a machine to run on casually; a spare box or a dedicated user
  account is still the right answer for a case that matters.**
- **What the bash detector covers.** Every shell call is bracketed by a hash of
  everything under `work/`, the four harness files an agent should never touch
  (`SWARM.md`, `team.json`, `layout.json`, the sentinel), every live claim, and
  the spend/time caps. It does **not** byte-watch `threads/`, `locks/`,
  `traces/`, `inbox/` or `history/`: those change constantly under normal
  operation, so comparing them would blame whoever happened to be running a
  shell at the time. Claims on them are refused and the write guard blocks
  them; a shell write to one is a known blind spot — except `traces/`, which a
  run with a trace collector gives the panes read-only while its lines go to a
  process outside the profile, each chained to the last. The watch also covers at
  most 500 files under `work/`; when a run outgrows that, the harness says so
  once to the agent whose shell call found it (`watch_truncated`), because a
  write it can no longer see is a promise it can no longer keep.
- **Peer mail is data.** The system prompt states that only the kickoff, the
  contract and the harness are authority. The harness enforces the parts that
  matter (claims, protected paths, done, both caps) rather than hoping the
  prompt holds — and when it does act, it says so on the board as `system`, so
  the enforcement is visible to every agent rather than buried in a log.
- **The harness owns its own files.** `done/`, `locks/`, `traces/`, `history/`,
  `inbox/`, `threads/`, `tools/`, `inputs/`, `ledger/`, `catalog/`, `SWARM.md`,
  `team.json`, `budget.json`, `names.json` and `layout.json`, custody's
  verdicts (`custody.json` and the earlier ones beside it), `artifacts.json`
  and the host's trace spill `work/.trace-spill.jsonl`
  cannot be claimed or written by an agent; a shell write to one is detected and
  announced. The sentinel is written only by `done` or by the harness itself.
  Custody itself reads and writes nothing through a link planted at one of
  its names: the previous verdict is set aside first, and each file it
  writes goes to a fresh file renamed into place.
- **Inputs are copies, read-only at three depths.** `--inputs DIR` copies the
  directory into `inputs/` (the original is never touched; the evidence's
  own links are copied as links and never followed, so none names a file of
  this machine), strips the write bits, and keeps a pristine clone. The tool
  guard refuses it, a shell write is healed and announced, and on macOS
  (`sandbox-exec`) or Linux (a read-only bind in a mount namespace, Landlock
  beneath it, or Landlock alone where the host allows no namespaces) the pane
  runs with it read-only at the kernel; each pane records what it actually got
  as `inputs_guard`. `--inputs-bind` skips the copy on a host with a kernel
  guard: `inputs/` links to the source and the kernel holds the source itself
  read-only. Reading is not restricted. [inputs.md](inputs.md), ADR 0005.
- **The same guards on Linux, by a different mechanism.** The write guard is
  Landlock (kernel 5.13+) with a user namespace over it where the host allows
  one: a read-only root, this run and Pi's agent directory bound back writable,
  Herdr's socket and `--no-read` paths hidden under an empty tmpfs, the panes
  in their own pid namespace. Where namespaces are refused (Docker's default
  seccomp, Ubuntu's AppArmor restriction) Landlock alone holds the write
  allowlist and the record says what could not be masked. Attribution is by
  process ancestry there, not by token: `/proc/<pid>/environ` is readable
  across panes of one uid (measured), so a gate in front of the collector
  reads the sender's pid from the kernel (`SO_PEERCRED`) and walks up to the
  pane. What each host could enforce is probed at kickoff and recorded as
  `host_caps`; the custody section of the report reads it back.
  [linux-plan.md](linux-plan.md) has the measurements, and
  [linux-server.md](linux-server.md) is what an operator has to set up.
- **The record says what the panes measured, not what the host could give.**
  Every agent probes its own guard when its session starts, and the kickoff
  reads those probes back into the record as `write_guard_measured`
  (`kernel`, `partial`, `none`, `unmeasured`), with a WARN and a custody row
  when it is not `kernel`. A guard that never reached a pane — the pane's
  login shell was neither zsh nor bash, the multiplexer started the agent
  elsewhere — used to be invisible in a run that said it was guarded. On a
  Linux host the pane's shell must be zsh or bash for the hook to run at
  all, and the kickoff refuses to start otherwise.
- **The finish line is checked, not asserted.** `await-done.sh` runs the goal's
  own `## Checks` and reads them from the run registry, outside the sandbox — a
  swarm that could rewrite its contract could otherwise certify itself.
- **Netguard is on by default.** `herdr agent start --kind pi` cannot take a
  wrapper argv, so kickoff does two things: writes `<sandbox>/bin/pi` that execs
  `netguard.sh --allow <provider host> -- <real pi>` and prepends that directory
  to `PATH`, and starts a persistent proxy-only `netguard.sh` sidecar on
  its own `127.0.0.1:<port>` (the first free one from 43178 up, so two swarms
  never share a proxy) with `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` set on every
  pane so the filter holds even if Herdr launches `pi` by absolute path. The
  allowlist is netguard's default provider hosts plus the one the selected
  model needs — `--allow` adds, it does not replace; `--only` replaces. An
  entry with no port is port 443 alone; a local endpoint is allowlisted as
  `host:port`, because a bare `127.0.0.1` would admit a CONNECT to every
  port on the machine, this console and an SSH daemon included.
  Verified live: agent `bash curl https://example.com/` → `CONNECT tunnel
  failed, response 403`, provider `ALLOW`, swarm still reached `SWARM_DONE`.
  `--no-netguard` opts out. Caveats:
  - **Node-built clients.** Node's global `fetch` honours `HTTPS_PROXY` only with `NODE_USE_ENV_PROXY=1` on Node ≥ 22.21 / 24 (netguard exports it). On older Node the proxy is ignored; inside a network namespace that fails **closed** (no egress at all), never open. The `pi.dev/install.sh` binary is Bun-compiled and Bun's `fetch` honours the variables natively.
  - **Docker.** The default seccomp profile blocks `unshare` for unprivileged containers; `netguard.sh` prints a WARNING and falls back to `--mode proxy-only`, which is **advisory**: a process that ignores the proxy variables has full egress.
  - **macOS: UNKNOWN.** No `unshare`; only proxy-only runs. A `pf` ruleset would be the enforced equivalent and needs root.
  - The shim wraps `pi` in `netns` mode where available, so on Linux hosts outside Docker both layers apply.
- **The provider key stays in Pi's store.** `swarm.sh` passes no credential to
  the panes; `pi /login` once and Pi reads its own. `--key-from-env` restores
  the old env-var path for cloud and CI hosts with no persistent home, and says
  in `--help` that `ps` can see it. No file in the repo or sandbox ever contains
  a key; `.gitignore` excludes `runs/` anyway. See
  [ADR 0003](adr/0003-the-provider-key-comes-from-pis-own-store.md) and
  [Credentials](credentials-and-teams.md).
- **Cost and time caps.** `--cap-usd` is mandatory. Spend is measured from Pi's
  own session usage, not estimated. At either cap the agents are steered to
  `done cannot_complete`, and if the swarm is still over one grace period later
  the harness writes the sentinel itself: each pane's own extension, and
  from outside every pane the idle watchdog on the host (for a microVM run,
  the hub), so a swarm whose every pane is wedged is still stopped. With
  `--idle-nudge-sec 0` a host run has no watchdog and only its panes.
  `--hard-kill` additionally shuts the steered session down. Kickoff allows
  N=1–30 and warns above 10.
- **No root on the host, ever, and installing is not root.** (Under
  `--isolation microvm` the agent is root *inside its own VM*, which holds
  nothing of the host but what is mounted, read-only but for the seat's own
  directories; see the next point.) The panes are ordinary
  processes owned by the examiner: the "sandbox" is a directory plus a kernel
  guard over `inputs/`, a no-exec rule over what is carved out of it, and an
  egress allowlist. There is no `sudo`, nothing mounts, and nothing asks for
  either — which is the guarantee that makes read-only evidence mean anything
  on this machine. A host run started as root is refused unless
  `--allow-root`: root is not bound by the read-only modes a host run relies
  on. A microVM run started as root is warned about. A case that needs a library the host does not have gets
  `--allow-install` instead: `pypi.org` and `files.pythonhosted.org` join the
  allowlist, `PYTHONUSERBASE` points at `work/.toolchain/` inside the sandbox,
  and what a run installs goes when the run goes. It also sets
  `PIP_BREAK_SYSTEM_PACKAGES=1`, so pip installs there on a system whose
  Python is marked externally managed (PEP 668); PEP 668 then no longer
  refuses a pip run without `--user` either, and what keeps that out of the
  system's Python is the write guard (with `--no-write-guard`, nothing). It
  is off by default, the contract tells the agents the rule when it is on,
  and the ledger is where they record what they installed. Homebrew and the
  system package managers stay out: they write outside the sandbox, to a
  machine the next case also has to trust.

  What that leaves unreachable on the host is anything that genuinely needs
  root — a FUSE mount, a loop device, attaching a volume. The place for that
  is not the examiner's machine. Under `--isolation microvm` it is what each
  agent's VM is: root confined to a disposable VM, with the evidence mounted
  read-only; whether FUSE or a loop device exists there is what the VM's
  probe records (`vm/<id>.json`, `probe.fuse`, `probe.loop`). A
  run that needs to *read* an
  encrypted or virtual volume usually does not need root at all: libbde,
  libvhdi, libluksde and pytsk3 read them in place, and the `crypto` toolbox
  set now names them so a kickoff finds out before the run rather than at
  minute forty.

- **In a microVM (the default, `--isolation microvm`), the agent is inside a
  VM and the guards are the host's.** Measured, and held by `tests/vm-integration.test.ts` on a KVM
  runner: guest root cannot change the run's floor, the evidence or the trace
  by writing, remounting (its kernel flips the flag; the host still refuses
  every write) or unmounting a writable hole; a VM reaches its allowed hosts
  and nothing else, by name or by address; a secret is only a placeholder in
  the guest; two VMs posting at once through the hub lose nothing; a seat
  writes only its own `work/<id>/`, and its extracted material sits on a
  no-exec mount.
  What stays true about a VM, said plainly:
  - A peer's published file can take five seconds to look current in another
    VM (a claim on such a file waits that out; a plain read does not). A
    peer's `work/extracted/<id>/` is read directly, not published, and may be
    read while the peer is still writing it.
  - The guest's TLS is intercepted whenever a secret is bound, on 443 and on
    every port a secret travels on. The allowed host names that receive no
    secret keep their own TLS end to end. Intercepted as well: an allowed
    suffix that covers a secret's host, an `--allow-host` entry given as an
    address or a CIDR block (msb's bypass takes names only), and under
    `--no-netguard` every public host on those ports, which the host's msb
    decrypts. A client with its own trust store (Chromium's NSS store, Java's
    keystore) fails on an intercepted connection. [usage.md](usage.md#netcheck)
    lists the cases.
  - Root in the guest can flip a read-only share's flag (the host still
    refuses the write) and can unmount its own holes or the floor; what is
    then under those paths is the VM's own disk, never the host's. The no-exec
    on `work/extracted/` and `work/quarantine/` is a mount flag in the guest:
    both directories are mounted whole, read-only and no-exec, with the seat's
    own corner writable and no-exec on top, so a peer's carved material is
    no-exec in every VM too. It stops an agent running carved material by
    mistake, not a root that means to. The finish line, custody and the
    report are decided on the host, never from what a VM reads.
  - Inside a VM the extension's refusals are the agent's own code under the
    guest's root: tool refusals, claim-before-write, the self-compaction lock,
    the per-seat cap steer and the budget check before each model call are
    advisory there. What holds is what the hub, the mounts, msb and, when it
    is on, the model gateway enforce. And every process in the VM speaks to
    the hub as that seat: a forged tool, a parser over hostile content, a
    carved binary the guest's root runs. A harness post sent from a VM
    reaches peers as `from: "system via <seat>"`, that seat's word.
  - Each seat's socket on the hub serves only its own VM. The kickoff makes a
    token per seat (`SWARM_SEAT_TOKEN` in that VM's environment); every
    connection opens with it or is refused and named on the trace
    (`seat_auth`), so a process outside the VM, a host-mode pane on a host
    that cannot seal a socket included, cannot speak to the hub as a seat.
    Inside the VM every process has the token. It rests in the hub
    directory (0600, 0700, mounted by no VM), in the VM's environment and in
    msb's database while the VM lives; never in the trace, the registry, a
    VM record or a package; and it goes with the hub directory.
  - The hub bounds what one seat can ask of it: 16 connections, 160 MB held
    at once (lines not yet whole, lines waiting, calls queued or running;
    past it the seat's connections pause), 8 MB for a call that carries no
    file, and a pace for posts, ledger records and `done`. A seat can still
    fill the host's disk through its own writable directories, which have
    no quota.
  - A placeholder is still a capability at the host it is bound to: an API
    key reaches every endpoint there that the key may use (files, batches,
    fine-tuning, not only inference), and a subscription token is the
    operator's account there, which is why a subscription needs
    `--allow-oauth-in-vm`. A pack's secret is in the environment of the whole
    VM, so any process in it, an agent's shell included, can use it at the
    pack's hosts; the value itself never enters the VM.
  - Spend is what each seat reports (it may only grow); the host enforces the
    wall clock and each VM's `maxDuration` by itself. With `--model-gateway`,
    for the providers it fronts, one process on the host holds the key (in
    its memory; never in a VM, a file or the trace), meters each call from
    the provider's own answer, and refuses a stopped seat's call at once and
    a call past a cap or the wall clock three minutes after it was crossed.
    The VM holds a seat token that is worth nothing off this host and
    reaches no provider host for that provider. Subscriptions, Bedrock,
    Vertex, Google, Mistral, OpenRouter, Fireworks, Azure and local models
    are not fronted and keep the placeholder path; the kickoff names each.
    [model-gateway.md](model-gateway.md).
  - An allowed host is a way out as well as in: a `*.blob.core.windows.net`
    rule (Volatility's symbols) reaches any account's storage there. A local
    model's port, reached through msb's host gateway, is the whole API of
    that server, not only inference: Ollama's `/api/pull`, `/api/create` and
    `/api/delete` included.
  - msb's strict mode is not enabled: a host-name rule admits the addresses
    that name resolves to, and msb does not check that the connection's TLS
    server name or HTTP `Host` is that name. A service behind a shared front
    may be reachable through an allowed name.
  - msb, which holds every credential for the run, is not itself caged.
    While a VM lives, msb also keeps its configuration, the secrets' values
    included, in its own database on the host's disk
    (`~/.microsandbox/db`). The kickoff makes `~/.microsandbox` its user's
    alone, and a finish or reap that removed VMs rewrites that database
    without the removed VMs' leftover bytes. That needs `sqlite3` on the
    host; an operator's `stop` warns when it could not.
  - What a guest prints reaches the host's terminal through Herdr, escape
    sequences included (a clipboard write, a title change).
  - Each kept VM disk holds what the agent left on it — extracted material,
    its /tmp — and is evidence-bearing: keep or destroy it with the case
    (below).

  The host resolves the credentials at kickoff, so a subscription token must
  outlive the run (`--min-expiry` asks Pi for one that does). No VM can
  refresh a token, so one revoked at the provider mid-run ends every seat
  that uses it.
  [ADR 0009](adr/0009-agents-live-in-microvms.md).
- **What leaves with the package, and how a recipient checks it.**
  `swarm.sh package <id> --sign` signs the package's `MANIFEST.txt` with the
  examiner's ssh key (namespace `dfirswarm-package`) and puts the signature,
  the public key and who signed beside it. `swarm.sh verify` re-hashes every
  file against the manifest (none missing, changed or added) and checks the
  signature against an allowed-signers file. A good signature proves that
  key signed that manifest and nothing in the package changed since; that
  the key is the examiner's is for the allowed-signers file to say. The
  ledger export (`swarm.sh export`) puts a leading apostrophe on a text cell
  a spreadsheet would run as a formula.
- **`--notify` runs the operator's own command.** It gets each event's
  details (run id, state, counts and paths; no evidence) on stdin, as the
  operator, detached and for at most 30 seconds. The command is kept outside
  the run (`runs/notify/<id>.cmd`, 0600) and runs only when that file is a
  regular file of the operator's; the registry records only that there is
  one, and the operator's record shows its length, not its text, since a
  webhook URL can carry a token.
- **What a run leaves on disk, and who keeps it.** Everything a run derives
  from the evidence stays on this machine until the operator removes it: the
  run directory (`work/` with `work/extracted/` and `work/quarantine/`,
  `tool-output/`, `.pi-sessions/`, the trace, the ledger, `catalog/`,
  `package/`, and with a copied `--inputs` the copy and its pristine clone),
  and under `--isolation microvm` each VM's kept disk and logs beside it, in
  `<sandbox>.vm-snapshots/<id>.msb` and `<id>.logs`. The harness deletes none
  of it. [data-protection.md](data-protection.md) says what of it can be
  personal data, what leaves the machine, and what the operator decides.
  - **Minimisation on the way out.** An entry an agent marks `sensitive` (a
    credential, a key, personal data) and what it cites stay out of a package
    made with `package --redact` and an export made with `export --redact`:
    the chained records keep their chains by each redacted line's own hash,
    and `REDACTIONS.txt` lists every change with the hashes before and after,
    so the owner of the original can match it. What GDPR or similar laws ask
    of a hand-over beyond that is the operator's to decide.
  - **Retention and legal hold.** Keep or destroy a run with its case, under
    the case's retention rules and any legal hold, and not before custody and
    the package are taken. `swarm.sh hold <id> [--reason TEXT]` keeps a run
    from `purge`, from a new run in its sandbox and from the VM reaper;
    `release <id>` lifts it. `swarm.sh purge <id> --yes` deletes a finished
    run's sandbox, its kept VM disks (`<sandbox>.vm-snapshots/`; with
    `--vm-snapshot-dir`, only this run's files in that directory) and its hub
    directory, refuses a held run or one still running, and leaves a
    destruction record on `runs/operator-audit.jsonl`: what was deleted with
    its size, and the hashes of the inputs manifest, the custody verdict and
    the package manifest. The registry keeps the run as `purged`. Purge
    deletes files the ordinary way: it does not overwrite the blocks the
    filesystem freed, and copies elsewhere (a package handed over, a synced
    folder, a backup) are the operator's to deal with. `--no-vm-snapshot`
    keeps no VM disk at all.
  - **Disk encryption.** The kickoff records whether the volume that holds the
    runs is encrypted at rest (`disk_encryption`: `on`, `off` or `unknown`,
    from FileVault and APFS on macOS, a crypt device under the mount on
    Linux), prints it as the `Disk:` line and warns when it is off. It does
    not refuse.
  - **Synced folders.** The runs live under `runs/` in the checkout unless
    `SWARM_RUNS_DIR` or `--sandbox` says otherwise. A run directory inside a
    synced folder (Dropbox, iCloud Drive, OneDrive, anything under
    `~/Library/CloudStorage`) is uploaded to that service: a copied
    `--inputs`, snapshots and extracted material included. Before anything
    is written, the kickoff refuses to put a copy of the evidence
    (`inputs/`, `.inputs-pristine/`) or the VMs' kept disks in a folder it
    recognises as synced (under `~/Library/CloudStorage`, iCloud Drive,
    Dropbox, OneDrive, Google Drive), unless `--allow-synced-folder` says
    they may go, or a regular file of the operator's named
    `.dfirswarm-allow-synced` sits at the top of that synced folder (or in a
    folder between it and the destination); the registry says which allowed
    it. A run directory there is warned about for what the agents derive. It recognises only those names. For a real case put the runs,
    and any `--vm-snapshot-dir`, on a local disk that is not synced.
  - **Disk.** A kept snapshot can be as large as the VM's root disk
    (`--vm-disk`, 8 GiB by default) per agent. Before each snapshot the stop
    looks at the free space where the disks are kept: below a fixed floor of
    4 GiB (`SWARM_SNAPSHOT_MIN_FREE_BYTES`), not the size of the disk, the VM
    is kept, not snapshotted and not removed. A VM whose snapshot fails for
    any reason is kept the same way, and the stop says `NOT PUT AWAY`.
  - **Time.** Custody at stop reads every evidence file once more, so a stop
    on a large case takes as long as hashing its evidence again.
    `--custody-timeout SEC` bounds it (14400 by default) and names what it did
    not re-read; `--no-custody` skips it, and `scripts/custody.ts <sandbox>`
    takes it later.
- **Playwright is off by default** and refuses remote http(s) targets unless `SWARM_BROWSER_REMOTE=1`; under netguard the browser has no egress anyway.
- **The web app gates what costs money, and keeps case data on this machine.**
  It binds `127.0.0.1`; reads need no token and show case data, so opening it
  to the LAN (`--host 0.0.0.0`) is the operator's explicit choice. Start, stop,
  reap and restore need the token the server prints in its URL (in the
  fragment, so it never reaches a proxy log). `SWARM_UI_TOKEN=` turns that off
  deliberately. Never port-forward it; use an SSH tunnel. An agent's HTML
  artifact, and the report, are shown without scripts: a script could
  navigate the frame with what the file holds to any host, from the
  examiner's browser, past every allowlist of the run. **Open with scripts**
  runs one file's scripts in that view after a warning that says so,
  through a one-time grant that needs the token, is bound to the file's
  sha256 and lapses after a minute, and each opening is on the run's trace
  (`artifact_scripts`).
- **The operator is on the record.** Each `start`, `stop`, `reap`, `say`,
  `package`, `report` and `tools` is a line in `runs/operator-audit.jsonl`
  beside the registry, which no pane can write: when, the OS user and host,
  through what, and the arguments (`--env` values and the goal left out),
  each line carrying the sha256 of the one before. A `start`, `stop`, `reap`
  or `say` of a live run is on its trace too (`operator_action`); from a
  shell that is not the kickoff's it is marked unverified, since the
  harness cannot prove who typed it. The chain shows a line taken out or
  changed; it is not signed, so whoever can write the file can rewrite it
  whole.
- **Time is UTC in the run.** The agents and the run's own processes run
  with `TZ=UTC` (an `--env TZ=` overrides it), a ledger event time must
  carry its zone, and the registry records the host's own zone and, where
  the host can say, whether its clock was synced (`host_clock`; macOS gives
  no unprivileged answer, and it is `null` there). The examiner's own shell
  keeps its zone.
- **A run started as root is warned about**: root is not held by the modes
  on the evidence, its pristine copy, the manifest and the anchor, so only
  the kernel guard (or a VM) still holds them.

**Settled**: claims are short leases with a reason and a `seconds` argument,
renewed by re-claiming (120 s); the trace shows `thinking` rows and a duration
on every call; the agent view shows context-window occupancy; a
`claim violation` is a *bash* write announced on the board, not a blocked one;
`file_diff` addresses revisions by content hash; threads have a purpose and a
member list.

**Local choices** (marked in code): the stall timeout (ours: 960 s for the
reaper, above the catalog's own 900 s step, and 90 s for the console's `?`), the thread dim threshold (ours: 2 min), the grace period before a
harness stop (ours: 2 min), the hard-kill default (ours: off), the sentinel
filename and the board's directory tree, file-history storage (ours: numbered
copies), the Herdr pane-count ceiling (none hit at 30), and macOS network
enforcement.
