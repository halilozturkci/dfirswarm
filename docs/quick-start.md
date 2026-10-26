# Quick start

From a clean machine to a first live swarm, the console, and a first case:
prerequisites, install, the agents' VM image, the dry run with no model, the
proof runs with no key, the first live N=2, the web console, and what a real
case needs on the command line. Every agent runs in its own microVM unless
the run says `--isolation host`. About five minutes if Herdr and Pi are
already installed, plus one image build.

### Prerequisites

| Need | Why | Check |
| --- | --- | --- |
| **Node ≥ 22.19** | `--experimental-strip-types` runs the `.ts` scripts and tests without a build step; the pinned Pi needs 22.19, and on an older 22 the harness extension does not load. Node ≥ 22.21 (or 24) is needed for `NODE_USE_ENV_PROXY` if your `pi` is a Node build (see [Safety](safety.md)). | `node --version` |
| **bash 3.2+ (macOS's own is enough), jq 1.6+, python3, curl; zsh if it is the login shell** | `swarm.sh` renders the contract with python3 and manages the registry with jq; the pane hook runs in the login shell, which has to be zsh or bash; `netcheck` uses curl. | `jq --version && python3 --version`; the login shell: `getent passwd "$(id -un)" \| cut -d: -f7` on Linux, `dscl . -read "/Users/$(id -un)" UserShell` on macOS |
| **Herdr** | Panes, workspaces, `herdr agent start --kind pi`. Live runs used Herdr 0.9.0. There is **no** `herdr swarm` command; do not install `pi-herdsman`, `pi-herdr` or `@gjczone/pi-swarm` expecting this demo. | `herdr --version` |
| **Pi** (`@earendil-works/pi-coding-agent`) | The agent harness. Verified against 0.85.1 and 0.87.0, the version `package.json` pins and the tests load; the extension APIs it uses date from 0.74. | `pi --version` |
| **A provider login for Pi** | `pi /login` once: an API key, **or a ChatGPT/Codex subscription** for test and CTF runs (a consumer plan, never for a customer's data; `--customer-case` takes API keys only), never a Claude subscription, which Anthropic does not permit in a third-party client such as Pi; see [Credentials](credentials-and-teams.md). `swarm.sh start` passes no credential to an agent; Pi on the host reads its own store, and a VM gets a placeholder the host swaps for the key on the way out. A subscription goes into a VM only with `--allow-oauth-in-vm`. A host run on a host with no persistent home can take an exported key with `--key-from-env` instead (see [ADR 0003](adr/0003-the-provider-key-comes-from-pis-own-store.md)). | `pi auth check --model <provider/id>` |
| **A host that boots microVMs** | Every agent runs in its own microVM (microsandbox) unless the run says `--isolation host`: a Mac on Apple silicon, or Linux with KVM (`/dev/kvm` this user can open) and glibc. msb comes with `npm install`. `sqlite3` on the host, so that a stop can clear a removed VM's secrets out of msb's database (it warns when it cannot). A host without them is refused at kickoff, with what it lacks. | `ls -l /dev/kvm` on Linux; `sqlite3 --version` |
| **Docker, once** | Builds the agents' VM image and the job images a case's packs need ([below](#the-agents-vm-image)); a machine that pulls them from a registry does not need it. | `docker --version` |
| Only for `--isolation host`: **a kernel guard** | A host run is unisolated: every agent is a process on this machine, held by the host guards. macOS has `sandbox-exec` built in. On Linux the write allowlist and the clean room need Landlock (kernel 5.13+, `python3`), and the socket mask and the fail-closed egress guard need unprivileged user namespaces (`unshare -rm`, `unshare -rn`); bubblewrap adds a read-only root when present. The kickoff measures what the host has and records it, so a host that lacks one still runs, and the record says so. | `unshare -rn true`; `python3 scripts/landlock.py --dry-run -- true` |
| Optional: Chromium | `--playwright` tool. `npx playwright install chromium`, or point `BROWSER_CHECK_EXECUTABLE` at an installed Chrome. | |

### Install

```bash
# Herdr + its Pi integration
curl -fsSL https://herdr.dev/install.sh | sh
herdr integration install pi

# Pi
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
# or: curl -fsSL https://pi.dev/install.sh | sh

# This repo, and microsandbox's msb with it
git clone https://github.com/halilozturkci/dfirswarm && cd dfirswarm
npm install
# Host runs only (--isolation host), without microsandbox's native binaries:
#   npm ci --omit=optional
```

### The agents' VM image

Each VM boots an OCI image loaded into msb. The agents' VMs boot the base,
`dfirswarm-base:dev-<arch>`: Pi, a shell, Python and the tool library.
Build it once (`amd64` in place of `arm64` on an Intel or AMD Linux host):

```bash
docker build -f images/base.Dockerfile -t dfirswarm-base:dev-arm64 images
docker save dfirswarm-base:dev-arm64 -o /tmp/dfirswarm-base.tar
"$(node --experimental-strip-types scripts/vm.ts msb-path)" load -i /tmp/dfirswarm-base.tar
```

The forensic programs are in the job images, one per profile (`disk`,
`memory`, `mobile`, `macos`, `cloud`, `triage`, `network`, `linux`, `re`,
`core`, `full`), built the same way ([images/README.md](../images/README.md)).
`core` is the base pack alone: the Sleuth Kit and the rest of what that pack
names, no other pack's programs (a run whose only pack is the base pack boots
it). A run with packs runs its tool work in the images that hold them, and each
image lists its programs in a file the agents read (`images/<profile>/tools.md`
in the run). When this host lacks the base, or the job image that holds all of
the run's packs, the kickoff tries to pull it before anything is written, and
when it cannot, stops and says how to build it. Another job image that is
missing and cannot be pulled is left out, and its packs' jobs run in the one
that holds them all.
With `--no-jobs` or `--brains-with-packs`, the agents' own VMs boot the
image that holds the run's packs instead.

### 1. Dry run without a model (no keys, no Herdr, no network)

```bash
npm test
# = node --experimental-strip-types --test tests/dry-run.test.ts tests/ui-server.test.ts ...
```

The protocol test alone runs with nothing but Node:

```bash
node --experimental-strip-types --test tests/dry-run.test.ts
npm run test:bash    # await-done certification, the reaper, netguard, the guards this host has
```

Two fake workers post on the board, hit a claim conflict, get a write blocked
without a lease (recorded as `claim_violation`), have a shell write detected
and announced, fold fake Pi usage into `budget.json`, write `work/hello.txt`
with both ids, and stop on `done/SWARM_DONE`. The bash fixtures cover the part
that decides whether a run counts as finished, and the guard suites skip
themselves with a message on a host that cannot enforce a guard.

### 1b. A whole swarm without a key (real panes, scripted model)

Fixtures never touch Pi's hooks or Herdr's panes. To exercise those without
paying for tokens, point Pi at a local scripted provider. This proof was
made as a host run and is shown that way; `tests/vm-integration.test.ts`
runs the same kind of scripted model with Pi in a VM.

```bash
node tests/mock-provider.mjs --port 8787 \
     --script tests/fixtures/mock-swarm-hello.mjs &

scripts/swarm.sh start --isolation host --model mockswarm/scripted-1 --n 2 \
  --cap-usd 5 --no-netguard --goal-file prompts/goals/hello.md \
  --env PI_CODING_AGENT_DIR=/tmp/piagent
```

`/tmp/piagent/models.json` declares the provider; the full file and the results
are in [docs/proof-run.md](proof-run.md). Everything but the model is real,
which is enough to watch a claim conflict happen between two live processes and
to watch the harness write `done/SWARM_DONE` itself when the agents ignore a cap.

### 1c. A whole swarm on a local model, for nothing

The same run on a model served from this machine costs nothing and needs no
login. With Ollama running and a model pulled, give Pi's `models.json` a
provider with a placeholder key and a `compat` block (the full file, and why
each line matters, is in
[credentials-and-teams.md](credentials-and-teams.md#local-models-ollama-lm-studio-vllm-llamacpp)),
then:

```bash
scripts/swarm.sh start --isolation host --model ollama/glm-4.7-flash-64k:latest --n 2 \
  --cap-tokens 3000000 --wall-clock 12 --local-only \
  --goal-file prompts/goals/hello.md
```

A team that bills nothing cannot be stopped by `--cap-usd`, so the kickoff
asks for a token cap instead, probes the server before any pane opens (that
it answers, that it has the model, what context Ollama will really give),
and runs netguard with the local endpoint as the only allowed host. The run
this was proven on (`s7f9d`, two agents, 2/2 checks in 8m 50s, 157,803
tokens, $0, three `ALLOW connect 127.0.0.1:11434` and no DENY in the netguard
log) is in [verified-runs.md](verified-runs.md), a host run as shown. In a
VM run the agents reach the local server through msb's host gateway, on that
port alone. The summary and the console then say "free" and count tokens
against the cap rather than "$0.00 spent".

### 2. First live run, N=2

Herdr must be running before kickoff: open the Herdr app, or in a second terminal run `herdr server` (`swarm.sh` talks to it over the socket and does not start it for you; it checks `herdr status server` before it makes anything, and refuses the start while the server is stopped). Make sure `herdr` is on `PATH` (`export PATH="$HOME/.local/bin:$PATH"` after the installer).

```bash
pi /login                            # once; swarm.sh does not pass keys to panes
scripts/swarm.sh netcheck            # optional: proves provider ALLOW / example.com DENY

scripts/swarm.sh start \
  --model deepseek/deepseek-v4-pro \
  --cap-usd 1 \
  --n 2 \
  --goal-file prompts/goals/hello.md
```

`--goal-file` is where you say what the swarm is for. It is a markdown
document that must carry its own `## Definition of done`; the `## Checks` lines
in it are what `await-done.sh` runs to decide whether the run actually
finished. A goal without a definition of done does not start; see
[Writing a goal](usage.md#writing-a-goal).

The agents run in two microVMs, one each, from the base image. Output says
so (`Isolation: one microVM per agent`), names the VMs it creates and their
size, and ends with the swarm id, the sandbox path and the three commands to
watch, check status and stop. Each VM's probe goes into its record
(`vm/<id>.json`), and a VM whose probe fails stops the kickoff. A host that
cannot boot them is refused before anything is written, with what it lacks
and how to go on.

A host run (`--isolation host`) prints a line per guard instead, saying what
this host could enforce. Read those lines once: on macOS the write guard, the
evidence guard and the quarantine are kernel-enforced (seatbelt) and the
egress guard is a proxy the panes are pointed at, which is advisory; on Linux
the egress guard is a network namespace with no other route out, and the
write guard is Landlock, inside a user namespace where the host allows one.
Either way the same facts go into the run record and the report's custody
section. Then:

```bash
scripts/swarm.sh list
scripts/swarm.sh status <id>
SWARM_SANDBOX=runs/<id> scripts/watch.sh
scripts/await-done.sh --sandbox runs/<id>     # exit 0 once the DoD is met
scripts/swarm.sh stop <id>
```

A live N=2 hello run costs about **$0.02–0.06** on DeepSeek V4 Pro and, as a host run, finishes in one to two minutes ([Verified results](verified-runs.md)); VMs add their start-up to that.

### 3. Open the web console

```bash
npm run ui:build                     # once; swarm.sh ui also builds when ui/dist is missing
scripts/swarm.sh ui                  # http://127.0.0.1:43173 (SWARM_UI_PORT changes it)
```

Binds `127.0.0.1`: this machine only. From another machine, use an SSH
tunnel (`ssh -N -L 43173:127.0.0.1:43173 you@host`); `--host 0.0.0.0` opens
it to the LAN, where anyone who can reach the port can read the board, the
trace and what came out of the evidence. **Watching is open; starting, stopping,
reaping and restoring need a token.** The server mints one at startup and
prints it in the URL it hosts (in the fragment, so it never reaches a proxy
log); open that URL once and the browser keeps it. `SWARM_UI_TOKEN=...` pins
your own, and `SWARM_UI_TOKEN=` (empty) turns the check off deliberately.

Swarms started from the terminal appear instantly; the **New swarm** form
starts them through the same `swarm.sh`, with the goal document first and its
finish line read back before a model is chosen. A run's **Jobs** tab lists
every tool job from the store's journal, with its record, its manifest and
its logs. In the ledger a sensitive entry stays blurred until you click it;
`package --redact` is what takes it out of what you hand over. To browse the
console without a model: `npm run ui:fixture` then
`SWARM_RUNS_DIR=$PWD/runs-fixture scripts/swarm.sh ui`.

### 3b. Or start it from the console

The **New swarm** form takes everything the command line takes and runs the
same `swarm.sh start` underneath. In the order the form asks, on a first case:

| | |
| --- | --- |
| ![The overview with the New swarm button](screenshots/kickoff-01-overview.png) | ![The goal document with the finish line read back beside it](screenshots/kickoff-02-goal.png) |
| **1. New swarm.** The overview lists every run in this registry; the button in the header opens the kickoff. | **2. The goal.** Write it or load a saved one; the panel beside it reads the finish line back (definition of done, the checks found, whether they read `work/`). A goal without a finish line is refused here too. |
| ![The team card with provider readiness](screenshots/kickoff-03-team.png) | ![The caps card: USD cap, token cap, wall clock](screenshots/kickoff-04-caps.png) |
| **3. The team.** One model or a mixed team with a count per model; the chips are what `pi auth check` answered for each provider right now. | **4. The caps.** A dollar cap for the swarm, a token cap (required for a team of local models), the wall clock. |
| ![The read-only inputs card with an evidence set chosen](screenshots/kickoff-05-inputs.png) | ![The case card: catalog, install, quarantine, toolbox, per-agent cap, case id, examiner](screenshots/kickoff-06-case.png) |
| **5. The evidence.** Sets under `SWARM_INPUTS_ROOT`, with file count and size; in a VM run each VM mounts the set read-only, and in a host run *auto* takes the kernel guard the host has. | **6. The case.** The catalog, which takes the census of every input and plans the packs' recipes (in a microVM run they run as jobs while the agents work); install, quarantine, the toolbox, a per-agent cap, the case id and the examiner; the packs, which also choose the job images; and the microVM switch: on by default, and off makes a host run, labelled unisolated. |
| ![The network card and the switches](screenshots/kickoff-07-network.png) | ![The label, the command the form built, and the Start button](screenshots/kickoff-08-command.png) |
| **7. The network and the switches.** Guarded by default; hosts a case needs; local-only; browser tools, hard kill, tool writing, prepare only. | **8. The command, then Start.** The form shows the exact `swarm.sh start` line it will run. Starting needs the token from the server's startup line; watching never does. |

### 3c. While the case runs, and after it stops

The run is yours to steer while it runs; each command below that changes it
acts through the hub and lands on the trace and on the operator's record,
while `metrics` and `replay` only read it. Each has its detail in
[usage.md](usage.md) (and `swarm.sh help <command>`).

```bash
# ask the running swarm a question (Q-n); list and follow them
scripts/swarm.sh question <id> add --text "Was the archive mailed?" --why "the client says so"
# a question that takes something as happened says so; the premise is tested first
scripts/swarm.sh question <id> add --text "When was the archive mailed?" --presumes "The archive was mailed" \
  --why "the client says so"
scripts/swarm.sh question <id> list

# what the case takes as given (P-n), when the goal did not designate it:
# a given is never proved again nor held open as a part of an answer
scripts/swarm.sh question <id> premise add --text "The laptop was issued to the subject" \
  --locator "the case brief, first paragraph" --why "stated in the brief"

# what the run asked of you (R-n): a lead only you can unblock, evidence it
# lacks, a clarification, a stop proposal; answer, decline or ack each
scripts/swarm.sh requests <id> list --open
scripts/swarm.sh requests <id> answer R-3 "the key is in the second envelope"

# evidence acquired after the kickoff, for an acquisition request, and
# material you supply (a statement, a policy): both sealed and on the ledger
scripts/swarm.sh evidence <id> add /evidence/phone.tar --why "the phone" --for R-4
scripts/swarm.sh material <id> add memo.pdf --why "the client's timeline"

# a program no image holds, for a running run: sealed as material with where it
# came from, how it was built and the hashes you checked; the seats are told
# how to run it (a copy in an executable temporary directory inside a job)
scripts/swarm.sh tool-supply <id> add ./detector --why "a key detector, asked for in R-4" \
  --source "Debian bookworm source package 1.0-11" --built "make, debian:bookworm-slim arm64" \
  --sha256 <sha256 of ./detector> --for R-4

# the dynamic network: what was asked, decided and granted; grant or deny
scripts/swarm.sh net <id> list
scripts/swarm.sh net <id> grant NR-2 --why "the geocoder is needed for Q5"

# a run paused at a cap: more time (or --tokens, --usd) lifts the pause
scripts/swarm.sh extend <id> --minutes 30

# hold a going run yourself, and let it go on; unpause also tries again at
# once when the model provider's limit paused it
scripts/swarm.sh pause <id> --why "the client asked us to wait"
scripts/swarm.sh unpause <id>

# a run that ended: continue it on its own chains, with a new question
scripts/swarm.sh resume <id> --question "When was the stick first attached?"

# after it stops: its process metrics, its registers replayed under this
# checkout's finish rules (no model call, nothing written in the run), and
# the code the agents wrote that could become library tools
scripts/swarm.sh metrics <id>
scripts/swarm.sh replay <id>
scripts/swarm.sh tools <id> --candidates
```

- **Questions** ([usage.md](usage.md#questions-swarmsh-question-and-directives)):
  a person's question is a proposition to test, offered to one seat; `--as ID`
  names an enrolled person, `--sign` signs the act. A premise is the case's
  given, designated by you (or in the goal's front matter `premises:`); an
  agent's proposal is a proposition under test until you `premise admit` it.
- **Requests, evidence and material**
  ([usage.md](usage.md#the-case-contract-requests-evidence-material)):
  under `--more-evidence no` an acquisition is answered at once with "no
  additional input under this case policy", never "the fact is absent".
- **The network** ([usage.md](usage.md#the-dynamic-network-net)): a refusal
  stops that avenue, never the lead; one item per host and lead waits for
  you.
- **The stop policy, pauses and resume**
  ([usage.md](usage.md#the-stop-policy-extend-pause-unpause-stop-resume)): a
  cap pauses the run by default; so does the model provider refusing every
  seat, under any policy, until the time it named or a try every 30 minutes;
  `pause` holds it under any policy and `unpause` lifts a pause whose cause is
  gone; `stop` ends it as stopped, never completed; `resume` continues the
  same run, and an earlier seal still verifies as a prefix.
- **Metrics, replay and tool candidates**
  ([usage.md](usage.md#metrics-swarmsh-metrics-scriptsmetricsts),
  [usage.md](usage.md#replay-swarmsh-replay-scriptsreplayts),
  [usage.md](usage.md#the-report-the-outputs-and-the-code-left-behind)): read
  from the run's own registers, nothing written. `replay` evaluates a copy,
  values-free; `--compare` sets the run's own harness against this checkout
  and names every difference.

### 4. Your first case

A case differs from the hello goal in three ways: evidence, a real goal
document, and the tools the agents will need. The flags below are the ones
every published case ran with; `swarm.sh help start` explains each.

```bash
# the method, fetched a skill at a time
scripts/pack.sh install packs/computer-forensics-base
scripts/pack.sh install packs/windows-forensics
scripts/swarm.sh start \
  --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --n 7 \
  --goal-file library/windows/host-intrusion.md \
  --pack computer-forensics-base,windows-forensics \
  --inputs /evidence/case-42 --inputs-copy \   # the run's own read-only copy
  --catalog --toolbox dfir --quarantine \
  --allow-tool-forging \
  --cap-usd 60 --cap-per-agent 12 --wall-clock 90 \
  --case-id CASE-42 --examiner "Your name" --label case-42
```

- **The images.** The agents boot the base, and the packs choose the job
  images: these two run their jobs in the `disk` profile,
  `dfirswarm-disk:dev-<arch>`, which holds the programs they name. Build it
  as the base was built ([images/README.md](../images/README.md)); the build
  fails if a program a pack requires is missing. A job names the image it
  needs (`job_run profile=<name>`) or runs a pack tool in its pack's image,
  and a pack tool the agent's own VM cannot run is run again there as a job
  by itself.
- **Evidence.** `--inputs DIR` hashes every file and mounts the directory
  read-only into every VM (`--inputs-copy` gives the run its own read-only
  copy: the way to start a live run, since evidence your account can write is
  refused in place until it is copied or made read-only), and `work/extracted/` and `work/quarantine/` are no-exec in every VM
  whatever `--quarantine` says. In a host run `--inputs DIR` copies the directory into
  the run and holds it read-only in every pane; for evidence too large to
  copy, `--inputs-bind` guards the source directory in place; on macOS
  `--inputs-image case.dmg` attaches a disk image read-only; and nothing the
  agents extract can execute under `--quarantine`.
- **The goal.** The investigation library ([library/](../library/README.md))
  ships an investigation for each kind of case: hosts, servers, memory, logs, captures,
  malware, cloud tenants, phones, and the general work of triage, indicators
  and timelines. Each carries the questions with the artefacts that answer
  them, a `## Definition of done` that names the report and the ledger, and
  `## Checks` the agents cannot edit. Load one in the console or name the
  file with `--goal-file`, then change what your case asks. The BelkaCTF goal
  is a worked example of the same shape:
  [docs/use-cases/belkactf/belkactf6-bogus-bill/goal.md](use-cases/belkactf/belkactf6-bogus-bill/goal.md).
- **Method.** `--pack computer-forensics-base,windows-forensics` puts an
  examiner's method in front of the swarm: the agents see a one-line index of
  every skill and fetch a body only when they reach that artefact family, so
  a pack the size of a textbook costs a few hundred tokens until it is used.
  The packs are in the repository ([packs.md](packs.md#7-the-packs-in-this-repository));
  install what the case needs with `scripts/pack.sh install packs/<name>`, and
  the console's **Packs** tab then says which skills the run read and which
  it carried and never opened.
- **Tools.** `--toolbox dfir` checks for Sleuth Kit, libewf, libbde,
  Volatility, YARA and the parsers a case needs and names what is missing
  before the first agent starts: in a throwaway VM of the job image that
  holds the run's packs, or on the host in a host run. `--catalog` takes the
  census of the evidence and catalogues it with the packs' recipes into
  `catalog/`. In a host run, or with `--no-jobs`, that is one first pass
  before any agent spends a token; in a microVM run the recipes run as jobs
  while the agents work, and what the jobs produce is catalogued in turn
  (the derived catalogue; `--no-derived-catalog` turns it off). With
  `--allow-tool-forging` the agents write the tools the image lacks;
  `swarm.sh tools <id> --save DIR` keeps them and `--tools-from DIR` hands them
  to the next swarm.
- **The network.** Only the model providers are reachable. `--allow-host` adds
  a host the case needs (a symbol server, a geocoder); `--allow-install`
  lets the agents install what they need (into each VM's own disk, or into
  the run in a host run), inventoried, and `--no-pypi` keeps the index off the
  allowlist while the machinery stays on. In a host run on macOS this guard
  is advisory and the record says so.
- **A re-run.** `--no-read DIR` keeps a previous run's findings on the same
  evidence away from the agents (no VM mounts it; a host run denies it at the
  kernel), so a second swarm cannot read the back of the book. To hand the
  second swarm the first one's claims as hypotheses to re-derive or refute
  instead, `--ledger-from <run>`.
- **The copy and the disk.** A copied `--inputs` is checked against its
  source by content (`--no-verify-copy` for name, kind and size only), and
  the kickoff's `Disk:` line says whether the volume that holds the runs is
  encrypted at rest. Keep the runs on a local, encrypted disk that is not
  synced: a copy of the evidence bound for a synced folder is refused.
- **Custody.** `--inputs-hashes FILE` holds the evidence to the hashes your
  imager recorded (md5sum, sha1sum or sha256sum lines), and a mismatch stops
  the kickoff. `--custody-sign-key FILE` signs the custody verdict with your
  ssh key, `--custody-timestamp-url URL` has it timestamped by an RFC 3161
  authority, and `--time-reference URL` records a reference clock's offset
  from this host's. Every check in the verdict has a status, and
  `swarm.sh custody-verify <id>` checks the run against it later, writing
  nothing.

When the sentinel lands, `scripts/swarm.sh report <id>` renders the report
with its custody section, `scripts/swarm.sh summary <id>` prints what the run
cost and what the harness had to do, and `scripts/swarm.sh package <id>` ships
the whole run with a SHA-256 manifest. Every published case under
[docs/use-cases/](use-cases/README.md) is that package, pruned of the evidence.

Before you hand it over:

```bash
scripts/swarm.sh custody-verify <id>                                  # the run, checked against its sealed custody verdict
scripts/swarm.sh review <id> --accept 3 --examiner "Your name"        # or --reject / --amend N --note "why"
scripts/swarm.sh review <id> --sign --examiner "Your name"            # sign off the ledger and the report as they stand
scripts/swarm.sh package <id> --sign                                  # sign the manifest with your ssh key
scripts/swarm.sh verify runs/<id>/package --allowed-signers signers   # what the recipient runs
```

Until an examiner reviews the ledger, the report says every finding is the
agents' conclusion. The sign-off records the ledger's head and the report's
hash (`work/report.md`, or the file `--report PATH` names), so an entry
recorded or a report changed after it shows the sign-off is not current.
`package --redact` takes out what a sensitive entry says and the files it
cites, while every chain in the package still verifies, and `--with-outputs`
adds the jobs' sealed outputs. `hold <id>` keeps a run from being purged or reused;
`purge <id> --yes` deletes a finished run's material and leaves a
destruction record. [usage.md](usage.md#after-a-run-examiner-machine-review-releases-timestamp-rerun-package---sign-verify-certify-export-hold-release-purge)
has each command.
