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

So a pack's skills are small files, and an agent loads one when it needs it:

- The index is small and sits in every agent's system prompt, in a section the
  kickoff renders from the loaded packs' `skills/INDEX.md` (`scripts/skills-section.ts`)
  into `.pi/APPEND_SYSTEM.md`, which Pi appends to its own prompt sections:
  one line per skill, its id, a title and one line saying when to reach for it.
  Pi keeps those sections across a compaction, and for the run a hand-off starts,
  so the index is still there when the context is not. (The prompt the extension
  forces in `before_agent_start` lasts only for the run a user prompt starts,
  so it is not what carries the index; the extension adds the section to a
  prompt that lacks it, and says so on the trace.) Its budget, in estimated
  tokens (bytes / 4.245): an entry at most 40, a pack's index at most 1,000, the
  whole run's index at most 2,500. Above the pack or the run budget the section
  shows each pack's router only (see "Routers" below); a pack that names no
  router is shown whole, and the trace says so. The prompt's `worker-system.md`
  carries the protocol: look in the index before working an artefact class,
  load the matching note, say in one line what rules you will apply, hold at
  most three at once, `skill_done` when the topic is finished, and load again
  after a compaction (or a release) what is still needed.
- A body arrives only when an agent calls `skill("<id>")`, as plain Markdown:
  the front matter is left off and there is no JSON around it. The id is as the
  index lists it (`area/topic`), or `pack:id` (`pack-name:area/topic`)
  when more than one pack carries the same id; the index then lists it as
  `pack:id`, and a bare id that more than one pack carries is served by the first
  pack of the run and says which others have it. A body the agent already holds
  is not sent again ("already in your context, loaded at turn N"). The seat's
  ledger of what it holds is read off the session itself (`buildContextEntries()`),
  at a compaction and when a process starts on a session that already has some, so
  it is exact: a compaction keeps the newest part of the history (`keepRecentTokens`)
  and the bodies in it stay held, the others are taken out, and the next call
  delivers them again (the row says `reload_after_compaction`). The hand-off header
  lists the bodies the compaction took out. A message's tool calls run at the same
  time in Pi; the two tools take turns, in the order the message lists them, so
  a second `skill(id)` of the same message is answered "already in your context".
  `skill()` with no id lists every skill of every pack unless the kickoff's file put
  the whole index in the prompt, in which case it points there.
- A body may name other skills under `needs`. The result lists them with what
  each costs in tokens, and loads none: the agent loads the ones the case needs.
- `skill_done(id, note)` says the agent is finished with a body: the event is on
  the trace, and the body is marked releasable (a seat that holds three bodies
  it has not finished is reminded to finish one before it loads a fourth). What
  releasing does is the next bullet.
- A body the agent has finished with leaves its context, and a one-line stub
  stays: `<id> released (N tokens). Re-load with skill('<id>').` The harness does
  it with a `context_edit` draft that the swarm extension returns from Pi's
  `turn_end` (Pi 0.87.1, `dist/core/agent-session.js`: the drafts of a turn
  boundary are appended to the session before the next request is built from
  its projection), so the very next model call is sent the stub. The session
  keeps the raw tool result and the edit beside it, as an append-only line: what
  custody hashes, what the replay and cost readers parse and what the console
  shows are the entries they always saw; only what the model is sent changes.
  `skill(id)` after a release delivers the body again, the trace row says
  `reload_after_release`, and `skill_done` on a released note says that it was.
  `--skill-release compaction|auto|off` (`SWARM_SKILL_RELEASE` in the seat) says
  when, and **`compaction` is the default**: a mid-run release does not pay back
  its cache write before a context is cut (the cost is below), and the summary is
  written from ids and sizes in this mode too, which is the part that is a clear
  gain. `auto` is the experiment arm until a run has measured what a mid-run
  release buys in attention. An unknown value runs as `compaction`, and the policy
  row says so.

  | Mode | What leaves, and when |
  | --- | --- |
  | `compaction` (default) | a body marked done leaves in the turn the seat's `self_compact` came back, just before the compaction rewrites the prefix anyway, on every model |
  | `auto` | that, and also at the next turn boundary after `skill_done` on a model of class **open**, while no signed thinking block comes after the body |
  | `off` | nothing, and the summary input is not shaped (the behaviour before the unloader) |

  The class is read from Pi's catalogue entry for the seat's model (`api`,
  `reasoning`), never from its name or the thinking level (`releaseClassOf`):

  | Class | The entry | `auto` releases at a boundary |
  | --- | --- | --- |
  | **open** | `api` on the allow-list (`openai-responses`, `openai-codex-responses`, `azure-openai-responses`), or `reasoning: false` | yes |
  | **signed-thinking** | `reasoning: true` on `anthropic-messages` or `bedrock-converse-stream` (Fable 5.1, Opus 5.5, Sonnet 5 and every other reasoning Claude entry there) | no |
  | **unproven** | `reasoning: true` on any other api: OpenRouter's and the radius gateway's Claude entries (`openai-completions`, `pi-messages`), Gemini, a local reasoning model | no |
  | **unknown** | the session names no model | no |

  An allow-list, because the question is whether anything that comes after the
  edited result is bound to it, and that has been looked at for one family only.
  What was verified, offline, through Pi's real request builders stopped at
  `onPayload` (`tests/skill-unload.test.ts`; the same on Anthropic with an API key
  and with OAuth, Bedrock, OpenRouter, OpenAI Responses and Codex): an edit changes
  the edited result alone, and every reasoning item and signed thinking block is
  sent unchanged, in place, with the cache marker where it was. What the service
  does with it is another matter. For Anthropic's managed-effort models (Fable
  5.1, Opus 5, Opus 5.5) Pi tells the service to drop any thinking block whose
  prefix no longer matches (`anthropic-messages.js`, `block_binding.prefix_mismatch_behavior:
  "drop_block"`, beta `thinking-binding-controls`), and records the drops it is
  told of as `thinking_dropped` diagnostics: so an edit before a thinking block
  plausibly makes the service drop it, silently, and Anthropic's guide says the
  same of client-side edits of earlier turns on Fable 5.1, Opus 5.5 and Sonnet
  5.5. On other Claude thinking models a mismatch may be an error (Pi's own comment:
  "instead of surfacing as persistent 400 responses"). Not verified against a real
  Claude session; so those seats release at a compaction, where the history is
  replaced anyway. The harness reads the answer off the first reply after a
  release or a compaction (`skill_release_effect`, in the bullet on the trace below). For OpenAI and Codex,
  nothing documents a binding of reasoning items to an earlier tool output, and
  nobody has checked the Codex rate-limit accounting of a re-sent suffix.

  What is released, and what is not:

  - Only a body the agent marked done. A body it has not finished with is never
    touched, however many it holds: the notes it is working from stay. (The harness
    reminds at a fourth, it does not take one away.)
  - Not a body the model has not had a turn with: one loaded and marked done in the
    same assistant message waits for the next boundary.
  - Not a body with a signed thinking block after it in the context, whatever model
    or thinking level the seat has now. A signed block is sent back whatever the
    current level is, and for the model that wrote it: a seat switched from a Claude
    model to an open one with `/model`, or the thinking level turned off and on, would
    otherwise be edited behind blocks that stand after the edit. A thinking block that
    is a Responses reasoning item is not signed over the history and does not count.
  - All the finished bodies of a boundary go in one return, so the history is
    rewritten once, not once per body.
  - Never toggle: a body released once between two compactions is not released
    again at a turn boundary when the agent loads it again and marks it done; it
    stays until the compaction.
  - "At a compaction" is the turn in which the seat's `self_compact` came back
    successfully (the tool ends the run, and the compaction follows). A hand-off
    that was refused ("nothing to compact yet"), or that failed and was given up
    (the note is kept, the lock is released, the seat works on), is not that: such a
    seat is released from only by the rules above, never by the leftover "hand-off".
    Pi's own threshold and overflow compactions have no boundary before them and
    release nothing (they still get the summary input below).
  - A model change or a thinking-level change is picked up at the next boundary; the
    trace says what the policy came to (`skill_release_policy`).

  The cost, so nobody has to find it out on a bill. Editing an earlier tool
  result makes a provider's prompt cache write everything after it again once
  (about 1.25 times the input price; on Anthropic, with one trailing breakpoint
  and a 20-block look-back, an edit deeper than that plausibly rewrites the whole
  message part, not only what follows) and then saves the read price on the body
  at every later request. Break-even is about 1.15 x S / (r x N) requests, with S the tokens
  after the body, N the body and r the cached-read price as a share of the input
  price: 11.5 x S/N at r = 0.1, 24 x S/N at 0.05 (Opus 5.5, GPT-6.1 Sol), 49 x S/N at
  0.025 (Fable 5.1). A 500-token body with 5,000 tokens after it pays back after
  roughly 115 requests at 0.1; with 30,000 after it, 690. A context epoch is tens to
  low hundreds of requests, so on a cache-priced provider a mid-run release is a net
  cost, not a saving; it is bought for the model's attention, which nobody has
  measured. The waste it is aimed at is large (in 67 recorded runs, 71 % of 82
  fetched bodies were never named or used again; 114 of the 120 fetches a
  compaction followed were summarised away, and none of the 120 was loaded again).
  The `skill_unload` row carries `suffix_tokens` (an estimate of what followed that
  body, the reasoning items' encrypted content included) and `batch_suffix_tokens`
  (the largest suffix of the boundary: the cache writes once from the earliest
  edit, so a D8 run takes that number once per boundary, not the rows' sum).
  After an edit Pi estimates the whole context at characters over four until the
  next reply (`compaction.js` `estimateProjectedContextTokens`); on 10,853 recorded
  replies that estimate is up to 17 % above what the provider counted (7 to 12 % at
  p95), enough to push a seat 10 % under its compact line over it and lock it. The
  `context` rows are written at the end of a turn from the reply's count and stay
  the provider's; the harness's levels and lock now keep the last count the provider
  gave until the next reply, and do not move on that estimate.
- A compaction is written from ids and sizes. Pi cuts each tool result to 2,000
  characters when it serialises the history for the summary, so a note was
  summarised from its opening lines. The summary call is now given every skill
  body as one line that names the note and its size (a released one is already a
  stub), and a `<skills-read>` block: the notes read, their sizes, which the agent
  marked done, and which were not (probably still needed). The summary prompt
  asks for those under Critical Context. The hand-off header carries the same
  account in one place, each note named once and without its text: what the
  compaction took out, what was released earlier, what stayed in the newest part of
  the history, each with its size and whether the seat marked it done, and which
  notes are probably still needed (a note read in the summarised part and marked done
  in the kept tail is done). The session keeps the whole results; only the summary's
  input is shaped. `--skill-release off` leaves it as Pi serialises it, and the
  header as it was. Pi's own summariser, which takes over when ours fails twice, still
  serialises what Pi gives it: the stubs already in the session help there, the
  shaping does not.
- Every load is an event on the trace, with the sha256 of the file as the pack
  shipped it (the value `pack.json`'s checksums carry) and its token count. Which
  method a swarm consulted, which version of it, and when, becomes part of the
  record the report can cite. Every release is an event too (`skill_unload`: the
  note, its sha256 and tokens, the tool call whose result was replaced, the
  reason, the turn; a later `ok:false` row naming the same call takes it back
  when Pi did not commit the edit), and so is the policy a seat ran under
  (`skill_release_policy`) and, for the first Anthropic reply after a release or a
  compaction, how many thinking blocks the service said it dropped
  (`skill_release_effect`: Pi already records that on the message). One Claude run
  with the `auto` arm answers the question the Claude rule rests on.
  `scripts/swarm.sh context <id>` and the console's Packs tab
  count, per agent, the bodies loaded and what they cost, how many a later row
  names or uses (a proxy), how many a compaction took out of the context, how many
  were loaded again, how many the harness released and the tokens that took out,
  and how many of those the agent loaded again (the wasted-release rate).
- The kickoff passes Pi `--no-skills`, which keeps Pi's skill directories
  (`~/.pi/agent/skills`, `~/.agents/skills`, a project's `.pi/skills`, a `skills`
  setting) out of an agent's prompt. It does not keep out everything an operator
  can add; `docs/usage.md` says what still enters.

A skill is written for an agent in the middle of a case: what to look at, in
what order, what the answer looks like, what would disprove it, which tool to
use. It does not explain what a registry is.

### Skill file format

Front matter, then a short imperative body.

    ---
    id: execution/prefetch
    title: Prefetch, and what it proves
    when: An executable's run count, its first and last run, or the files it touched.
    needs: [execution/overview]
    tools: [prefetch_mam, mam_scan]
    requires_host: []
    ---

The `id` is the path under the pack's `skills/` without `.md`, as the index lists
it; it carries no pack name (`pack:id` is how a caller names one pack's copy).

`needs` names skills this one assumes. `tools` names tools that should already
be loaded. `requires_host` names binaries the body's commands call. Install
validates all three against the pack and warns about anything it does not carry:
a warning rather than a refusal, because a Windows skill is expected to call the
base pack's `icat_extract` and the set is resolved across the dependency chain
at kickoff. A reference that no pack in the resolved set carries is a bug, and
`tests/pack-tools.test.sh` fails the build on one.

### Routers

A pack may name one skill as its router, the note that says which of the pack's
other notes answers which question. It is declared in the skill's own front
matter, optional and at most one a pack:

    router: true

`pack.sh seal` refuses a value that is not `true` or `false`, and a second
router. When there is one, the generated `skills/INDEX.md` carries a line
``Router: `<id>` `` above the entries; a pack with no router has no such line and
its index is byte for byte what it was. The harness reads only that line: a run
whose index is over budget shows the router's own entry for each pack in the
prompt, and the router names the notes under it. This is the mechanism; which
packs have routers, and how long a router may be, are the pack standard's and
the pack lint's to say.

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
      "secrets": [
        { "name": "VT_API_KEY", "title": "VirusTotal API key", "required": false,
          "why": "Reputation lookups on hashes the case finds.",
          "url": "https://www.virustotal.com/gui/my-apikey" }
      ],
      "checksums": { "sha256": { "skills/INDEX.md": "..." } }
    }

`depends` is resolved at install. A pack whose dependency is missing is refused,
named, with the version it wanted.

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
the skill index into every agent's system prompt (`.pi/APPEND_SYSTEM.md`), and lets `skill` load any body.
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
