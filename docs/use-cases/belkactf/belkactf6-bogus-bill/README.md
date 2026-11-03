# BelkaCTF #6: Bogus Bill

A cashier at a corner shop takes a fake $50 bill and reports it. One bill, one
seized iPhone, one laptop — and eighteen questions that ask what was really
behind it. This is the first published capture-the-flag the swarm has been run
on, and the first case scored by string comparison rather than by whether a
report holds together: eighteen questions, each with one answer that exists
somewhere in the two images.

| | |
| --- | --- |
| Run | `s821c`, 2026-09-20T18:03:46Z → sentinel 2026-09-20T18:54:17.540Z (**50.5 minutes** of a 60-minute clock) |
| Started from | the web console's kickoff form, not a terminal — see [Infrastructure](#what-had-to-be-built-first) |
| Team | 10 agents, 5 models, 4 providers: 3 × `azure-foundry/grok-4.6`, 2 × `azure-foundry/DeepSeek-V4-Pro`, 2 × `deepseek/deepseek-v4-pro`, 2 × `openai/gpt-5.4`, 1 × `lmstudio/qwen3.8-27b-uncensored` (local) |
| Evidence | `inputs/BelkaCTF_6_CASE240405_D201AP.tar` (5.1 GB iPhone full file system), `inputs/BelkaCTF_6_CASE240405_LAPTOP.E01…E06` (8.7 GB Windows laptop), `inputs/CASE.md`; read-only at the kernel in every pane (`seatbelt`), `--inputs-enforce on` |
| Flags | `--catalog --toolbox dfir --quarantine --allow-tool-forging --cap-per-agent 15 --wall-clock 60 --cap-usd 100 --allow-host api.wigle.net --allow-host wigle.net --allow-host nominatim.openstreetmap.org` |
| Outcome | `work/report.md` under all eighteen headings, `work/flags.md`, `work/dependencies.md`, `work/timeline.md` with 22 dated rows, ledger of 57 entries; **10/10 checks pass, certified** |
| Answers | 6 at high confidence, 1 at medium, 8 recorded as low-confidence hypotheses, 3 left open — scored against the official write-up outside this repository ([why](../README.md#answers)) |
| Cost | **$77.32** of the $100.00 cap, 1,196 provider calls, 111.3M tokens |
| Harness | 259 implicit claims, 2 claim violations, 0 inputs violations, 38 idle nudges, 6 forged tools called 79 times, 0 per-agent cap steers |

## A second run on this case

[`run-2.md`](run-2.md) is `s83fd`, 2026-09-21: the same evidence and the same
goal, with the first run's answers sealed off at the kernel and no tools
carried forward. It reached 9 high-confidence answers to this run's 6, for $8
less, while short-handed — and an agent walked out of the network guard in one
command, which has its own document: [**netguard-escape.md**](netguard-escape.md).

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm; the rendered
contract the agents read is [`run/SWARM.md`](run/SWARM.md). The eighteen
questions are the event's own, verbatim, and are listed in
[`challenges.md`](challenges.md) with the story panels that came with them.

Two things in the goal were deliberate and both turned out to matter:

- **Nobody was told how the questions relate.** We did not know whether the
  eighteen are independent, and the goal says so: work it out, write the map
  into `work/dependencies.md`, and say on the board when a question is blocked
  behind another. The map the swarm produced is
  [`run/work/dependencies.md`](run/work/dependencies.md), and it is the reason
  the run did not stall — it named the BitLocker container as the gate for
  five questions in the first twenty minutes and moved everyone else off them.
- **The official write-up was placed out of reach.** Netguard's allowlist was
  the four model providers, the local endpoint and three geolocation services.
  `belkasoft.com` was not on it, so the answers could only come from the
  evidence. The proxy log shows 260 denials, all of them Pi's own startup
  calls to `pi.dev`.

## What the agents did

**The division of labour was theirs.** Ten agents named themselves in the
first four minutes — `iPhone Analyst`, `Laptop Recon`, `Vault unlock`,
`Location & Venue Hunter`, `Dependency & Timeline`, `Docs and money` — and
split along the shape of the evidence rather than along the question list: two
images, two very different jobs. One agent took the tracker and the timeline
and never touched an image.

**They found the container, and the key, and could not open it.** The full
account is [why-not-all-eighteen.md](why-not-all-eighteen.md) — three layers
of file format, one missing library, seventeen denied installs, and the
distinction that decides the whole case: mounting is privileged, reading is
not. The
encrypted container question (`Q8`) was answered inside twenty minutes:
`C:\Users\phorger\Documents\desktop.ini:vault.vhdx`, a BitLocker-protected
VHDX hidden in an NTFS alternate data stream, recognised from its `-FVE-FS-`
signature. Then `Docs and money` went further than the question asked and
recovered the **BitLocker recovery key** from an iPhone note inside an iTunes
backup on the laptop image. The host had no `dislocker`, no libbde, no libvhdi
and no root to mount with, so two agents wrote their own unlocker in Python
(`bde_unlock`, then `bde_unlock2` at version 3, 27 calls between them) and
still did not get in. Five to seven of the eighteen questions live behind that
door. This is recorded as [O10](observations.md) and is the single largest
finding of the run — the swarm did the forensics and the host was missing a
tool class the toolbox never checked for.

**The hardest question in the event fell anyway.** Question 17 — the offshore
bank's SWIFT code, solved by five players worldwide during the live event —
was answered `CRVBPA2P` at minute 32, by decoding the home-grown cipher an iOS
Shortcut had been applying to the gang's Telegram messages.

**Six tools were forged and called 79 times**, the first at minute 15. What
happened before minute 15 is [O2](observations.md): the forge hint fired five
times into an empty tool library and nobody acted, because a tool written
inside a 60-minute run only pays for itself in the next one, and nothing says
so.

**Two agents died nine minutes in and nothing said so.** Both
`deepseek/deepseek-v4-pro` agents stopped within six seconds of each other on
`402 Insufficient Balance`. The console counted them among "10 working" for
the rest of the hour, the board carried no notice, and the idle watchdog spent
its nudges on agents that could not come back. [O8](observations.md).

## The numbers

| | |
| --- | --- |
| Spend by model | `azure-foundry/grok-4.6` $32.60 (42%), `azure-foundry/DeepSeek-V4-Pro` $27.73 (36%), `openai/gpt-5.4` $16.77 (22%), `deepseek/deepseek-v4-pro` $0.23, `lmstudio/qwen3.8-27b-uncensored` $0.00 |
| Busiest | `s821c03` (Location & Venue Hunter) 368 events, 165 bash calls, $14.33 |
| The local seat | `s821c09` made 9 calls for $0.00 and was cut off mid-turn ([O9](observations.md)) |
| Board | 104 posts, 62 of them from agents |
| Trace | 2,287 events, 655 bash calls |

The full run is under [`run/`](run/): the report, the flags table, the
dependency map, the timeline, the ledger, the board thread by thread, the
trace, the catalog index, the toolbox and inputs records with a sha256 per
file, and `MANIFEST.txt` with a hash for every file in the package.
[`run/PRUNED.md`](run/PRUNED.md) says which evidence-derived binaries were
taken out of this copy and why.

## What had to be built first

The console could start a swarm but not a *case*: the kickoff form had the
team, the caps and the read-only inputs, and none of `--catalog`,
`--toolbox`, `--quarantine`, `--case-id`, `--examiner` or `--cap-per-agent`,
so every forensic run before this one had been started from a terminal. A
**Case** card was added to `/new` and is what started this run; the command it
produced is in the screenshot below and in `run/SWARM.md`. The evidence was
staged as an input set under `SWARM_INPUTS_ROOT` (the iPhone tar extracted
from the event's AES-encrypted zip, the six EWF segments cloned), and the
local model was registered with Pi as an LM Studio provider and answered both
a plain completion and a tool call before the run was allowed to start.

## Screenshots

[`screenshots/`](screenshots/README.md) is a narrated walk through the console
on this live case — sixteen images, in the order you would show somebody who
has never seen the platform: the kickoff, the board negotiating itself into
existence, the evidence with its hashes and the kernel guard named per pane,
the ledger, the forged tools, the bill by model and by agent, and the finish
line certifying itself 10 of 10. One of them is a design fault kept on purpose
([O4](observations.md)).

## Why it did not answer all eighteen

[`why-not-all-eighteen.md`](why-not-all-eighteen.md) is the account, written
out in full: the three-layer container, the key recovered from the other
image, the nine commands the agents tried between 18:11 and 18:23, the two
BitLocker readers they wrote themselves, and the answer to the question that
run raised — whether a package index is enough or privileges are needed. It
also names, question by question, why the six that had nothing to do with the
vault were left as hypotheses.

## What this run showed about the platform

[`observations.md`](observations.md) — eleven findings with the evidence for
each, written to be folded into
[docs/improvement-plan.md](../../../improvement-plan.md): the catalog
cataloguing one EWF set six times, forging that starts fifteen minutes late,
a Tools tab that cannot say why it is empty, tab-group labels that look like
tabs, a local model's first turn outliving the idle watchdog, a provider
failure that kills an agent silently, a toolbox that never checked for the
tool class the case turned on, and a package whose evidence rule is defeated
by the agents' own scratch directories.

## Reproducing it

Get both archives and their passwords from the event's
[Information page](https://belkasoft.com/belkactf6/info), unpack the iPhone
`.tar` out of the first (it is AES-encrypted; Info-ZIP cannot read it, `7zz`
can), put the tar and the six `.E01…E06` segments in one directory with
`CASE.md`, install `sleuthkit`, `libewf`, `yara` and `foremost`, start Herdr,
and start the console with that directory's parent as `SWARM_INPUTS_ROOT`:

```
SWARM_INPUTS_ROOT=<inputs root> SWARM_RUNS_DIR=<runs dir> SWARM_INPUTS_MAX_MB=20000 \
  scripts/swarm.sh ui --port 43173
```

Then either fill the kickoff form as the screenshots show, or run what it
would have run:

```
scripts/swarm.sh start \
  --models "azure-foundry/grok-4.6=3,azure-foundry/DeepSeek-V4-Pro=2,deepseek/deepseek-v4-pro=2,openai/gpt-5.4=2,lmstudio/qwen3.8-27b-uncensored=1" \
  --cap-usd 100 --n 10 --wall-clock 60 --cap-per-agent 15 \
  --allow-host api.wigle.net --allow-host wigle.net --allow-host nominatim.openstreetmap.org \
  --allow-tool-forging --inputs <inputs root>/belkactf6 --inputs-enforce on \
  --catalog --toolbox dfir --quarantine \
  --case-id BELKACTF6 --examiner "<name>" --goal-file prompts/goals/belkactf6-bogus-bill.md
```

On the evidence of this run, add `--toolbox dfir,crypto --toolbox-required` and
`--tools-from` a library seeded with this run's six tools
(`swarm.sh tools s821c --save <dir>`). The first would have refused to start
without a BitLocker reader; the second would have saved the first quarter of
the hour.
