# What this run showed about the platform

Kept while the run was live, from the trace, the sandbox and the console.
Each item is written to be folded into
[docs/improvement-plan.md](../../../improvement-plan.md) as an A-item once the
run has ended, with the evidence it rests on.

## O1 · The catalog runs the whole EWF set once per segment

`--catalog` walks every file under `inputs/`, and libewf resolves a whole
segment set from any one segment. `BelkaCTF_6_CASE240405_LAPTOP.E01` through
`.E06` therefore each produced their own `partitions.txt`, `fsstat.txt`,
`filelist.txt`, `bodyfile.txt` and `timeline.csv` — six identical catalogues of
one 8.7 GB disk, all reporting the same partition at sector 673792. The first
pass took about 100 seconds instead of about 17, and the sandbox carries six
copies of a body file for one volume.

**Evidence:** `catalog/BelkaCTF_6_CASE240405_LAPTOP.E0{1..6}/p673792/`, all with
the same partition offset; kickoff log 18:01:53 → 18:03:48.

**Fix to propose:** the catalogue recognises a segment set — `.E01` with
`.E02…`/`.EAA…` siblings sharing a stem, and the same for split raw `.001` —
and catalogues the first segment only, naming the set in `catalog/INDEX.md` so
an agent knows the other segments were not skipped by accident.

## O2 · Forging works, fifteen minutes late

The run ended with **six forged tools called 79 times**: `sqlite_query` (38
calls), `bde_unlock2` v3 (15), `bde_unlock` (12), `blob_strings` (9),
`gzip_note` (5) and `affine_decrypt`, written by four different agents across
nine `make_tool` calls. The two that say most about the feature are
`affine_decrypt`, written while the swarm was breaking the home-grown cipher
an iOS Shortcut had been encrypting the gang's messages with — the work that
produced the answer to question 17, the hardest task in the event — and
`bde_unlock`/`bde_unlock2`, a BitLocker unlocker the agents wrote in Python
*because the host had none*. That is the feature working as intended: a swarm
that meets a wall builds the tool it is missing.

One wrinkle worth keeping: `affine_decrypt` was forged and then called zero
times through the tool interface, so the cipher was broken by the script
rather than by the tool made from it. A tool nobody calls is still a tool the
next run inherits, but it is not evidence that the interface was used.

The finding is the delay, not the absence. For the first fifteen minutes
`tools/` was empty and `make_tool` had not been called once in 410 bash calls,
although the forge hint had already fired five times (three agents on
`python3`, one on `sqlite3`). Three agents called `tools` in the first minute,
got `{"n": 0, "loaded": 0}`, and did not look again. The first tool
(`sqlite_query`) arrived at minute 15 — and then was called 38 times, which is
the measure of what the first quarter of the run spent typing by hand.

The structural reason is that a forged tool pays off in the *next* run too,
through `swarm.sh tools <id> --save DIR` and `--tools-from`, and nothing in
the hint or the contract says so. This run seeded no library, so every agent
started from zero.

**Evidence:** `traces/events.jsonl` — `forge_hint` ×5 at 18:05:47, 18:08:15,
18:13:23, 18:14:39, 18:14:53; `tools` ×3 returning `n: 0` in the first minute;
first `make_tool` at 18:17; `swarm.sh tools s821c` listing all six; forged-tool
call counts from the trace.

**Fix to propose:** (a) the forge hint says the tool outlives the run and where
it is kept; (b) a maintained tool library is the default `--tools-from` for a
case run rather than something the operator remembers — a run that begins with
`sqlite_query` in the list never spends the fifteen minutes, and this run has
just produced six tools worth carrying; (c) the kickoff says on the contract
whether a library was seeded and how many tools are in it, so "no tools" is
never ambiguous.

## O3 · The console cannot say why the Tools tab is empty

For the first fifteen minutes of this run the Tools tab was empty, and an
empty Tools tab reads as "nothing to see here". The facts that would have
explained it — forging is on, five hints have fired, nobody has taken one, no
library was seeded — were all in the trace and none of them on the tab. The
same tab looks identical on a run started with forging off. The operator
watching it concluded the agents were not forging; six tools and 79 calls
later, that conclusion was wrong, and the console had given no way to tell.

**Fix to propose:** an empty state that distinguishes the three cases (forging
off · forging on with N hints and no tool yet · a library of M tools, called K
times), with the `forge_hint` events one click away in the trace. Once tools
exist, the tab should show what each was called and how often — the 38 calls
to `sqlite_query` are the argument for the whole feature and they are not on
the screen anywhere.

## O4 · The tab-group labels read as tabs

On a swarm's page the strip renders `THE RUN`, `EVIDENCE`, `THE FRAME` and
`OUTPUT` as small caps `<span>`s inline with the pills, in one `flex-wrap`
row. They look like disabled tabs, they are not clickable, and when the row
wraps a group's label can end up on a different line from its own tabs. The
grouping was added to bring order to eleven tabs; as drawn it adds four things
that look like tabs and are not.

**Evidence:** `ui/src/screens/swarm-detail.tsx`, `TAB_GROUPS` rendered at the
`label-caps` span inside the same flex row as the tab buttons; the screenshots
in this folder show the wrap.

**Fix to propose:** take the labels out of the tab row — either a stacked
layout where each group's label sits above its own pills, or a single row of
pills with separators between groups and the group names dropped entirely.
Whichever is chosen, nothing in the strip should look clickable unless it is.

## O5 · A local model's first turn outlives the idle watchdog

`s821c09` runs `lmstudio/qwen3.8-27b-uncensored` on this machine. Its first
turn — reading a ~10 KB contract and `team.json` — took about four minutes,
during which the watchdog nudged it twice. The nudges were harmless here, but
the threshold (`--idle-sec`, 180 s) is tuned to cloud latency and a local 27B
model on a long contract exceeds it before it has emitted a first token.

**Evidence:** `traces/events.jsonl` — `agent_start` and `inputs_guard` for
`s821c09` at 18:04:23, `thinking` at 18:08:14, `read SWARM.md` at 18:08:23;
two `idle_nudge` events in between.

**Fix to propose:** the first-turn grace is derived from the agent's provider —
a local endpoint gets a longer one — or the idle timer starts at the first
completed turn rather than at `agent_start`.

## O6 · `esedbexport` is missing from the dfir toolbox on this host

The toolbox check reported 12 present, 1 missing. Nothing in this case needs
ESE databases, so it stayed a warning, but a Windows case that reads
`Windows.edb` or a Jet database would have found out mid-run.

**Evidence:** kickoff `WARN: toolbox: missing esedbexport`, `toolbox.json`.

## O7 · Shipped during this run: the console could not start a case

The kickoff form had the team, the caps and the read-only inputs but none of
`--catalog`, `--toolbox`, `--quarantine`, `--case-id`, `--examiner` or
`--cap-per-agent`, so every forensic run until now had to be started from a
terminal. The Case card was added to `/new` before this run and is what started
it. Recorded here because it is the same class of gap as O3 and O4: the console
lags the harness it drives.

## O8 · A provider failure kills an agent silently

`s821c05` and `s821c06`, both on `deepseek/deepseek-v4-pro`, stopped six
seconds apart at 18:07 and never came back. Their session files say why:

```
"stopReason":"error",
"errorMessage":"402: {\"message\":\"Insufficient Balance\", … }"
```

The DeepSeek account has no credit. Two of ten agents were dead nine minutes
into the run and nothing said so: the console header still counted them among
"10 working", the board carried no notice, and the idle watchdog spent all
three of its nudges on each of them — nudges that could not possibly work,
because every retry hit the same 402. The run finished the hour with eight
agents and an operator who had no way to know that from the console.

What did hold: neither agent blocked a peer. Every lease they held had expired
by 18:08 — `work/s821c05/tarfilelist.txt`, `work/extracted/s821c06/SAM` and
fifteen others — so the work they abandoned was free for anyone to pick up,
which is A22 doing its job on a failure mode it was not written for.

The preflight cannot catch this: `pi auth check` answers whether Pi *has* a
credential, not whether the account may spend. That limit is already written
down in [credentials-and-teams.md](../../../credentials-and-teams.md#what-a-subscription-will-not-do)
— what is missing is what happens *after* the first failed turn.

**Evidence:** `.pi-sessions/s821c05/*.jsonl` and `.pi-sessions/s821c06/*.jsonl`,
last message at 18:13:44.956Z and 18:13:45.730Z; `traces/events.jsonl`, last
tool call for either agent at 18:07; the Budget tab showing $0.11 and $0.12
against a $15 per-agent cap.

**Fix to propose:** a turn that ends in a provider error is an event the
harness owns — `agent_error` in the trace, a post on the board naming the
agent, its model and the provider's own message, and a state the console can
show (`failed`, not `working`). Two rules follow from it: the watchdog does not
spend nudges on an agent whose last turn was a provider error, and a model
whose agents have all failed is named once in the header rather than left to
the spend table to imply.

## O9 · The local model's turn was terminated and never retried

`s821c09` (`lmstudio/qwen3.8-27b-uncensored`) ended its turn at 18:17:50 with
`"stopReason":"error","errorMessage":"terminated"` and made no further tool
call. It had done real work up to that point — `inputs_guard`, the contract,
`team.json`, an inbox read — on a model that needed about four minutes for its
first turn.

Whether the request was cut by the netguard proxy, by Pi's own timeout or by
LM Studio is not in the record, which is itself the finding: the error text a
local endpoint returns is one word, and nothing in the sandbox says which side
hung up.

**Evidence:** `.pi-sessions/s821c09/*.jsonl`, last message 18:17:50.125Z.

**Fix to propose:** the same `agent_error` event as O8, plus the round-trip
detail a local run needs — how long the request had been open and which side
closed it — so "terminated" can be told apart from a model that simply took
longer than the proxy allows.

## O10 · The case turned on a tool class the toolbox never checked for

By minute 20 the swarm had done the hard part twice over: it found the
encrypted container hidden in an NTFS alternate data stream
(`C:\Users\phorger\Documents\desktop.ini:vault.vhdx`, `sha256 877fff02…`),
identified it as a BitLocker-protected VHDX from its `-FVE-FS-` signature,
and then recovered the BitLocker **recovery key** from an iPhone note inside
an iTunes backup on the laptop image. Five to seven of the eighteen questions
live inside that container.

It could not open it. This host has no `dislocker`, no `bdemount`/`bdeinfo`
(libbde), no `vhdimount`/`vhdiinfo` (libvhdi) and no `qemu-img`, and the
sandbox has no root, so there is nothing to mount with either. The swarm held
the key to a door it had no handle for.

The toolbox check passed: it reported "12 present, 1 missing" and the one
missing was `esedbexport`. `dislocker` **is** in the harness's `crypto` set —
it was simply never looked for, because the kickoff was given `--toolbox dfir`.
Nothing in the run connected "the goal says encrypted container" or "the
catalog just read `-FVE-FS-`" to "you did not ask for the crypto set".

**Evidence:** board posts 49, 50 and 65; `work/extracted/s821c08/vault.vhdx`;
`scripts/toolbox.sh` `CRYPTO_TOOLS` naming `dislocker`; `toolbox.json` for this
run listing only the dfir set; `command -v dislocker bdemount vhdimount
qemu-img` all empty on the host.

**Fix to propose, in the order it would have helped:**

1. **The sets should cover the class, not one tool of it.** BitLocker, LUKS,
   FileVault and virtual disks are one job — reading a volume you cannot
   mount. `crypto` gains libbde (`bdeinfo`, `bdemount`), libvhdi
   (`vhdiinfo`, `vhdimount`), libluksde and `qemu-img`; and because there is
   no root in the sandbox, the set is documented by what it can do *without*
   mounting.
2. **The kickoff should infer the sets.** A goal that says "encrypted
   container", or a catalog that read a BitLocker or LUKS signature, means the
   crypto set — proposed by the kickoff with the choice left to the operator,
   the way `--toolbox auto` already picks dfir from `--catalog`.
3. **`--toolbox-required` should have been the default for a case run.** A run
   that refuses to start because it cannot open what the goal is about costs a
   minute; the same run discovering it at minute 40 costs the case.

Worth keeping in view: the failure here is the *host's*, and the swarm's
behaviour around it was right — it named the blocker on the board, wrote which
questions were gated behind it, and kept working on what was not.

## O11 · The package's evidence rule is defeated by the scratch directories

`swarm.sh package` leaves `work/extracted/` and `work/quarantine/` in the
sandbox, because what is there came out of the evidence and may be live. It
said so on the way out: "Left in the sandbox: 289 file(s)". But the package it
wrote was still 37 MB, and 35 MB of that was evidence-derived material sitting
in agents' own scratch directories — `work/s821c08/NTUSER.DAT`,
`work/s821c08/UsrClass.dat`, `work/s821c01/browser/places.sqlite`,
`work/s821c05/postbox.strings`, a 17 MB `tarfilelist.txt`. Nothing is wrong
with the agents putting them there; A18 told them to keep their own extracts
out of the shared root, and a scratch directory is exactly where they belong.

The handover therefore carries the evidence it meant to exclude, and by a
path nobody looks at. This copy had to be pruned by hand
([PRUNED.md](run/PRUNED.md)).

**Evidence:** the package as written, 37 MB; the fifteen files listed in
`run/PRUNED.md`; `package` reporting 289 files left behind.

**Fix to propose:** the rule is about provenance, not about a directory name.
A file under `work/` whose bytes match something under `inputs/` — or that a
trace event says was written by `icat`, `tsk_recover`, `tar -x`, `esedbexport`
or another extractor — is evidence-derived wherever it lives, and the package
records its hash and leaves the bytes behind, the way it already does for
`work/extracted/`. The count it prints then means what it says.

---

## What was done about them

Every item above was turned into a change in the same branch as this run,
with a test that fails without it. The improvement plan carries them as
[A27–A34 and B16–B17](../../../improvement-plan.md).

| | Finding | Change |
| --- | --- | --- |
| O1 | The catalog walked all six EWF segments | A segment set is catalogued once; the continuations are named in `catalog/README.md` so the gap is not read as a skipped file |
| O2 | Forging started fifteen minutes late | The forge hint now says the tool is kept and handed to the next swarm with `--tools-from`; seeding a library by default is still open |
| O3 | The Tools tab could not say why it was empty | The empty state names which of the three cases it is and counts the hints that have fired |
| O4 | Tab-group labels read as tabs | One row per group, labels in a column of their own, `role="group"` per row |
| O5 / O9 | A local model's first turn outlived the watchdog, and a terminated turn was never explained | A seat on a locally served model gets `--local-first-turn-sec` (600) before its first turn counts as silence |
| O6 | `esedbexport` missing on this host | Left as it is: a host fact, and the toolbox already reports it with the install command |
| O7 | The console could not start a case | Shipped before the run: the Case card on `/new` |
| O8 | A provider failure killed two agents silently | `agent_error` on the trace and the provider's own words on the board; the watchdog stops nudging an agent whose last turn was a provider error |
| O10 | The toolbox never checked for the tool class the case turned on | `crypto` now names libbde, libvhdi, libluksde and `qemu-img`; `--toolbox auto` reads the goal; the catalog warns when it sees a volume signature and crypto is not in the set |
| O11 | The package's evidence rule was defeated by the scratch directories | Binaries over `SWARM_PACKAGE_MAX_BINARY_KB` stay in the sandbox and are named with their hashes in `LEFT-BEHIND.txt`. Provenance from the trace was tried first and dropped — it caught 0 of the 15 files it had to |

One more came out of reading the trace afterwards, and it is the largest:

## O12 · They asked for the package index seventeen times

The agents never asked for root. They asked for a package: `which dislocker
bdemount bdeinfo qemu-img guestmount` at 18:11, `brew install dislocker` at
18:16, `hdiutil attach` on the VHDX at 18:19, `pip3 install dislocker` at
18:23. Netguard denied `pypi.org` **17 times**, `formulae.brew.sh` twice,
`github.com` and `raw.githubusercontent.com` fourteen times between them.

This is a recurrence. B14, from challenge 9, says it in as many words: "the
host had `openssl` and `gpg` and neither `aescrypt` nor `pyAesCrypt`, and
netguard keeps PyPI out of the sandbox, so a seat reimplemented the AES Crypt
key derivation by hand and failed". The toolbox sets shipped; the half about
the index did not, and the next encryption case paid for it again.

**Shipped:** `--allow-install` (B16) — `pypi.org` and
`files.pythonhosted.org` on the allowlist, `PYTHONUSERBASE` inside the
sandbox, off by default, stated in the contract, recorded in the ledger.
Root stays refused on the examiner's host: these panes are the examiner's own
processes, and the read-only guard over `inputs/` is precisely what root
would undo. A case that truly needs a mount wants a disposable container
(B17), not `sudo` — and most do not, because libbde, libvhdi, libluksde and
pytsk3 read those volumes in place.

## O13 · Every line of reasoning in every run rendered blank

The THINKING tab showed one empty row per reasoning event: a clock, an italic
gap, and nothing else. It looked like a model that thinks in silence. It was
the console reading the wrong field.

The harness writes reasoning as `logEvent(cwd, agent, "thinking", {}, { text,
chars })` — empty args, and the text in the **result**. The console asked for
`args.text`, got `undefined`, and printed the empty string. Every reasoning
event, in every run since the tab existed, in all three places it was drawn:
the raw trace, the agent's own trace, and the "right now" strip.

Two things hid it. The reasoning rows were also `→ {"text":"…","chars":694}`
on the right, so the line was not wholly blank and read as a formatting quirk
rather than a missing field. And three of the ten agents on this run — every
agent on `azure-foundry/grok-4.6` — genuinely emitted no reasoning at all,
which made "the thinking blocks are empty" look like a fact about the models
instead of a bug in the reader.

The census is worth keeping, because it is the thing the fix must not hide:

| Model | Agents | Reasoning events |
| --- | ---: | ---: |
| `azure-foundry/grok-4.6` | 3 | **0** |
| `azure-foundry/DeepSeek-V4-Pro` | 2 | 228 |
| `openai/gpt-5.4` | 2 | 120 |
| `deepseek/deepseek-v4-pro` | 2 | 36 |
| `lmstudio/qwen3.8-27b-uncensored` | 1 | 5 |

Grok on Azure Foundry returns no reasoning content through Pi's
`openai-completions` path. That is a provider fact, not a harness defect — but
a reader has no way to tell it apart from a broken recorder, and until now the
console did not try.

**Shipped:** the renderer reads `result.text` and falls back to the old args
shape, so old traces keep working (A35). THINKING is now a document rather
than a list — one wrapped block per turn, the clock in the margin (A36). Its
empty state asks the harness who else was quiet and says which of three
things it is looking at: this model returned none anywhere in the run, this
agent alone was quiet while its shipmates on the same model were not, or
nobody in the run reasoned at all (A37). And the preview the harness keeps
went from 240 characters to 2,000 (B18) — 240 was barely the first sentence,
so the reason an agent changed direction was never in the record; the note
under a clipped block now says how much was kept of how much there was.
