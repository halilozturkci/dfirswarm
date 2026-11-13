### Fixed: an AD1 image's further segments (.ad2, .ad3 …) belong to its set, as an E01's do

The census counted EWF (.E01 …), EnCase 7 (.Ex01 …), SMART (.S01 …) and split raw (.001 …) sets, not FTK Imager's AD1 sets. A job that
declared an image's `.ad1` was given that segment alone, so `ad1_extract` read 1 of 12 segments and said the other 11 were "not there", and
the kickoff catalogue listed the items of the first segment only (30,315 of 399,836 on a real image). The `.adN` names are now segments of
the `.ad1` beside them, ordered by their number (`.ad10` after `.ad9`, as the AD1 reader takes them), so the scope and the catalogue get the
whole set.

### Fixed: a page of the ledger a seat read is an echo in the store sweep, not a new hit

The harness's own `ledger`, `leads` and `questions` tools read the run's registers alone, but their kept outputs name no path in their
arguments (`{limit: 12}`), so the sweep could not tell what they read and held their hits. A seat that read the ledger after recording an
answer made a new hit for the answer's own strings; the coverage record that had to name it made the next. In one run a question's answer was
written 18 times in an hour and the finish loop never settled. Those outputs are now echoes (`REGISTER_READERS`), and a sweep line written
under the earlier rules is read again when the hub starts (sweep rules version 2).

### Fixed: a skill asked for with a pack's short name in front is that pack's note

24 of 25 failed skill loads in three runs named the pack by a short name: `base:evidence/ad1`, `base/evidence/ad1`,
`windows:execution/prefetch`. The index over budget shows each pack as its router (`base/router`), so a seat wrote that namespace in front.
`skill()` now takes a whole word of a pack's id, its words up to a dash, or its router's namespace as the pack, with a slash or a colon, and
answers with the id to use; `x:id` where no pack goes by `x` is the one pack that carries `id`. Two packs that carry it: none is chosen.

### Fixed: a job that ends 0 after a program it copied into `$OUT` could not run says so

A supplied program copied into `$OUT` (mounted no-exec) could not run, and a script that went on ended 0: the run's job printed
"Permission denied" 26 times and was `ok`, with no word of why. The job is still `ok`, and its reason and its requester's post now say
"exit 0, but a program it ran could not be executed" with the way to run it, as they do for a job that ends 126. Only the shell's own line for
a file that exists in the job's `$OUT` is read at exit 0.

### Fixed: `cd <run root>` names nothing in the store sweep, and a held hit is told where to name 200 objects

A seat's `cd /…/runs/<id> && grep … ledger/ledger.md` read the bare root as a path outside the run, so its kept output held as a hit; a `cd`
or `pushd` to the run's root now names nothing, while a bare root anywhere else (`grep -r x <root>`) still reads as the whole run. The
`sweep_hits` fix said to name each object in `refs`, which hold 20: a seat that followed it in the same run dropped objects named before and
had them come back as hits. It now says `result_refs`, which hold 200 and count the same.

### Added: a skill's card comes with a call to its tool (`--skill-cards`, on by default)

Skills reached a seat only when it called `skill(id)`. On the open models of the Batman III runs that almost never happened: 5 of 8 seats of
one run loaded no skill, and 9 % of its pack-tool calls came from a seat that held the tool's skill (74 % on a Codex run); its `ad1_extract`
errors were what `evidence/ad1` says. Now a call to a tool a skill lists under `tools`, by a seat that does not hold the skill, comes back with
the skill's card: its `card:` front-matter line, or the lines that say when to use it, its first example call and what it does not show. Once
per skill and seat in a context; a compaction shows it again, and the hand-off header carries the cards of the skills it took out. A tool
more than three skills list shows the list of those skills instead. `--skill-cards off` leaves skills to `skill(id)`; `skill_card` on the trace.

### Fixed: a seat can no longer sit unseen in one call for hours

On one run a seat waited 178 minutes on a shell call in its VM that never returned (another, 112 minutes), and nobody was told: Pi's bash
has no limit unless the model names one, and the watchdog leaves a seat its pane calls working alone. A shell call in a seat's VM now gets
a limit (900 s when it names none, 1800 s at most; `SWARM_SHELL_TIMEOUT_S`, `SWARM_SHELL_TIMEOUT_MAX_S`), and one stopped there is told that
longer work is a job (`shell_timeout`). The watchdog says a seat that is working with nothing on its session or the trace past
`--call-stall-sec` (2400 s) once per silence, on the board and the trace (`call_stalled`).

### Fixed: a seat that read many images is no longer refused on every turn after

A seat read 71 images with `read`; its provider takes 32 a request, and since the context was the same on each turn it was refused six times
and lost for the run's last 74 minutes, while the board said "only this turn failed". A model call now carries the newest 24 images at
most (`SWARM_MAX_IMAGES`, 0 for no limit): past that the oldest are sent as a line naming them, down to half at a time so the history the
provider caches changes rarely, and the session keeps them all. A refusal for too many images lowers the seat's limit to the provider's
number (`image_cap`), and the board says what the harness changed.

### Added: a job runs a supplied program by naming it (`programs`)

Nothing runs where it stands in the store (sealed, no execute bit) or in a job's `$OUT` (no-exec), and the one board post that said how to
run a supplied program came at minute 2: on one run a seat copied ffmpeg and zbarimg into `$OUT`, 26 calls were refused, and the job ended 0.
`job_run(programs: ["import:mat-<n>"])` now copies each supplied program into an executable directory in the worker, with its `bin/` on
`PATH` and its `lib/` on `LD_LIBRARY_PATH` (`$PROGRAMS` names the directory), and adds it to a declared scope. Only a supplied import is
taken. The contract's Tool jobs section, the tool-supply post and the exec-refused reason for a supplied program say so.

### Changed: the derived catalogue spends its generations on what a user made, not on a vendor's files

It took the largest waiting objects first, and its 50 generations went where the bytes were: 49 of 50 to Office's files under
`Program Files/Common Files` on one run, 37 of 50 to the libraries of a supplied ffmpeg a seat had copied into `$OUT` on another. What a
user made or kept (a profile's Desktop, Documents, Downloads, …) now goes first and a vendor's or the system's files last (Program Files,
Windows, ProgramData, AppData/Local/Microsoft, /usr, /lib, shared libraries), the largest first within each; a job's copy of a file an
import holds is skipped and named, as a copy of an input is.

### Changed: ad1_extract takes what a seat meant instead of refusing it, and names the locators near one it does not hold (computer-forensics-base)

A budget over its ceiling (`max_seconds` 3000) is held to the ceiling, and in a job a relative `out_dir` ("tree") is taken under `$OUT`;
both were refused, and seats sent the call again. In a job `max_bytes` is held to the room free where `$OUT` is, less 64 MiB, so a
whole-image call stops by its budget between items instead of running into a full disk part way through a file (three jobs). Each is said
in the answer's `adjusted`. A locator the image does not hold is answered with the nearest items the read holds, and that a locator is an
item's address as `members.tsv` lists it, not an offset in a segment file (a seat had worked one out from a raw offset).

### Fixed: the hub no longer runs out of heap when several store sweeps run at once

One run's hub died of a 4 GiB heap after 90 minutes, and nothing was said before it did. Measured on a clone of that run: one store sweep's
list of the store's 212,722 objects held 330 MB, 260 MB of it their whole paths, and three sweeps at once (the hub starts one per coverage
record, in the background) peaked at 1.6 GB. An object now holds its directory, shared by every file of a job, and its name, joined when it
is read; sweeps that start while a listing is made share it. Three sweeps at once now peak at 312 MB. The hub writes its memory to
`status.json`, says a crossing of three quarters of its heap on the trace (`hub_memory_high`), and is started with a heap snapshot near its
limit, which `swarm.sh stop` keeps under `~/.dfirswarm/diagnostics/<run>/`, out of the run. A seat told its file-history quota is spent sends
later revisions as their hash, not their bytes.

### Fixed: an answer stands on a coverage record revised for the same questions at the same coverage

A coverage record revised to name what a store sweep found took down the answer resting on it, which then had to be written again with the
same value, and each new answer moved the fingerprint the summary and the narrative are bound to: on one run one answer had 18 versions in
an hour, and the finish line's acknowledgements were cut each time. A coverage record superseded by a coverage record for the same questions
at the same coverage now carries the answer: the answer rests on the correction as it stands, which is still reviewed, swept and read by
the gates, and is weighed again only when the questions or the coverage change. The sweep's fix says to leave the answer as it is then.

### Added: what holds the finish is on the trace, by code

The finish register recorded readiness only when it turned, and the trace kept only whether the run was ready, so after a run nobody could
say what had held each `finish prepare` (on one run: eight prepares, one readiness line). `finish status` and `prepare` now give `held`,
each section with the ledger gate's code holding it (`sweep_hits`, `no_critic_act`, `answer_support`, …), and the `finish` trace row keeps
how many items held the finish and how many sections each code held, never the items' words.

### Added: an answer out of the format its question asks for is told so when it is recorded

Answers that were right lost their marks for the form the case grades: on one run nine of eleven answers were sentences where the question
gave a format (`Name_md5(file)`, `DD-MM-YYYY-HH-MM`, `ip:port`), on another a date came as `2024-02-21 16:33`. A question's `Format:` line
is now read into a pattern (a hash's hex digits, a date and time's digits in the placeholders' order, an address, a port, an email, free
words between the separators), and an answer whose value holds no line in that form gets a note naming the format. It is recorded as
written: the pattern is a reading of free text, so it is said, never refused.

### Added: a case says what its questions need done, and the kickoff checks it before anything is spent

On the first Batman III run three questions closed not determinable for want of a video decoder and a QR reader, and on another a
`zbarimg` was there and could not read a PNG (no ImageMagick PNG coder). `--requires video-decode,qr-decode,…` (or `requires:` in the
goal's metadata block) names what the questions need; the toolbox check, where the agents run, looks for a program that does each and runs
a test input where one says more than presence (`zbarimg` on a small PNG). `toolbox.json` records each under `requires`, `SWARM.md` says
it, and one not met is a warning before the run starts (a blocker with `--toolbox-required`). Eleven capabilities: video-decode,
audio-decode, qr-decode, ocr, image-convert, pdf-text, office-macros, archive-7z, pcap, stego, memory.

### Changed: a collapsed skill index shows each pack's core notes beside its router, and five routers carry the rules every note holds

With five packs the index (4,339 tokens) passed the run's 2,500 and every pack showed its router line alone, so the notes the cases
reached for most (the AD1 note, the documents and media note, Windows clocks, Prefetch, static inspection) were one load further than a
weak model went. A skill may now say `core: <rank>`; the generated index lists the pack's core notes on a `Core:` line, and a collapsed
index shows them beside each router, one pack's at a time, while the run's and the pack's budgets have room (`core_shown` in the
report). With the five Batman III packs the prompt shows 14 index lines (406 tokens) instead of 5. The routers of the base,
Windows, reverse-engineering, ransomware and encrypted-containers packs open with an `Always` block of two or three one-line rules every note
of the pack holds (a negative is bounded, a converted time keeps its raw value, a decompiler's output is a lead), for a model that loads
the router and nothing under it; the base, reverse-engineering and ransomware routers may have 500 tokens for it
(`scripts/skill-budgets.json`). Packs: computer-forensics-base 1.16.12, windows-forensics 1.7.36, reverse-engineering 1.16.10,
ransomware-response 1.13.8, encrypted-containers 1.14.10.

### Added: the run's metrics say what the seats made of the skills

`swarm.sh metrics` gains a Skills row: loads (failed, already held) and cards per seat, the share of tool jobs a seat ran while holding the
note on that tool (loaded or shown as a card since its last compaction, which drops a body from the context), the tools run uncovered most,
and how often a compaction after a load was followed by a load again. On one Batman III run it reads 1 of 55 tool jobs (2%): 44 of the
uncovered were `ad1_extract`. It is the measure of the skills experiment.

### Fixed: a search over a whole job whose hits the record names is said, not held

A job that declared a whole job as its input (`job:j000104`) read nothing the record named as such, so its output stood as a hit although
the record named the one file under that job that held the string (one run's j000468, held on E-414). A whole job or a directory of one is
now accounted for when the record names an object under it in which the sweep found the string and no object under it holds the string
unnamed; one that does keeps the hit standing. Sweep rules version 3: recorded sweeps are read again under it.

### Changed: a sweep hit another seat attested an examination of no longer holds, and the coverage record is not written again for it

A hit the store sweep found outside a coverage record held until the record was written again naming the object, and each new record was
swept anew, finding the seats' own outputs of the last round (one run's finish loop). A hit is now examined in place when a standing
finding, event, absence or limitation for one of the record's questions, written after the sweep, names the object and a seat other than
its authors attested it. Unattested, or attested only by its author, the hit holds as before. The `sweep_hits` fix says so.

### Fixed: a seat told of facts the hub could not give is told they are unknown, not zero

When the hub restarted, a compaction's hand-off header fell back to zeros and printed them as fact ("Ledger: 0 entries", "Sentinel:
absent"), and a turn whose sentinel or inputs read was refused ran on Pi's base prompt alone. The header now says those facts are unknown
and to check the inbox and the sentinel; the prompt is built with the reads it has and says which it could not make.
