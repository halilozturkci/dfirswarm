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
