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
