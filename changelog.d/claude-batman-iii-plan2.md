### Fixed: a run with a whole-image extraction no longer stops its own job pipeline

Three runs from one branch were post-mortemed with five earlier ones. An extraction of 150,000 to 230,000 files (24 to 34 GB)
held a worker slot until it was sealed, was sealed one file at a time in the hub's loop, and started over after a restart: one
run delivered no job result for two hours. A worker slot is now free once its job is fenced; sealing is a stage of its own, two at
a time with one place always for small jobs, hashed in a worker pool with a progress record it resumes from (200,000 files in
39 s; the manifest byte-identical); a large manifest has a sorted index and a head file, so a ref resolves in under a
millisecond; the sensitivity index is built incrementally and same-bytes taint is per file; a requester is told before any
derived offer is worked out; an identical whole-object tool call joins the job that runs or is committed (`independent: true`
runs a second); `job_same_as` carries a count and a side file. `job_finished` records when the command ended, when the worker
was gone and when the service noticed, and a job's limit is enforced from outside the command.

### Fixed: a store sweep's record is bounded, sweeps run one pass at a time off the hub's loop, and a pass resumes

A sweep that stopped at its budget wrote one row for every object it had not searched: 33 to 51 MB a record, 621 MB of heap to
parse seven, and a hub that ran out of heap twice. A record now holds a summary and names a side file with the whole list
(`ledger/sweeps/unsearched-<sha256>.jsonl`); every sentence made from a sweep is bounded; `ledger.md` is rendered outside the
table lock. One pass, in a process of its own, serves every coverage record that waits, keeps what it found by object and
string, goes on where a budget stopped the last, and ends clean over a store larger than the budget; sweeps lost in a crash are
reconciled when the hub starts. Sweep rules 4.

### Fixed: no answer to a seat is unbounded, and a seat whose process ended is started again

The finish header carried every gate item whole into every `wait`, `inbox` and `leads` answer and every hand-off: 76 MB once,
a request of 19 million tokens, and eight seats' links closed within ten minutes with nothing starting them again. The header
names the caller's own items and counts the rest; a hand-off carries the seat's own part of the lead register in 2,000
characters; the hub keeps an answer over 256 KiB whole on disk and tells the seat so instead of sending it
(`SWARM_RPC_ANSWER_MAX_BYTES`). The watchdog says a seat whose link stays down (`seat_down`), starts it again in its pane up to
three times, with a fresh session when the old one holds a line too large to load (`seat_relaunched`), then records it dead
(`seat_dead`, `ALL_AGENTS_DEAD`).

### Fixed: exit 137 before the limit is a kill, not a timeout

A job killed after 3 to 17 seconds was said to have "stopped at its limit of 900s"; the seat raised the limit and then moved the
work into its own VM. It now reads "killed (signal 9) after N s, before its limit", with the worker's memory size.

### Fixed: a job that waits says why and behind what

`job_status` and `job_run` say "queued: N ahead, all workers busy" or "finished, waiting to be sealed: N ahead; running it
again gains nothing" instead of `accepted`, `fenced` or "still running"; `job.json` is written at each step; a record that cites
a job not yet sealed is told so. When the store is the stall the regroup says so to everyone and asks nothing of the seats.

### Changed: what a seat is sent is smaller

The library hint on a job's admission is at most three tools, one line each, said once to a seat (it was three quarters of all
`job_run` result text in two runs). `tools` lists one line a tool and gives one whole by name (the library whole was 472,000
characters a call). `SWARM.md` lists a pack tool in one line and keeps each whole in `PACK-TOOLS.md` (478,000 characters became
47,700). The overlap hint is said once. A catalogue revision post wakes nobody. A tool-supply post names the programs and counts
the libraries. A PNG a seat reads is scaled to 1,568 pixels on its long side (`SWARM_IMAGE_SCALE=off`). A million-token
model's hand-off line is at 200,000 tokens, not 150,000.

### Changed: the seat's own shell, and `job_run`'s three forms

A shell call that names no timeout has 120 s (was 900); a shell loop that sleeps to wait on a job is refused and pointed at
`job_status`. `job_run` drops a placeholder command beside a tool call and runs the tool; other mixes of command, tool, args and
import are refused with the call to send. A forged tool's arguments are taken as their declared types ("[1, 2]" for an array,
"4096" for an integer), and `make_tool` runs the tool's own known-answer test (`selftest`) and tells peers whether it passed.

### Added: `store_find` and `jobs` in the hub

Which job holds a file, by a part of its name or by its sha256, from the manifests' indexes across jobs and imports; and the
run's jobs for a seat (its own, a lead's, all), the open ones first with why each waits.

### Changed: an answer's first line is what is held to the question's format

The check took any line and any span in code marks, so a right value inside a sentence passed and was graded on its form. The
value's first line must be in the form; the note shows what the form looks like and says it is not a reason to guess a part.
A finding that answers a question nobody answered is said to the lead's holder after ten minutes and to everyone after
twenty. `finish status` holds the report against the ledger (`report_against_ledger`). `stop --ask-first N` tells the seats the
run stops in N minutes and to record what they hold.

### Changed: a tool's card comes first in its first result, once in the run

Of one run's 39 cards 20 were the same card after each compaction, 7 were pinned to a refused call, 9 were a bare list of ids
and none was followed by a load. A card is now the most specific note's, before the result, once per tool; none with a refusal;
the rules of the tools a seat has run ride on its hand-off. A lead that is opened or claimed is answered with the notes that fit
it, by name; `--skill-cards inject` answers with their rules (the forced arm of a notes experiment). `--seed-leads` opens a
lead per question at kickoff; `--lead-max-questions N` bounds a lead's width.

### Added: a supplied program is tested against a known answer, and each job image says what it can do

`swarm.sh tool-supply <id> add PATH --provides qr-decode,video-decode,image-convert` runs each capability's test as a job that
names the import in `programs`, tells the seats which works, and ends non-zero on a failure: a QR decoder supplied to eight runs
could read no image. At kickoff one job per job image tries x86-64 disassembly, QR and video decoding, reading a PNG, OCR,
brotli, numpy, a C compiler and a crypto library against inputs whose answers are known, and posts the result
(`job-capabilities.json`).

### Added: the hub's health on the trace, a Harness row in metrics, and capacity across runs

`hub_health` each minute (heap, event-loop delay, host load and free memory, what the hub holds); one heap snapshot at 60% of
the limit; an 8 GiB heap by default (`SWARM_HUB_HEAP_MB`). `swarm.sh metrics` has a Harness row: refused records per accepted
one, commit and queue waits, compactions per seat-hour, the hub's worst loop delay, restarts, lock timeouts, seats down. The
kickoff's capacity check counts the seats and workers of the other runs going on the host. Calls of one process take a named
lock in the order they asked (216 lock timeouts in one run were a process losing a poll to itself).

### Fixed: pack tools (computer-forensics-base, windows-forensics)

`catalog_search` answered `complete`, 0 matches, over a catalogue generation whose coverage was partial: every answer now
carries the generation's status, and a partial list makes the search partial. `ad1-items` writes what it covered from what it
read. `browser_storage` resolved a run-relative path against `/` in its reader and had never returned a result in a job. `regkv`
answers a key it looked for and did not find (`found: false`, exit 0) instead of failing, and is partial on a dirty hive whose
logs were not replayed. Notes: `evidence/ad1` shows both member forms and carries a card; a browser store is examined as secret
output; the p-code reader that is in the image is named.
