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
reconciled when the hub starts. Sweep rules 4. What a sweep found is bounded the same way (up to 920 hits a line were seen): past
50 rows the line holds a summary and a few, the whole lists in `ledger/sweeps/hits-<sha256>.jsonl`, read back whole and held to
that sha256 by the hub, by custody and by a package's verify. The reverse sweep's passes run in a process of their own and keep
what each object holds, so the hub's loop no longer lists the store and a pass started again reads nothing twice. A package
carries the sweeps' side lists (`ledger-sweeps/`); a redacted line's lists are withheld with it.

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
Below the table, `swarm.sh metrics` prints the harness measures one a line, each with its figure or why the run cannot give
it: job result delivery, sealing of large extractions, records needing two or more refusals, the library's share of tool
text, the gap before a model call (from the gateway's log), idle waits, and the minutes from a value's first sighting in a tool
result to its answer. Job answers and `store_find` results carry a sighting digest on the trace (hashed tokens, no text), so a
value first seen there is found; no value is ever printed.

### Fixed: pack tools (computer-forensics-base, windows-forensics)

`catalog_search` answered `complete`, 0 matches, over a catalogue generation whose coverage was partial: every answer now
carries the generation's status, and a partial list makes the search partial. `ad1-items` writes what it covered from what it
read. `browser_storage` resolved a run-relative path against `/` in its reader and had never returned a result in a job. `regkv`
answers a key it looked for and did not find (`found: false`, exit 0) instead of failing, and is partial on a dirty hive whose
logs were not replayed. Notes: `evidence/ad1` shows both member forms and carries a card; a browser store is examined as secret
output; the p-code reader that is in the image is named.

### Added: ransomware-response reads a key scheme from a sample, a dump and the files (1.14.0)

`cipher_state_scan` lists ChaCha/Salsa states, AES key schedules, 256-byte permutations and constant tables in a dump by
offset, after a planted control that must pass. `stream_kpa_check` says per member which key and nonce source gives the
expected first bytes, builds the trailer hypothesis from one known (file, key) pair and writes the recipe.
`family_decrypt` applies a recipe with a receipt per file, and says it authenticates nothing. `encrypted_survey` measures what
the encryptor added (`scheme_pointers`). Each is a secret-output job; no key, nonce or plaintext is in an answer. Note
`recovery/scheme-from-sample`.

### Added: windows-forensics reads Chromium logins, DPAPI master keys and thumbnail caches (1.8.0)

`chromium_logins` (v10/v11 with the tag verified; a wrong key is `decrypted: false` on its row), `dpapi_masterkey` (verified
only when the master key's own HMAC holds) and `thumbcache_read`. The DPAPI derivation is checked against two independent
forward implementations, not against a real Windows master key. `registry_recover` bounds every inline page (an answer was
144.8 MB) and counts what the keys declare against what was read; regipy read the rest of the file for a value whose data is
in its record, which the shared HIVE BOUNDS block now bounds (184 of 70,010 values became 69,989). Five hive readers are
partial on a dirty hive whose logs were not replayed.

### Changed: `ad1_extract` lists without writing and stops at the members it was asked for; the kickoff catalogue lists first

`list: true` writes the item list and no file; `paths` patterns and `members_file` select; a walk for files named by number or
locator ends when they are written (one member of 399,836: 0.1 to 6.5 s, was 15 to 19 s), and the selection's status is said
apart from the image's. A call that names no member over an image past 50,000 items or 2 GiB answers with the list unless
`whole: true`. A recipe that declares `phases: ["listing"]` is run at kickoff once for its listing and then whole: the listing
is posted as "the listing", with what follows, and the contract says nobody need walk the image for a list. `chunk_needles`
names a compressed container by its first bytes and is partial over one. A kickoff catalogue that lists process or memory
dumps says so to everyone, once, with the tools of the run's packs that read one. Since the packs are fixed before the
catalogue exists, the kickoff looks at the top level of each `--inputs` directory before it resolves them (by name and first
bytes: MDMP, PAGEDU64, hibr, LiME, ELF core): a run with packs gains `memory-forensics`, and `SWARM.md` lists each dump with
its size. `--no-pack ID` keeps a pack out; a run without `--pack`, an excluded pack and one not installed are said, not added.
`tests/tool-contract-jobrun.test.ts` calls every pack tool with an input path as `job_run` does (the run root as working
directory, arguments on stdin, the job's environment, a relative path that holds a space).

### Changed: a reference given to a tool as an argument is the path it names

An argument that is wholly `job:<id>/<path>`, `import:<id>/<path>` or `input:<path>` is replaced by the path the worker sees,
`$OUT` and `${OUT}` at an argument's head are the job's directory, a declared scope is given what the arguments name, and a
reference that names nothing is refused before the job runs. A job's write quota is the free room shared among the jobs that
run at once. A hand-off's header is at most 2,000 characters beside the note and the skills line. The leads header says how
many seats work now. Custody holds a sweep line's side list to the sha256 the line names.

### Changed: a record is a tool of its kind, checked whole and refused once

`record_finding`, `record_answer`, `record_coverage`, `record_limitation` and `record_absence` each take the fields of their
kind, and a refusal names every field that fails at once instead of one per call. An answer carries its value apart from its
`qualifier`, says why a value changed (`value_changed_because`), the controls it ran (`control`), the images it read and did not
read and the carriers it holds; the report prints the qualifier apart from the value and says when no value is established.
`store_find` and `jobs` are seat tools. `image_crop` gives a region of a PNG at its own resolution.

### Changed: only a check removes a candidate, a carrier choice waits for its table, and a decoy is never the answer alone

A finding or an answer keeps `candidates [{value, state: open | ruled_out | decoy, why, by?}]` beside its value. A revision
carries every candidate of the entry it corrects, the reading a dispute of it gives (`dispute` takes `reading`), and its earlier
value when it lowers the confidence or answers an objection; a candidate leaves only as `ruled_out` naming a job, or an entry
resting on one, whose result excludes it. An answer that names the carriers it chose among (`carrier_names`) is recorded
established, or says nothing remains open, only once its carrier table has a row for each, and the finish line holds it
otherwise (`carriers_incomplete`). A finding whose payload declares itself fake, a test or a vendor's sample is marked `decoy`,
and an answer resting on decoys alone needs `decoy_check`, a machine check. `ledger.md` and the report show the candidates.

### Changed: a seat's shell output, its waits and its finish are bounded and said

A kept shell output is its first and last part, at most 64 MiB (`shellKeepMaxBytes`). After three waits nothing woke, a wait's
answer leads with the work nobody holds. A seat at work whose evidence job ended after its last record holds the finish until it
records. A tool no one note is the method of shows its own manifest's rules with its first result. The Harness row says
`job_run`'s text, the hints' share of it, the largest answer and the empty summaries.

### Changed: a supervised hub past 85% of its heap ends at a quiet moment for its keeper to restart it

With no call in flight and no busy job the hub exits 75 (`hub_recycled`); `hub-supervise.sh` and `swarm.sh` start it again.

### Added: computer-forensics-base reads a QR symbol, a video's frames, a line of glyphs and a cache body (1.17.0)

`qr_read`, `frame_survey`, `glyph_strip` and `cache_body`, with the note `evidence/first-stage` and the recipe
`first-stage-candidates`. ffmpeg, ffprobe and tesseract are optional host programs; a tool says when one is absent.

### Fixed: pack tools after their independent verification

memory-forensics 1.16.1: `minidump_map` keeps one clock for the whole call, resumes a find, names handle types, records the PDB
and filters memory over regions. windows-forensics 1.8.1: `thumbcache_read` reads from the header's end; `regkv` answers as
`regkv/5`; cards on 27 notes. ransomware-response 1.14.1: `stream_kpa_check` tries the trailer hypothesis on every other member
within its bounds; `cipher_state_scan` finds a key schedule that begins or ends in zero bytes; `encrypted_survey` measures a
tail instead of printing it.

### Fixed: shared blocks bound a running program's output and stop a stalled SQLite statement

Every tool that runs a program reads its output through one block (`PROCESS`): at most 64 MiB of standard output and 8 MiB of
standard error, kept as its head and its last MiB; a cut output makes the answer partial. Every tool that queries SQLite carries
one watch (`SQLITE WATCH`) that interrupts a statement still running in SQLite past the tool's clock or at a stop signal.

### Fixed: pack tools after later rounds of independent verification

memory-forensics 1.16.3 to 1.16.7: `minidump_map` places every stream through one rule, judges the rows before a page's offset,
and reads every module name before it pages. windows-forensics 1.8.4: a hive is opened through a checked open, and its subkeys
and values are held to a memory budget (`HIVE BOUNDS`); `chromium_logins` stops a stalled query. computer-forensics-base 1.17.3:
each media tool and the recipe derive their status from one list of what they did not read or judge. ransomware-response
1.14.4 to 1.14.6: `stream_kpa_check` answers the footer hypothesis complete only when every earlier place is settled, and holds
it to one 512 MiB memory budget (`stream_kpa_check/6`).
