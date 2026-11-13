# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Added: the programs a memory case asked for, and Volatility's Windows symbol tables, in the images

A run on a Windows memory image, a capture and a logical disk image asked for programs no image held: a steganography extractor, an AES key-schedule finder, a compiler, and the symbol tables that Volatility's Windows plugins need when a VM has no network. Each is in the image that fits it now: `gcc` and `make` in memory and `re`, `aeskeyfind` in memory and `full`, `steghide` and Pillow in every image, the symbol tables in memory and `full` and only for kernels of 2019 and earlier.

- **Windows symbol tables.** The memory and `full` images pin the Volatility Foundation's `windows.zip` (a bundle of 2019, last changed 2019-10-16; `vol -q isfinfo` reports 3,014 tables from it) as data of the `vol` entry in `packs/memory-forensics/requires/host.json`. The build checks its sha256, puts it in the venv's `volatility3/symbols/`, and lists it once so that no VM spends three minutes indexing it on first use.
  - It is **not** redistributed by us, and **no image that carries `install.data` is pushed from any workflow of ours, the pro one included**: whoever runs the images builds their own, and Pro builds those per customer under the customer's own acceptance of the licences. This is the owner's stated stance, written down here for him to confirm. The image says it is not for redistribution (label, `image.json`, NOTICE).
  - Our reading of the licences, not legal advice, with the clauses quoted in the NOTICE: the Volatility Software License 1.0 includes "any data (such as operating system profiles or configuration information)" provided with the software in its "Software", and Microsoft's Symbol Server terms (June 2022) limit use of the symbol files the tables come from to debugging and testing and forbid sharing them. Those terms may bear on use as well as on redistribution.
  - **It does not cover a recent kernel.** It is a 2019 snapshot. The kernel of the run that asked for it is in neither this pack nor the community collection last updated in 2024, so `windows.netscan` on that image would still need the table fetched or made. The memory pack's skill and `images/README.md` say so, and what to do. The disk image has `vol` and no tables; its `tools.md` says they are in the memory image, and a job that names no profile and runs `vol` goes to the image that carries the data for it.
- **`install.data`**, a new kind for a pack's `requires/host.json`: a file a program reads and that is not a program, pinned by url and sha256, put inside a Python package of the venv, with an optional `warm` command, a `check` command that must succeed (the images workflow runs it again with no network), its own `redistributable` flag and a `licence` of its own for the NOTICE. It is recorded in `image.json` (`downloads`, kind `data`), the SBOM (a `data` component) and `tools.md`.
  - A pinned data file that cannot be fetched **fails the build even when its program is optional**, since an image without it says the program is there while what it reads is not; `recipe.py build --allow-missing-data` goes on, the image records `not_installed.data`, and a kickoff says so as a WARN (for the agents' image and for each job image).
- **`install.build` with `patches` and `commands`.** A source with no configure script names its steps, and may be patched by pinned patches first. `aeskeyfind` (Debian ships it for amd64 and i386 only) is built from Debian's upstream tarball and Debian's four patches, among them the one for files over 4 GB, on both architectures.
- **`gcc` and `make`** in the memory and `re` images (for a program the seat writes, never a source tree the evidence holds), **`steghide`** and the Python library **Pillow** in every image (the base pack). Packs: computer-forensics-base 1.5.0, memory-forensics 1.2.0 (a skill note on key schedules and one on the symbol pack), reverse-engineering 1.2.0, windows-forensics 1.3.4 (its `vol` line says where the tables are).
- `tests/image-programs.sh`, run inside a built image (CI runs it on every profile, and it is how the local arm64 images were checked, in a container and in a microVM): the compiler compiles, a key schedule planted in random bytes is found at the offset it was planted, one of them past 4 GiB (which the unpatched upstream does not reach), and a message goes through steghide and back. The `images` workflow also checks that every pinned data file is on disk at its recorded size and was indexed, and runs each data entry's own `check` in a fresh container with no network.
- `pack.sh` checks the new fields before it seals: a patch needs an https url and a whole sha256, commands are argument lists, data needs its package, `check`, `redistributable`, licence and a path inside it.
- `docs/packs.md` says that a pack's `requires/host.json` runs code when an image is built, so images are built only from packs one trusts.
- `docs/roadmap.md` has a heading, "Images for programs we cannot redistribute": the Pro service to build a customer's images from the recipes with the customer's acceptance of each licence.

### Added: AD1 logical images in the base pack

A run's evidence held an AccessData AD1 logical image (FTK Imager's custom content image). The kickoff's census listed it as not catalogued: no recipe of any pack knew its `ADSEGMENTEDFILE` header. The job images that hold the base pack also hold dissect, which reads AD1, but nothing pointed a seat at it. A seat decoded the container by hand, a second seat reproduced one file's hash, and nothing else read it. The format knowledge now lives in the base pack (computer-forensics-base 1.5.0); the harness learns nothing about AD1.

- **The `ad1-items` recipe** (kickoff and derived) lists every item of a version 4 image in `members.tsv`.
  - archive-members' columns come first, so `catalog_search which=members` and `member:<gen>#<n>` read it the same way.
  - Then the times as dissect reads the keys (`mtime` modified 0x9, `atime` accessed 0x7, `btime` created 0x8), the MD5 and SHA-1 the image records, the SHA-256 of each file's content, and `check`: ok, mismatch, no-stored-hash or not-read. Each file is inflated to check them. Past the time limit, inflating stops and listing does not.
  - `locator` (`ad1:item=<address>`) names an item alike in a partial and a whole read; `n` after a break does not.
  - `attributes.tsv` keeps every metadata entry of every item, labelled; `image.json` keeps the headers and the data source name the paths are under.
  - Nothing is extracted. A segmented image is read across `.ad2`, `.ad3`, … beside the first. A further segment is named as read from its first. An encrypted image (`ADCRYPT`) and other versions are named and not read.
  - Every claim the image makes is bounded before it is followed: segments (4096), the chunk size (512 B to 16 MiB), a chunk's compressed length, a chunk table (by what the image can hold, read a batch at a time), a name (64 KiB), a metadata text (1 MiB), the tree's depth (1024), every chain to one visit an address. A damaged image is listed as far as it reads, each break named.
- **The `ad1_extract` tool** writes the tree out, each file inflated, hashed and checked, with a manifest (`ad1_extract.tsv`) of what went where.
  - It takes items by locator or `n`.
  - A name the file system cannot hold is written renamed, and the manifest keeps both.
  - A file whose content breaks, or whose write fails (a full disk), is kept as `.partial` and named; no truncated file keeps its own name.
  - In a job it writes only inside `$OUT`. Run as a job, its files are sealed, and the derived catalogue takes an archive or a disk image inside in turn: extraction stays the agents', in jobs (ADR 0010).
- `file_type` names an AD1 segment (`.ad1` to `.ad<n>`) and an encrypted AD1 by their first bytes. The `evidence/imaging` and `evidence/collections` skills say what an AD1 image is and how to work it, with dissect's `target-query` as a second reader.
- Both use Python's standard library alone, so no image changes. They run in the job image the run picks for the base pack (`images/recipe.py job-profiles`). Images built before record the pack as 1.4.1, and the kickoff says so (`image_fit`) until they are built again.
- Tests:
  - `tests/ad1-pack.test.ts` builds its synthetic AD1 images in code. They mirror the reader's own assumptions.
  - So the suite also reads one real FTK Imager image, 2 KB of test data from Fox-IT's dissect.evidence (AGPL-3.0, `tests/fixtures/ad1/`, named in NOTICE).
  - It covers detect, the listing, the time keys, damaged and hostile images, segments and locators, the time limit, the tool's names and failed writes, the census, and the derived chain from an AD1 a job makes to the zip inside it.

### Added: supplying a tool to a running run, and a job that says it could not execute a program

A live run asked the operator for programs no image held. `swarm.sh material add` was the only way to hand one over: it sealed the file, but said nothing of where it came from or how it was built, and the two jobs that tried to run it in place failed with `exit 126` and with `exit 127: a program it runs is not in its image` before a seat found the way (a copy in an executable temporary directory inside the job).

- **`swarm.sh tool-supply <run> add PATH --why W --source TEXT [--built TEXT] [--sha256 HEX]... [--for R-n|L-n]...`**, and `tool-supply <run> list`.
  - A tool is material: sealed as `import:mat-<n>`, class `operator_supplied` (never evidence), so the case policy's rules for material are its rules. Every preset admits it; a policy that says `operator_supplied=none` refuses it before anything is sealed, because nothing recorded on its output could be kept.
  - It adds what only the operator knows, in `material.json` and in the ledger entry's provenance (`provenance.tool`, in the chained core): where it came from and how it was built (the operator's statement, recorded whole, refused rather than cut past 4000 characters), the hashes the operator checked (each must be one of the supplied files' sha256, else nothing is sealed), and the requests and leads it is for (each must exist; neither is closed by it).
  - The board post tells the seats that the harness vouches for the bytes only, to test the tool on input whose answer they know, and how to run it: a job declares it as an input and copies it, and every library it loads, into an executable temporary directory inside the job.
  - A directory is sealed whole and read by every seat: the reply lists its files and a hidden file or directory in it (`.env`, `.git`, `.netrc`) is refused. A path that holds the run is refused for every addition.
  - The harness names no program and knows no format. A hub started by an older harness takes the act as plain material; the command line holds the policy's rule, the statements, the hidden-file refusal and the hashes itself first, and the reply warns that the source, build and `--for` were not recorded.
- **A job that could not execute a program says so, by where the program stands.** `scripts/job-exec-refused.ts` reads a failed job for the shell's exit 126 (with the shell's own line that names the program, from stdout, stderr or a stderr file it kept), for the dynamic loader's `failed to map segment from shared object` at any status, and, at another status, for a `Permission denied` on an existing file under a directory a worker mounts read-only. A `Permission denied` anywhere else at another status is left alone, since nothing in the line tells a program that could not be run from a file that could not be written. The reason names the path and where the line is, and then:
  - a supplied program (`store/imports/mat-<n>/`): a copy in an executable temporary directory inside the job;
  - evidence (`inputs/`, `work/extracted/`, `work/quarantine/`, an evidence import): evidence is read, never run, so ask the operator for a program with `swarm.sh tool-supply` or reimplement the step, as the contract asks for code recovered from evidence;
  - anywhere else: the rule first, the copy only for a program the operator supplied;
  - the shell's other reasons for 126 (a file built for another machine, a missing interpreter, a directory): its own line, and no copy.

  It is read before `program_missing` and `write_refused`: the loader's exit 127 is no program missing from the image, and a sealed file's `Permission denied` is no refused write. Recorded as `exec_refused` on the job and `job_exec_refused` on the journal.
- The worker prompt says the same in a short paragraph, evidence rule included.

### Changed: the stop proposal waits for the minutes, not for a burst of jobs

The diminishing-returns proposal fired on 20 committed jobs or 30 minutes with nothing yielded. On the 45 recorded runs with ten jobs or more, it proposed 27 times; 26 came on a burst of 20 jobs in one to eight minutes, and every one of those was followed by a yield, 25 within ten minutes. The one stretch that never yielded again had no job, and the minutes caught it. A stop is now proposed after 30 minutes with nothing yielded (`SWARM_YIELD_MINUTES`); `SWARM_YIELD_JOBS=N` adds the job count back, off by default. It is still never a vote and never a stop. See [ADR 0013](docs/adr/0013-a-negative-is-bounded-and-a-cap-pauses.md), "The stop proposal's window".

### Changed: a resume refuses a question it cannot admit, before anything moves

`swarm.sh resume --question … --as operator` on an install where nobody is enrolled as `operator` used to move the run's end aside, record the resume and start the continuation, and only then warn that the question was not admitted: the run went on without the question it was resumed for. Each question is now checked first, as its admission would check it (`questions-cli.ts add --dry-run`), and one the register would refuse refuses the resume with nothing changed, naming why. `--skip-refused-questions` resumes without it and says so. See [ADR 0013](docs/adr/0013-a-negative-is-bounded-and-a-cap-pauses.md), "A resume refuses a question it cannot admit".

### Added: a question that must be established

On a flag-only challenge under `--stop operator`, the one question's answer was partial on a reviewed finding, which is a disposition under the bar. The coordinator's done ended the run examination-limited after 23 minutes, without the flag; the operator had to resume it and ask again by hand.

- **The requirement.** A question can now be required to be established. For it, partial, not determinable, a bounded negative short of the stronger bar and out of scope do not end the run, under any stop policy. It ends established (or with its premise shown not to hold, or by a bounded negative under the stronger bar), by the operator's acceptance of its limits, or withdrawn.
- **Who says so.** The goal, in a `## Must establish` section or `must_establish:` in its metadata block (`[1, 3]`); the kickoff says which questions are required and warns of a name the goal does not number, or of a key that names nothing (a list's items may be indented or not; a list beside the goal's own section is merged into it). The operator or an examiner, with `question add --must-establish` or `question amend Q-n --expect-rev N --must-establish`. Never an agent; never a background question.
- **The way out stays on the record.** `question accept` disposes it as it disposes any question; `question amend --no-must-establish --why W` releases the requirement, and the register keeps who released it and why.
- **Where it shows.** The answers check gives such a question no disposition unless it answered it, the finish gate names the requirement first among what blocks it, the done's refusal gives its ways instead of the negative path, readiness holds it, and every seat's header names it until it is established. `questions/questions.md`, `question list|show` and the agents' `questions` view say who required or released it.
- **Measured.** Five new contract fixtures (`must-establish-partial`, `-not-determinable`, `-accepted`, `-released`, `-established`). The replay impact line against main reads every other fixture the same. `docs/rules.md` does not change: no ledger rule changed.

See [ADR 0013](docs/adr/0013-a-negative-is-bounded-and-a-cap-pauses.md), "A question that must be established".

### Changed: Pi 0.87.1, on the host and in the VMs

Pi moves from 0.87.0 to 0.87.1 in both places it is pinned: `package.json` (host-mode seats, the tests) and `images/base.Dockerfile` (`PI_VERSION`, every VM seat). 0.87.1:
- adds GPT-6 Sol and GPT-6 Luna for OpenAI Codex subscriptions and API keys;
- adds Claude Opus 5.5;
- fixes split-turn compaction summaries that Claude Fable 5.1 refused.

A base image built before this change still runs 0.87.0 until it is built again.

Dependabot now leaves Pi and `microsandbox` alone. Both are moved by hand: Pi in its two places together, and `microsandbox` only after the VM isolation is measured again. 0.7.3 turned on a strict hostname policy by default, under which a VM reached none of its allowed hosts in CI.

### Added: kickoff goldens

`tests/kickoff-goldens.test.sh` compares what `swarm.sh start --no-start` writes for three goals with `tests/fixtures/kickoff/`:
- the contract and the system prompt;
- the budget, the team and the case policy;
- the inputs manifest and the questions.

The machine and the moment are written as placeholders. A change to the kickoff fails it until `GOLDENS=update` writes the files again, so the change shows as a readable diff of what the agents will read. With it, the refactoring plan's steps are done: the protocol split into modules, the inputs manifest and the contract in TypeScript, the rule register, the replay impact line, and these goldens.

### Added: the rule register and a pull request's replay impact line

The first impact tools of the refactoring plan, for reading what a change reaches before reading the code.

- **The rule register** (`docs/rules.md`, generated by `scripts/rules.ts --write`). It lists every coded rule of the ledger: the defects that hold the finish line, the warnings that hold nothing, and the review caps. For each rule it gives the functions that raise it, the design sections that state it (the ADRs and `docs/protocol.md`), and the tests and contract fixtures that exercise it.
  - `tests/rules-register.test.ts` fails when the file is stale, or when a rule has no test or fixture, no design or no place it is raised. A change to a rule therefore shows in the file's diff.
  - Filling the gaps it found added `docs/protocol.md`, "The codes the answers check names", for the seven oldest defect codes, and rule tests named by code under `tests/rules/` for four rules nothing named: `no_answer`, `premise_revised`, `premise_withdrawn` and `derivation_unverified`.
- **The replay impact line** (`scripts/replay-impact.ts <base>`). It replays every contract fixture under a base commit and under this checkout and names each difference.
  - CI runs it on every pull request against its base and writes the table to the job's summary.
  - A difference is information, never a failure.

### Added: a part at the limit of the evidence; a locator is not coverage; an honest under-claim count

The claims round showed that complete answers stayed partial over residuals
the evidence cannot settle. Reviewers never used `not_asked`, so its warning
never fired. It also showed a decoy value that is in the allocated bytes
attested established on a verified locator, while the true value sat in slack.
Claude, Fable and Astra reviewed the options, and the owner chose these.

- **Limited parts.** An answer's part can be `limited`: the question asks it, and the evidence in scope cannot settle it.
  - `limited_by` names what shows that: the coverage record for the question, or a limitation whose reason is unavailable or excluded.
  - A limited part keeps the answer partial, as an open part does. The report, the console and `swarm.sh metrics` ("Limited parts") say it is beyond the evidence rather than open to more work, and whether another seat reviewed what shows it.
  - A review weighs it with `at_limit`. A limitation that says the evidence is gone now takes a negative's review.
  - As first built, a limited part could lift an answer to established once its bound was reviewed. The branch's c10 runs recorded the case's hardest step "limited" and the answer established at high confidence while its words said the step could not be done. The label is now never lifted (ADR 0013, amended).
- **A locator is not coverage.** An established attest that locates a value
  is recorded best_candidate (`rival_area_uncovered`) until, for each input
  the located object was read from, a coverage record for the question:
  - names that input;
  - says every area searched or not_applicable;
  - cites a job over the input.

  A located object that traces to no input, and a partial answer, are not
  held. The review prompt asks where a rival value would live. `swarm.sh
  metrics` ("Rival areas") counts the caps and each area's not_applicable.
- **Calibration.** The truth names each question's parts and the facts that
  settle each. Regenerating with the same seed keeps the inputs and the goal
  byte for byte. `scripts/calibrate.ts` adds:
  - "Unnecessary partial": every part the evidence settles is settled in the
    answer's support, never in a limitation;
  - "False established";
  - "Limited parts".

  The old line is kept as the proxy.
- **Replay.** Contract fixtures `limited-part-partial` and
  `rival-area-uncovered` hold the two rules. Replayed over the older
  `review-source-first` history, the rival-area rule would cap two of its
  established attests; nothing else reads differently.

### Fixed: a store sweep recorded under older rules is read again under the current ones

The calibration run sd0e59d, stopped on the harness before the echoes below
and resumed on the one that made them, kept its three `sweep_hits` holds (on
E-111, E-118 and E-129): the gate reads each coverage record's latest sweep
line, those lines were written under the older identity rule, and nothing
read them again. Now (ADR 0013, "Re-reading after a rules change"):

- **A version on each line.** Every coverage record's sweep line names the
  version of the sweep's rules it was written under (`rules`;
  `SWEEP_RULE_CHANGES` says what each version changed and whether a line from
  before it can be read again from what it recorded). A line with none is
  older than any versioned one.
- **Read again when the hub starts** (a kickoff or a resume): each record
  whose latest line is older than the current rules gets one line on the
  sweeps' chain with `reread: {from_version, reason: "rules changed", of, at,
  how}`, its hits sorted anew from what the line recorded (the logic of
  `replay --resweep`, nothing searched, the search's own times kept) or,
  where a change needs bytes the line did not record, its record searched
  again within the sweep's budget. A line under the current rules is left
  alone.
- **Said**: a `sweep_reread` line on the trace, and one board post with how
  many records were read again and which of the gate's sweep holds changed.
  The sweep's words say a line was read again, from which version and how.
- **Also at the answers check and the finish gate**, as a step of
  `reconcileSweeps`, idempotent: a host run with no hub is covered, and a
  replay's evaluation reads a copy's older lines again too
  (`store_sweeps.reread`).
- **Chains**: the lines are appended, the chain verifies, and a custody
  verdict taken before holds as a prefix.
- **Measured**: sd0e59d replayed as of its resume, 1666851 against this
  harness: the answers check reads its 20 recorded sweeps again (in 11 the
  hits move, 106 becoming 67, with 13 echoes), the three holds clear, and
  questions 2, 5 and 6 take the dispositions their answers claim.

### Fixed: the store sweep reads a kept output and its sealed import as one object, and names echoes

On the calibration run sd0e59d the store sweep held three negatives
(`sweep_hits`, questions 2, 5 and 6) on hits in whole outputs the harness had
kept under `tool-output/`. The seats sealed each file and named the import in
revised coverage records, as the fix said, and the hits held on for two done
calls and more than half an hour: the sweep knew the import by its manifest's
sha256 and the kept file by its inode, so the two were separate objects. Now
(ADR 0013, "Echoes: authored, not derived"):

- **One object under several names.** A kept output or a job's log is known
  by its content when another object has its size (hashed once, cached): a
  kept output and the import it was sealed as are one object, and a record
  that names either names both.
- **Echoes.** A hit in an object made from the run's own words is named on
  the sweep's line (`echoes`, each with its `origins`: what made every name
  of the object, and why) and holds nothing: a command that read only the
  run's registers and harness files (a dump of the ledger, which holds every
  `looked_for` string; `RUN_REGISTERS`), a summary the harness kept from a
  seat's own words outside any tool call (a compaction; `HARNESS_KEEPERS`),
  or a search whose own words name the string and that read nothing but
  what is accounted for. The same principle as the network's evidence link
  (ADR 0012): what a command's own words name is authored, not derived
  (`jobOwnWords`, now one helper for both).
- **Accounted for** is a register, or an object the record names in which the
  same sweep found the same string. An output made only from such objects,
  whose maker does not name the string, is said among the named hits with
  what it read. A maker that read an input (which the sweep never reads, so
  a derivation of one is the only place its rows show), anything else of the
  run, or paths that cannot be told (a command naming none, a job that saw
  everything or reached the network) leaves the hit holding: a search for
  the string over evidence the record does not name is the miss the sweep
  is for.
- **Makers from the record, not a parser.** A kept output's maker is the
  trace line that kept it (attributed to its seat, on the chain:
  `keptOutputOrigins`), and what it read the run paths its words name
  (`runPathsIn`); a job's is its record and its declared inputs; a sealed
  import is made as the output it sealed was.
- **Shown** in the sweep's words (`ledger.md`, the review offer, which asks
  whether each echo is only the run's own words, the report's store sweeps)
  and the metrics (`sweeps.echoes`). A line from before has no `echoes` and
  reads as it did; `unexaminedHits` reads each earlier sweep by its latest
  line, as the gate does.
- **Measured**: `swarm.sh replay --resweep` reads each recorded sweep again
  with this checkout's rules and adds the result as a synthetic line on the
  copy's chain, nothing searched again. On sd0e59d, of 106 recorded hits 67
  still hold, 26 move to the named hits (the sealed imports the records
  named) and 13 are echoes (8 a ledger dump, 3 a compaction summary, 2 jobs
  that searched named objects the sweep found the string in); the three
  `sweep_hits` holds clear, and the three questions take the dispositions
  their answers claim.

### Added: a question's premise is tested first

In a synthetic calibration case a question asks about an event that did not
happen; the truth is `premise_not_supported`. Round after round the swarm
answered it partial, a planted clue that fits the question's frame in the
headline. Now (ADR 0011, "What a question presumes"):

- **What a question presumes** is on the register: `presumes` said by its
  asker (`swarm.sh question <run> add|amend --presumes`, the console's
  question form, `question_open`), by the goal (a front-matter `presumes:`
  list the kickoff carries into a `## Presumptions` section), or by an agent
  with a clarification (`question_ask(…, presumes)`, once, never over a
  recorded word); a person's question presumes the proposition its framing
  states.
- **The review tests the premise** against the fixed rival "the question's
  premise is not supported": `answer_review.premise_tested {outcome, refs}`,
  never resting on the answer under review. The answer may carry the test
  itself (`premise_tested`). Both are present only when given: an old entry
  or review hashes as it did.
- **An established attest without it is recorded best_candidate**, on an
  answer that claims established to a material question that presumes an
  event (the source-first review's code `premise_untested`), and the reply
  says how to fix it. **A partial answer without it is warned**
  (`premise_untested`) at its record, the attest's reply and finish status,
  never held.
- **The prompt and the tools** (the worker prompt, record, attest,
  question_open, question_ask) say: before answering a question that
  presumes an event, test whether the event happened; if the evidence does
  not support it, the answer is premise_not_supported; a clue that fits the
  question's frame is a candidate to test against that rival, not an answer.
- **The calibration generator** (version 3) frames every question's
  presumption from its words alone: each that asks which, when or how of an
  event presumes it, whatever the truth, so a presumption says nothing of
  which premise is false.
- **Shown** in questions.md, `question show`, the agents' list, the
  question's post, the console's card and the report (the §2 chain and each
  answer's premise tests, or that none is on the record).
- **Measured**: `swarm.sh replay --presumes Q[,Q…]` presumes the named
  questions in the copy and says what the rule would have warned and
  capped. s85febc and s704e4b replay with no difference against main; with
  the generator's presumptions, s85febc's questions 3 and 7 would have been
  warned, and nothing else changes. Fixtures `premise-untested-capped`,
  `premise-untested-warned`, `premise-tested-not-supported`. The calibration
  scorer says, for each question that expects `premise_not_supported`, what
  its answer recorded and whether the answer and its reviews carried a
  premise test (`summary.premise`, codes and counts only).

### Changed: the report shows each answer's parts, and the metrics count the under-claimed

Complete answers were still recorded partial at medium confidence, their
open parts often what the question does not ask: the score did not suffer,
but a reader takes "partial" to mean "not fully known". Presentation only
(ADR 0013, "What the report shows of an answer's parts"):

- **Each answer's parts, where it is rendered**: the report's §5 answer (a
  review's `not_asked` mark now beside the part it marks, in the parts
  table), its §2 chain (the parts listed under the result) and its §1 table,
  the console's question view, `questions/questions.md`, and the release,
  whose report is the same render.
- **A partial answer leads with a plain line**: "Asked parts: 3 of 3
  established. Open: 1, which a review marks as not asked." When every
  asked part is established, the report says so beside the partial label,
  which is unchanged. An answer without parts renders as before.
- **The under-claiming count**: `swarm.sh metrics` counts the partial
  answers whose asked parts are all established (asked: not marked
  `not_asked` by a review), and `--compare` sets each run's count side by
  side and flags the question. On s85febc and s704e4b it is 0 of 6: neither
  run's reviews marked a part not asked.
- **Measured on the truth too**: the calibration scorer
  (`scripts/calibrate.ts`) gives "Under-claimed: k of n present questions
  answered partial with every present fact found", each with its label and
  confidence, in its summary and its score JSON (`summary.under_claimed`);
  where the truth is known it sees what no review marked.

### Fixed: the findings of an independent review of the limits branch

Fable's review of the branch (one P1, four P2, ten P3) found one place
where the readers of the finish disagreed, and several where a rule held,
capped or waited beyond what was decided. Each fix has its test; the
contract fixtures gained two cases.

- **An acceptance excuses the same everywhere (P1).** The answers check
  dropped only a partial sweep, stale evidence and a pending preparation on
  an accepted question, while readiness and the accept act's `still_held`
  excuse every defect but the negative bar's: an accepted question held
  `premise_inconsistent` or `no_critic_act` was clear in readiness and
  refused by the check's verdict. The check now reads `acceptanceExcuses`
  alone. Replay counts such a question held through the check; fixtures
  `accepted-excused` and `accepted-negative-held`.
- **The operator's ruling on a premise releases its conflict.** A premise
  withdrawn, or a revision revised since, holds nothing; the answers citing
  it are warned (`premise_withdrawn`, `premise_revised`). On a question not
  material the conflict is a warning.
- **A locator vouches for what the answer rests on.** Its value must be
  among the words of the answer or of an entry it reaches (its support,
  and what those cite), else `locator_unverified`.
- **No locator or derivation is warned, not capped.** The approved rule
  capped a missing discriminator and a locator that does not verify; the
  third cap is now the warning `no_locator_or_derivation`, and the metrics
  count each established answer recorded partial after a capped attest
  (`reversals.partial_after_cap`).
- **The reverse sweep runs after the addition.** An evidence addition
  commits and answers at once; the sweep runs in the hub's background or
  as a detached step (`scripts/reverse-sweep.ts`), a pass at a time within
  its own budget (`SWARM_REVERSE_SWEEP_MAX_SEC`, 120;
  `SWARM_REVERSE_SWEEP_MAX_BYTES`, 2 GiB), what a pass leaves searched by
  the next, each pass posted when it completes.
- **Only a part the question asks is open.** On c10 run s704e4b three
  complete answers stood partial on parts the question does not ask. The
  record tool, its refusal and the prompt say an open part is a part the
  question asks, and the rest are limitations; a review marks such a part
  `not_asked: true`, which caps nothing, and a partial answer whose every
  other part is established is warned (`partial_all_parts_established`) to
  be recorded established with it among its limitations. Never a promotion.
  Fixture `parts-not-asked`.
- **Smaller fixes.** A late delta clears stale evidence only on the entry
  that examined the import, under review, and the report says irrelevant,
  inconclusive and adds_part deltas; a preparation lead closed without a
  run is its decline, a hold's fix never names a closed lead, and the
  harness closes only a preparation lead no seat holds; evidence code
  says a seat's own job output apart, a JSON `require` is not flagged, and
  the chip reads "may have run"; `lead_findings_uncited` ignores
  `duplicates` and `derived_from` rels; a discriminator may not rest on the
  answer, nor only on what it cites; a batch whose items were all resolved
  already records nothing and says so; the metrics count warning deliveries
  and review packets.

### Added: a command or job that runs code recovered from the evidence is flagged

On the c10 run sd9645b one seat's seven password-test jobs (worker VMs,
Node) evaluated a crypto library recovered from a browser cache blob, an
earlier job's sealed output, with `vm.runInContext` and `runInThisContext`;
the run disclosed it itself. Nothing stopped it: no-exec stops a file
executing, not an interpreter reading one, and a job's output under `store/`
is not no-exec at all. Now:

- **Flagged from the command's words** (`extensions/evidence-code.ts`): an
  interpreter, a shell or a browser given a file from the evidence, an
  extraction or a job's output as its script (or on its stdin, or through a
  pipe), and a construct that evaluates code (`eval`, `exec`, `compile`,
  `new Function`, `vm.runIn…`, `runpy`, `importlib`, `require`) given such
  a path or a name bound to what was read from one. Never refused. On the
  local runs replayed it names those seven jobs of sd9645b and nothing on
  s10d40e, s7827e1 or sa2f2f2.
- **Where it is said**: the `bash` result's note and an `evidence_code`
  trace event; the `job_run` reply's `evidence_code` and its trace row; the
  report's job record ("evidence code may have run") and a list in Appendix B.
- **The prompt, the contract and the kickoff** say that never running
  recovered code covers every way of running it, that no-exec does not stop
  an interpreter and a job's output is not no-exec, and what to do instead:
  reimplement it or use a trusted program, or ask the operator first.

### Added: a goal with a brief and no premises is warned about, and the shipped goals designate theirs

On c10 run sd9645b 4 of the 10 parts its answers held open were attribution
hedges ("did this person do it") on what the case brief states as given: the
goal designated no premises, so the premise register never acted. Now (ADR
0011, "Premises"):

- **The kickoff warns** (and `swarm.sh start --check` with it) when a goal
  has a case brief (a heading naming a brief, a scenario, a background or a
  situation, a `--sections-in` brief, or words naming one) and designates no
  premises: its answers will hold the brief's givens open. The warning says
  how to designate them: a `premises:` list in the front matter, or
  `swarm.sh question <run> premise add`. It never refuses.
- **The shipped goals designate theirs.** Every case goal under
  `prompts/goals/` opens with a `premises:` list of what its own text states
  as given (whose devices these are, who the subject is, the stated
  setting), each closely restating the goal's sentence with its scope, none
  an answer or something a question tests: belkactf6-bogus-bill 3, c02 1,
  c03 2, c04 1, c05 2, c06 2, c07 2, c08 2, c09 2, c10 2, c11 2, l01 2, l02
  1, l03 2, m01 2, u01 2, web-server-case 2. hello, pelican and
  analyse-inputs have no case and none.
- **The calibration generator** writes its cases' premises from each brief
  alone (usb-departure 3, web-intrusion 2, invoice-fraud 3), never from the
  truth; generator version 2.

### Changed: a review of the report carries over while what it covered is unchanged

The c10 run sd9645b's finish took about 49 minutes over three versions of
the report: 19 acks, 10 of them a seat's no-objection review given again to
a later version, since an ack was bound to the whole report's digest and
every version reset every seat's. And 15 of the 33 posts resolved as late
items were a seat's own ack announced on the board. Now (ADR 0015, "A
review carries over"):

- **An ack binds sections.** `finish ack` takes `sections` (a heading's
  number or words; none is the whole report) and records each section it
  covered with its digest. The sections are the report's `## ` headings as
  the report body reads them, numbered ones keyed by their number.
- **Only what changed is asked again.** When the report is published again,
  a review whose sections are unchanged carries over; one whose sections
  changed is asked about those alone; a review of the whole report is asked
  about a section added or removed. A `carry` event on `leads/finish.jsonl`
  records which reviews stand and which are asked again, and on what.
  Prepare's reply, `finish status` and the headers say whom to ask and on
  which sections, and tell a seat whose review stands not to ack it again.
- **What stays.** Late items keep their per-item rule, and the final
  transaction is unchanged. An objector's later ack answers its objection
  only when it reviews what the objection named, so an objection to one
  section stands through its objector's review of another.
- **The prompt** says never to ack again a review that stands, and never to
  announce an ack on the board.
- **Replay** estimates the rule on a run's recorded acks (`reviews`). On
  sd9645b: the closing section changed in every version, so none of the 10
  re-reviews, read as whole-report reviews, would have carried over, and no
  review round is avoided; they would have been asked about 23 sections
  instead of 80. Had each seat named its own questions' sections, 6 of the
  10 would not have been asked.

### Fixed: a program's log goes under the job's output, and a job that failed on a refused write says so

On the Belka validation run (s7827e1) the new disk-timeline recipe failed
with exit 1: log2timeline writes its log (`log2timeline-<timestamp>.log.gz`)
to its working directory unless told otherwise, and a job starts in the
run's directory, read-only in its worker (`OSError: [Errno 30] Read-only
file system`). psort failed on its own log the same way, and so did two
agents' own log2timeline jobs; each said only "exit 1". The recipe had only
met stand-ins.

- **The packs.** disk-timeline 1.0.1 gives log2timeline and psort their
  logs under `--out` (`--logfile`, which Plaso's tools have taken with
  `--log_file` and `--log-file` as aliases since at least 20180818; the
  images install 20260720) and runs each step there. timeline_super gives
  both its logs in `out_dir` (an agent's VM has the run read-only too) and
  names them. sigma_hunt gives Zircolite `--logfile` in `out_dir` and runs
  Hayabusa there, since no option moves its `./logs/errorlog-<time>.log`;
  both name their logs. No other recipe or tool runs a program that writes
  to its working directory as it is called. computer-forensics-base 1.4.1,
  windows-forensics 1.3.3. The stand-ins write each log where the real
  program does, fail when that is read-only, and the tests run the recipe
  and the tools from a read-only directory.
- **The job's reason.** A job that ends non-zero is read for a refused
  write (`scripts/job-write-refused.ts`): its stdout, its stderr and every
  stderr file it kept in `$OUT`, each whole. A line saying `Read-only file
  system`, or `Permission denied` on a path outside `$OUT`, makes its reason
  `exit N: a write outside $OUT was refused (…)`, with the path whole, where
  the line is, how many there are, that the working directory and the run
  are read-only in a worker, `$OUT` by name and path, and to point the
  program's log, temp or output options there or `cd "$OUT"`. On the job
  record (`write_refused`), the journal (`job_write_refused`, and
  `job_finished`'s reason), the requester's post and `job_run`'s and
  `job_status`'s answer. On the error text alone: no program is named.
- **The prompt** says a job runs with the run read-only, so a program's log
  or temp files are given a path under `$OUT`, or it runs after `cd "$OUT"`.

### Added: the premise register, and claim and open-part rows

A case brief supplies things several questions share (whose device it is,
who the subject is), and until now they were words in reasoning: one answer
could take a premise for granted while another's findings contradicted it,
with nothing on the record, and a partial answer could hold a premise open as
if it were a part to prove. "Partial" was one word for a whole answer, and a
review's parts named no part of the answer, so a part the answer never
listed could not be seen to be missing. Now (ADR 0011, "Premises"; ADR 0013,
"Claim and open-part rows"):

- **Premises on the question chain.** A premise is a `P-n`, an event on
  `questions/questions.jsonl` (`premise_add`, `premise_propose`,
  `premise_revise`, `premise_admit`, `premise_withdraw`): its words
  verbatim, where they stand, its authority, its scope (entities, time
  ranges, the questions it applies to), its revisions and its class, sealed,
  released and packaged with the register. Only the operator's premises are
  givens: the goal's `## Premises` section or front-matter `premises:`
  (seeded at the kickoff, a trailing `[scope: …]` read as its scope),
  `swarm.sh question <run> premise add|revise|admit|withdraw`, or the
  console's Questions tab. A given is not proved again and is never an open
  part; a supplied assertion is assumed as asserted; an agent's proposal
  (`premise_propose`, a new tool) is a proposition under test, assumed only
  conditionally, until the operator admits it.
- **Answers cite them.** `premises: [{id, rev, stance: assumed | supported
  | contradicted | unresolved, refs?, conditional?, scope?}]`, checked under
  the registers' lock (the revision read, a proposition under test only
  conditional, a premise scoped to named questions only there, a narrowed
  scope inside the premise's, `supported` on a standing finding), in the
  ledger's hashed core only when present.
- **The gate `premise_inconsistent`** holds both questions while standing
  answers assume and contradict one premise revision over scopes that
  overlap, and the contradiction names no standing finding that rebuts it.
  The ways out are all on the record and none forces either side: revise an
  answer; name the rebutting finding, which takes the premise to the
  operator as a request of kind `premise` (one per revision, closed when the
  premise is revised or withdrawn, or answered on the request) and warns the
  answer that assumes it (`premise_disputed`); narrow a scope; or answer
  conditionally ("assuming P-n"). Uncertainty holds nothing. An answer citing
  an earlier revision or a withdrawn premise is warned (`premise_revised`,
  `premise_withdrawn`).
- **Claim and open-part rows.** `parts: [{id, part, status: established |
  open, refs, open_by?}]` on an answer, against the verbatim revision it
  answers: an open part names what bounds it, an acquisition ask `R-n`, a
  route `L-n`, or a limitation or coverage record `E-n`; a premise never.
  A partial answer with no open part is refused ("record it established or
  name what is open"), an established one with an open part too. A review's
  parts name the answer's rows by `id` and may add one it leaves out
  (`missing`): that caps an established review as a part not held does, and
  is warned of (`part_omitted`) until the answer is recorded again with it.
  Review parts without ids and round 14's `declared_open` read as before.
- **Where they show.** The report lists the premises the examination took
  and, in each answer, its rows and how it stands on each premise; the
  console's Questions tab shows premises (with the operator's acts) and each
  answer's rows; `questions.md`, `ledger.md`, `swarm.sh question <run>
  premise list|show` and the agents' `questions` view `premises` read them;
  the header lists the premises that stand, and every premise act is told
  once to every seat. The prompt and the record, attest and questions tools
  say how to cite a premise and name an open part.
- **Replay** codes the new warnings, and holds a run whose answers check
  holds a question it reads as answered (as the finish line does). Contract
  fixtures premise-given, premise-admitted, premise-scopes, premise-held,
  premise-rebutted (a custody seal taken while it held verifies as a prefix
  after it), premise-conditional and parts-omitted, their expectations
  written from the ADRs; every fixture recorded before reads the same under
  be4e6a3 and this checkout; tests/premises.test.ts.

Replayed values-free (`swarm.sh replay --compare <be4e6a3> <this
checkout>`): s5764c4 (Belka), sa2f2f2 and sb1b3c8 read the same under both
harnesses, every question's disposition, defects, warnings, readiness and
report; their partial answers, recorded without rows, are disposed as
before. The generator's older cases were updated so that they can be
recorded again under the rows rule; their committed histories were kept.

### Added: a source-first review with checked locators, and late evidence weighed with a delta

On Belka a wrong value was attested established by three seats, each
naming an alternative: the rule was met and the answer was wrong. On the
calibration run sb1b3c8 the evidence that settled a question came late,
every stale answer was examined again on a record that named it and
reviewed, and the late fact was still missed. Now (ADR 0015, "A
source-first review"; ADR 0013, "Late evidence: the reverse sweep and the
delta"):

- **Review source-first.** A material negative's review offer leads with
  the question as asked (its revision, its words whole), its scope and the
  original sources its answer's coverage and cited entries lead back to;
  the answer under review is linked by its seq, never quoted first. The
  attest tool, its guidance, the prompt and the critic's fix say the same
  for the attests the finish line asks for. A review goes first to a seat
  of another model family than the work's (team.json's model per seat): a
  preference, never a requirement.
- **`answer_review` gains** `discriminator {rival, test, favours_if,
  outcome, refs}`, `reproduced_at [{ref, offset, length?, value?}]` and
  `derivation {job, inputs}`, each in the hashed record only when given (an
  older review hashes as it did). The hub reads each locator's bytes at its
  offset, in UTF-8 and UTF-16LE (bounded reads, never a scan; it says where
  the value is when it is near), and holds a derivation to a sealed job
  that ran to its end over what it declared.
- **The cap.** An established attest of an answer that claims established,
  on a material question, with no discriminator that counts, a locator
  that does not verify, a derivation that does not resolve, or neither a
  locator nor a derivation, is recorded best_candidate, each reason in
  `capped`, and the reply says how to fix each; the seat's later review
  that meets them is its review. A partial answer's review is checked and
  never capped for it: partial stays a disposition.
- **The reverse sweep.** At `evidence add` the import's files, and only
  they, are searched for the `looked_for` strings of every coverage record
  standing at the addition, each hit bound to the records it bears on, on
  `ledger/sweeps.jsonl` (a version 2 line, `of: "import"`, on the same
  chain). The hits go to the board post by question, to the words of each
  stale answer they bear on, and, on an answer the addition does not stale,
  to the warning `late_evidence_hits` at every point warnings are
  delivered. A hit never holds by itself.
- **The delta.** `evidence_stale` clears only when the answer, or the
  coverage it cites recorded since, cites an entry whose refs name the
  import's objects and that carries a delta: a `rel` to the question's
  answer of kind supports, contradicts, adds_part, irrelevant or
  inconclusive (the last three new, present-only in the core). The
  operator's acceptance after the addition still clears it.
- **Replay** counts, per run, the established attests the review rule would
  cap and why (codes only), and each addition's reverse sweep per question;
  `--reverse-sweep` gives an addition from before it the line this
  checkout's sweep would have written. Four contract fixtures: the delta
  clearing, the history from before it (held now, cleared under c34c6cb,
  replayed under both), the reverse sweep's hits delivered and not holding,
  and the review's caps; every older fixture reads the same under both
  harnesses but where the delta applies.

Replayed values-free: every established attest of an established answer
in s5764c4 (6), sa2f2f2 (2) and sb1b3c8 (3) would have been capped (no
discriminator; no locator or derivation); sb1b3c8's evidence came before
any coverage record, so its reverse sweep would have delivered nothing, and
under the delta its six examined answers are stale again.

### Added: a source's broad extraction, offered and on the record, before a negative on it

On the Belka runs four of five false negatives rested on a row no job had
ever produced: the phone's tar was inventoried at the kickoff (the mobile
pack's recipe "parses no artifact content") and then read narrowly, and the
whole-source parse the pack's own programs can do was nobody's work. Now
(ADR 0013, "A source's broad extraction before a negative on it"):

- **Recipes say what they prepare.** `purpose: inventory | broad_extraction`
  in `recipe.json`; a broad extraction names its `capability` and its
  `exclusions`, and one the job images cannot run says why (`unavailable`:
  no trigger, refused by name). pack.sh holds them to that. The shipped
  recipes are declared as they are: disk-volumes, archive-members,
  ios-filesystem, android-backup and static-binary inventory;
  memory-windows, linux-target and network-capture are broad extractions.
- **New recipes.** mobile-forensics `ios-ileapp` and `android-aleapp`
  (iLEAPP and ALEAPP over a whole iOS or Android full file-system tar or zip,
  every report kept, run by the kickoff); `android-backup-apps` (declared
  unavailable: nothing in the mobile image parses an adb backup's app tree
  as a whole, so its preparation is declined with that reason, not faked);
  computer-forensics-base `disk-timeline` (Plaso's log2timeline and a psort
  CSV over a whole disk image; hours on a large one, so offered, not run by
  itself). The programs are already in the images. Base pack 1.4.0, mobile
  1.2.0, linux, network and reverse-engineering 1.1.3.
- **The census** asks every broad extraction about every input and lists
  each that applies in `catalog/plan.json`'s `preparations`, the input's row
  and the README; it plans only the kickoff's. A detect pass never runs a
  broad extraction that is not `auto`, nor one that cannot run, and tells an
  agent that asked. The kickoff's queue says what it refused, and why.
- **Offers and receipts.** Each round the hub (`scripts/preparation.ts`)
  writes, once each, receipts on the store journal (`type: preparation`):
  planned, attempted, produced, partial, failed or declined, with the source's
  digest, the recipe and its version and sha256, the output manifest and the
  exclusions (the recipe's, then what this run of it did not cover). Every
  broad-extraction job has them, whoever asked. One not `auto` is offered as
  a lead of its own, one per source digest and capability, never when the
  same work is queued, running, sealed or recorded; a seat's close of it
  deferred, infeasible or needs_operator declines it with the seat's why, and
  the harness closes the lead once its extraction reached an outcome by any
  route. No new register: the journal is already chained, sealed and
  carried.
- **The hold, narrow.** `preparation_pending` holds a material negative that
  says the event did not happen, or whose coverage record is complete over
  a source, while that source's broad extraction is planned or attempted.
  Produced, partial, failed or declined releases it, and so does the
  operator's acceptance; a later run does not hold again. Every other
  material negative that reaches such a source (naming it, a member of its
  catalogue, or outputs made from it) while it has not produced is warned,
  `preparation_missing`, at every point warnings are delivered. A negative's
  review offer opens with the state of each source it rests on. The finish
  revision moves with each receipt; a run with none reads as before.
- **The prompt** says what a broad extraction is, what to do with its lead,
  the hold and the warning.
- **Replay** shows each source's preparation and the questions held or
  warned on it; `--prepare-as STATE` puts a synthetic receipt on each copy
  for every broad extraction this checkout's census finds applies to the
  run's own evidence (read in place). Replay counts an answer the check
  holds on its own defect as held by the finish line. Contract fixtures
  preparation-pending and preparation-failed-released;
  tests/preparation.test.ts.
- **Replayed on s5764c4 (Belka)**, values-free: two broad extractions apply,
  the mobile pack's over the iPhone tar (run by the kickoff) and the disk
  timeline over the laptop image (offered). With both attempted, one of its
  eight negatives is held (question 4, complete over the tar) and seven are
  warned (10 and 13 to 18); produced, none; failed, all eight warned.

### Added: `finish prepare`, and late items resolved in one batch

Every first done of s993d40, sa2f2f2 and s5764c4 was refused on items late
against the report (4, 5 and 15): only a done made the lease the late list
is read under, and the coordinator then resolved each item in a call of its
own. Now (ADR 0015, "Preparing the finish"):

- `finish prepare` takes the lease and the report's boundary exactly as a
  done does (a first lease to the report's publisher, a takeover of an
  unavailable holder, a report named anew), runs no goal check and writes
  no sentinel, and answers readiness and every late item, whole, with the
  lease's generation and the report's digest; a `prepare` event records
  it. Another seat's prepare is "not yours", quietly. A prepare again, a
  republished report and a takeover keep the earliest boundary. After a
  resume, the first prepare or done opens the new segment and carries every
  post still late by name (`segment`, `carried` on the lease).
- `finish resolve` with `items` ({post or ack, how: folded, where} or
  {post or ack, how: not_material, why}), `generation`, `digest` and a
  `key`: validated whole under the finish lock, one resolution event per
  item carrying the key, the generation and the digest. A stale generation
  or digest, or an item not late, refuses the batch with the exact stale
  fields and every id still unresolved, and records nothing; the same batch
  sent again under its key records nothing twice and says what is still
  late. The one-item form stays.
- The final transaction is unchanged: a veto, an objection or an evidence
  addition racing the done still holds the sentinel.
- The prompt and the `finish` and `done` descriptions say the order:
  draft, prepare, resolve in one call, invite acks, done. The done's late
  refusal, the header and the readiness post name the batch's generation
  and digest; `finish status`, `swarm.sh lead <run> list` and the report
  give the boundary, the segment and the last prepare.
- Metrics: a finish block (the first done and whether it was refused on
  late items, every late refusal, the finish tool's calls by act, the
  resolutions and batches, the tail from ready with every seat's tokens).
  Replay reads the prepares, the batches and the lease's segment.
- Contract fixtures prepared-batch-resolved, prepared-racing-veto,
  prepared-takeover and resume-carried; tests/finish-prepare.test.ts.
- Replayed, each run cut to its first done: a prepare there lists exactly
  the items that done was refused on; the finish line on the cut registers
  proceeds on sa2f2f2 only (the one refusal caused by late items alone). No
  post lands between a prepare and a batch in the coordinators' own
  measured times on s993d40 and s5764c4; on sa2f2f2 one lands before the
  batch's reply, which names it. First-done late refusals 3 to 0, or 1 if
  that post is left to refuse the done. Covering a late post by the
  report's reach was not built.

### Added: the warnings are delivered where the decision is made, and request guidance

The answers check's three warnings were said to the coordinator at the end
(the answers check, the finish gate, `finish status`), after the seats that
could act on them had moved on: on s993d40 the reviewers who held a partial
answer whole, and the seat that recorded an answer leaving out what its
question's leads had established, were told nothing when they decided. Now
(ADR 0013, "Warnings where the decision is made"):

- Each point asks the same gate over readiness's own inputs
  (`finish.ts` `warningsAt`) and says the warnings in the words `finish
  status` uses: the reply to the record that writes a question's answer
  (`warnings`; their codes on the trace as `warned`); a material negative's
  review offer, as it reaches its seat; the reply to an attest on the answer,
  on the coverage record a negative rests on, or on an entry a warning names;
  the reply to a lead's close or confirmation, for each question whose
  warnings the act changed; and `finish status`. None holds, none refuses.
- `lead_findings_uncited` covers what the record ties to a question outside
  its leads too: a finding or an event two seats hold that names the
  question in `answers`, or whose `rel` links it to an entry the answer
  cites; and one seat's that names the question when another question's
  standing answer relies on it (the record already rests a conclusion on
  it). One seat's that no answer relies on does not count. Each entry is
  listed with its tie, and the warning reads "answer #n (question:q) leaves
  out what the record ties to Q-q: …". Replayed: s993d40 4, 4, 1, 6, 2 and 9
  entries on its six questions (question 4's list holds the method
  established under question 6's leads that names question 4); sa2f2f2 4 on
  question 1 and 1 each on questions 4 and 6. Counting every finding a seat
  tags, tried first, warned 46 and 55.
- Request guidance: a question put to the operator says what observation
  would settle its question and what each possible answer changes (the
  prompt, `lead_close`, and the close's reply, `guidance`); a value read from
  an image is cited from the output of a job that read it, never from a
  transcription typed into a command (the prompt and `net_request`, as the
  network's refusal already said); under `more_evidence: no` nothing suggests
  an ask (verified, now a contract fixture).
- `swarm.sh replay --deliveries` reads, act by act, which warnings each point
  would have carried, on the registers as they stood at each act. Four
  contract fixtures hold the points to the ADR: `warnings-delivered`,
  `lead-findings-tied`, `lead-close-delivered` and `no-ceremonial-ask`.

### Added: replay, and the contract fixtures

A finished run's registers read again under a harness's finish rules, to
measure a rule change on recorded histories before a paid run is spent on it
(ADR 0017, "Measuring a rule change"). On the run s9722fa readiness and the
answers check read six partial answers two ways, and the case lost every
positive answer; nothing then could show that on the registers before the run.

- `swarm.sh replay <run>` (`scripts/replay.ts`) copies the run (a clone where
  the file system makes one; the evidence, the VMs and the seats' sessions left
  out, every link removed) and evaluates a checkout's answers check, finish
  gate, verdict, readiness, finish register, report standing and custody seals
  over the copy, each checkout in a process of its own, with no model call, no
  job and no VM. The run is never written: its registers are hashed before and
  after. It prints values-free (codes, ids, counts, the harness's own words);
  `--show-text` adds the lines that quote records. `--checkout PATH` evaluates
  another checkout; `--compare` sets the run's own harness (the hub's frozen
  copy, or the commit its registry records, extracted with `git archive`)
  against this one, or any two, and names every difference; `--stop-policy`
  evaluates the copy as though the run's policy were another.
- `tests/fixtures/contract/`: synthetic histories made through the harness's
  own acts, each with an `expect.json` written by hand from the ADRs: a partial
  disposed under every stop policy, an established claim held a best candidate,
  a negative nobody reviewed, evidence stale and cleared, sweep hits named and
  examined, a post late against the report, an objection racing the finish, a
  resumed run sealed twice, warnings and nothing else, and the c10 partial
  cascade. Under every fixture and stop policy readiness, the answers check and
  the gate agree on each disposition, a warning never holds, and every custody
  verdict verifies as a prefix. The c10 cascade is replayed under 3338e3c's
  harness, extracted from the history: its readiness holds the six partials as
  best candidates while the check disposes them; under this one all six are
  disposed and readiness is ready.

### Fixed: a case premise is not a reason to hold an answer partial, and an answer that leaves out what its question's leads established is warned of

On the run s993d40 (a CTF case of six questions) all six answers stood
partial. Two were complete answers whose only hedge was whether the person
the case brief names did it personally, which the brief states as given;
both were attested established by two reviewers while still labelled
partial. A third left out two methods the ledger already held as findings,
attested by another seat, under that question's leads. Now:

- The worker prompt and the `record` tool (an answer, its `result`) say
  what a premise is: what the case brief or the goal states as given (who
  the subject is, whose device it is, the scenario's facts) is a premise of
  the examination, not a part the answer must prove again. The answer names
  the premise it relies on in its reasoning or limitations ("rests on the
  case premise that …") and is established on the evidence for the rest; it
  is partial only for a part of the question it could not establish; when
  the evidence contradicts a premise, that is `premise_not_supported` or a
  finding, never a silent hedge. The `attest` tool's parts say a premise is
  not a part to hold open.
- Two warnings in the answers check, each a `WARN:` line, in its machine
  line's `warnings`, in the finish line's note and now in `finish status`
  (readiness carries the gate's warnings apart from its items): neither
  ever holds the finish. `partial_all_parts_established`: a partial answer
  every review of which holds every part it weighed established, one of
  them attesting it established; it asks the recorder to say which part is
  open or record the answer established. `lead_findings_uncited`: a
  standing finding or event, not disputed, attested by another seat or
  recorded by two, that the lead register recorded under a lead linked to
  the question (it interprets the lead's job, or a close or confirmation of
  the lead names it: `questionLeadEntries`, `extensions/leads.ts`), which
  the question's answer does not reach, directly or through the entries it
  cites (`answerReach`); every such entry is listed by `E-<seq>` with its
  leads, "established under Q-n's leads and not in its answer: cite them or
  say why they do not bear on it". Registers and refs only.
- `tests/case-premise.test.ts` and `tests/lead-findings-uncited.test.ts`.

### Fixed: only the collector writes the trace, and a deep runs directory no longer keeps its lines out

A Unix socket path takes at most 103 bytes on macOS and 107 on Linux. The
collector, the gate and the nudge broker bind from inside their directory,
but their clients dialled the full path, or one relative to wherever they
ran: under a deep `SWARM_RUNS_DIR` the kickoff's own line, the watchdogs'
and the operator's could not reach the collector, and on Linux the gate
could not forward a single pane's line. The shell's fallback then appended
a line to `events.jsonl` whenever the record was not chained yet, so a run
could begin with lines no one could vouch for, and a line appended between
its look at the tail and the collector's next write broke the chain.

- `scripts/trace-emit.mjs` dials the socket from inside its directory, and
  says why it failed: exit 1 when the collector could not be reached, 3 when
  it answered and refused the line. The gate forwards from the collector's
  directory; the operator CLI's harness lines (`emitHarnessLine`) go
  through `trace-emit.mjs` when even a relative path is too long.
- A line the collector does not take, for any reason, goes to
  `traces/system-spill.jsonl`, never into `events.jsonl`: the shell's
  `trace_emit`, the CLI's harness lines, and now the model gateway's and
  the fetch service's, which dropped it. The provider-limit rule reads the
  watchdog's nudges and wakes from the spill as well.
- The kickoff's own line is the proof that the record can be written: when
  the collector came up and cannot be reached, the start is refused, saying
  why, before any pane, hub or VM starts. A collector that answers and
  refuses the line (a trace that ends in a torn line) is not refused here.
- `tests/kickoff-guards.test.sh` runs a kickoff under a runs directory where
  no socket path fits (130 bytes).

### Fixed: a short sensitive value is not taken for the digits inside a hash

`--redact` looked for a sensitive entry's words anywhere in a text, so a
four-character value (a PIN) was found inside any sha256, keyed id or
timestamp that happened to contain its digits. The redaction then replaced a
line of the ledger or the trace for its hash, and the leak scan after it
refused the package for a leak that was not one; a real trace, full of
hashes, holds almost any four digits somewhere. A word under eight
characters (`scripts/package-tools.ts`) still counts wherever it stands, a
letter touching it included (`PIN4821`), and is skipped only inside a longer
run that makes it something else: its digits running on into a bigger number
(`12.482145Z`), a run of sixteen hex characters or more with digits of its
own, or a run of twenty base64 or base64url characters or more with letters
and digits of its own and few separators. Leaving a real value in is the
worse failure, so a path, a sentence or an identifier with the value in it
still counts. The redaction and the scan hold to the one rule, in text, UTF-8
and UTF-16 bytes and file names; a longer word counts wherever it stands, as
before. `tests/redaction.test.ts` failed about once in a hundred runs on it.

### Fixed: a partial answer is a disposition, whatever its reviews' strength, and a standing finding is never discarded to make an answer not determinable

On the run s9722fa (a CTF case of six questions, `--stop operator`) every
question had a partial answer with medium confidence. Each review was capped
to best_candidate by that confidence and by the parts the answer itself
declared open; readiness then held all six as "a best candidate, not
established" while the answers check disposed them partial, the coordinator
read the finish status as "best_candidate is not a disposition", and the
seats revised all six to not_determinable with a `downgrade` citing their
limitations and their own coverage records. The case lost every positive
answer. Now:

- "A best candidate" concerns only an answer that claims established
  (`claimsEstablished`, `heldAsBestCandidate` in `extensions/protocol.ts`),
  and readiness, the answers check (and through it the finish gate) and the
  report read that one test. Partial, not determinable, a bounded negative,
  out of scope and a premise shown not to hold are disposed by their own bar.
  A best candidate now holds readiness under every stop policy, as it holds
  the done; before, a cap-policy run could turn ready on one that the done
  then refused.
- A partial answer's review attests the answer's own claims: a part it
  declares open is held `established: false` with
  `answer_review.parts[].declared_open: "E-<seq>"` (a limitation the answer
  cites, or a coverage record it rests on; checked), and does not cap the
  review; neither does the answer's confidence nor a route its
  `would_change` names. An answer that claims established keeps the whole
  cap. The attest's reply says a best candidate on a disposition holds
  nothing.
- A downgrade's evidence names an entry that bears against the earlier
  chain (a finding or event that contradicts it, a refuted hypothesis tied
  to it, a supporting entry under dispute or contradicted, a correction of
  one); a limitation or a coverage record does not (`downgradeCheck`). While
  a finding or event the earlier answer rested on for its question still
  stands, the downgrade is refused and the refusal says to answer partial.
  This holds for a bounded negative as for not determinable.
- The worker prompt, the SWARM.md template and the `attest`, `record`,
  `finish` and `done` descriptions say it plainly. `tests/partial-disposition.test.ts`
  reconstructs s9722fa under all three stop policies.

### Fixed: a hit the store sweep found is cleared by saying what it showed, not by naming it

On the run sb1b3c8 seats cleared `sweep_hits` by writing a revised coverage
record whose refs named up to 66 hit objects, by their jobs' directories,
with nothing recorded about what any showed. An object that moves from an
earlier sweep's hits into a coverage record for the same question is now
cited in its `result_refs` by an entry that says what it showed: a finding,
an event, an absence or a limitation whose refs name the object itself (a
directory does not count), written after the sweep that found it; one entry
per object, or one absence over several (`unexaminedHits`,
`extensions/store-sweep.ts`). Until then the gate keeps holding it as
`sweep_hits`, naming each object and how to clear it, and the coverage
record's reply says so when it is written. Object refs and times only.

### Changed: under more_evidence: no, acquisition_none_why naming the policy is the answer, not an ask

Under the ctf preset seats opened acquisition asks in the finish tail only to
satisfy "a not_determinable names its acquisition ask", and the case policy
declined each at once. Under `more_evidence: no` the `no_acquisition_ask`
warning and the answer's reply now suggest `acquisition_none_why` naming the
policy (`NO_MORE_EVIDENCE_NONE_WHY`) and no ask; the worker prompt says it in
one sentence.

### Changed: done asks whether the dispositions suffice, not the operator

In a real run seats twice closed a lead needs_operator asking the operator
to "accept or reject the examination-limited dispositions" before any done,
and asked again when a note answer did not settle it. The worker prompt and
the `lead_close` and `done` descriptions now say it: whether the
dispositions suffice is what done asks the finish line; operator acceptance
(`swarm.sh question <run> accept Q-n`) is for a question the finish line
holds that only the operator can release; so the coordinator calls done
first, and a seat asks the operator only for what a refused done names as
the operator's. A needs_operator close whose words ask for dispositions to
be accepted, made while no done has been refused on such a question, still
stands, and its reply carries a `hint` saying so.

### Fixed: a value typed into a job's command is refused as authored, and the refusal says so

A seat read a value off an image, typed it into a job's own command, and
cited the job's output (which held it) as the evidence for a lookup. The
refusal read only "not in the cited bytes": the check set the value aside
as authored, and returned before it said why whenever every value wanted was
set aside. Now it says it whatever the other values are
(`scripts/net-broker.ts` `evidenceCheck`, `authored`), and
`evidence_link_missing` names the value as named by the cited job's own
command or arguments, authored, not derived, and says what counts: an
input, a catalogue member, or the output of a job that read the evidence.
Every such refusal also says that a value read from an image is cited from
the output of a job that read the image (an OCR tool run over the input),
never from a transcription typed into a command.

### Fixed: a notifier that failed says how

A spawn error, the 20-second timeout and a signal all read "notify.sh could
not be run" in a request's `delivery_failed`. The failure now says which:
`could not be run (ENOENT)` with the errno, `took more than 20 s and was
stopped`, `was ended by SIGKILL`, or the exit status as before
(`extensions/requests.ts` `runNotify`). The retry after a backoff is as it
was.

### Fixed: an entry the harness writes on the ledger is on the trace, and custody holds the ledger to it

Custody failed its ledger check on every run that took material from
outside: the fetch service's captures (runs s26f142, s7f90eb) and the
operator's evidence (sabfd76, sb177a7) were `external` entries written by
`recordExternal`, no trace line carried their hash, and custody named each
"in the ledger and never on the trace". `swarm.sh custody-verify sb177a7`
said NOT VERIFIED for that alone.

- **A line of the harness's own.** Every ledger entry the harness authors
  without a seat's `record` or the hub's `recordEntry` call (the external
  entry of an addition, of a question's attachment and of a capture; a
  person's hint recorded as a hypothesis in the asker's name) puts a
  `harness_record` line on the trace with the entry's seq and hash, the way
  the process that wrote it writes its other lines: the hub as its own line
  (the harness's token, its own spill), the operator's CLI with no hub
  running as `trace_emit` does (to the collector, else the harness's spill
  on a chained trace), a pane on the host through its `logEvent`. A merged
  duplicate writes nothing, and no line.
- **Custody counts it.** The ledger is held to those lines beside the record
  tool's and the hub's; in a microVM run only the harness's own line counts,
  never one a seat claimed (named in `claimed_by_seat`). An entry written
  into the file with no line still fails the check, and the runs from before
  still fail it: nothing is exempted.
- The console describes the line; the report counts one written from the
  operator's shell as the harness's, not as a line nobody can account for;
  the provider-limit rule and the watchdog read it as a harness row.

### Fixed: the model provider's limit on every seat pauses the run

An until-solved run hit its provider's subscription usage limit on every
seat at once ("Try again in ~6904 min.", "The usage limit has been
reached"). The watchdog prompted each seat again, half an hour apart, for
days, every VM and the hub up, and the operator was never told the run could
not go on before a stated time (docs/adr/0013, "The provider's limit, and the
operator's pause").

- **A pause for the provider's limit.** When every live seat's last turn
  since the last lift ended in a provider error, and each of them is limited
  (told to wait 30 minutes or more, or refused again after a retry), the
  watchdog pauses the run (`paused.reason: provider_limit`), under every
  stop policy. One seat's error never pauses it, nor one seat's long wait
  beside the others' passing errors. The pause keeps the provider's texts
  whole, the models, and the end it holds to (`until`): on one provider the
  longest end any seat was told, on several the earliest when each was told
  one. No seat is prompted, no model call goes out and the wall clock does
  not run.
- **Every seat is retried.** A seat whose last turn ended in a provider error
  is prompted again with backoff under every stop policy now (three times
  per run of errors under a cap policy), which is what shows a limit that
  persists; the harness's own rows under its id are not read as its turn.
- **The harness tries again** at that end, or every 30 minutes, wakes the
  seats, and pauses the run again if every seat is refused again, charging
  the try nothing. The operator is told once per spell (`paused`, with the
  end and the advice to stop the run to free the machine and resume it after
  the limit lifts), and the board once. Each failed turn is recorded once,
  whole; a seat tells the board once per spell of failed turns, a countdown
  ("~6904 min", "~6874 min") being one error.
- **`swarm.sh pause` and `unpause`**, and Unpause in the console beside the
  pause. The operator can hold a going run under any stop policy, and lift a
  pause whose cause is gone; a cap's pause still over its cap is refused,
  pointing to `extend`. An extension no longer reads a pause that is not a
  cap's as one it must lift. A run stopped in a pause keeps it, a resume
  wakes no seat with words about a lift, a run whose seats all died in a
  pause is not read as paused, and the console's elapsed time leaves pauses
  out.

### Fixed: what the first calibration run on the new flow showed (run sabfd76)

Scored against a truth kept outside the repo, the run missed a third of the
facts in deleted and unallocated space, answered "every file" and "every
connection" established with no coverage, adopted a decoy at high
confidence attested established, stated every answer high, answered a
question that needed a missing source not determinable with no acquisition
ask, and left a question not determinable after the evidence that settled
it was added late. Five generic rules follow (docs/adr/0013, "After the
first calibration run").

- **New evidence stales what rests on older coverage.** An evidence
  addition makes stale every standing bounded negative, not determinable
  and partial answer whose coverage predates it, whatever question it was
  added for; the gate holds each (`evidence_stale`) until a coverage record
  at the new revision stands reviewed, or the answer cites the new evidence.
  `evidence add` and its board post name them. An established answer is not
  staled.
- **A completeness claim rests on coverage of its areas.** A question that
  asks for every one, all, each or a complete list is marked `completeness`
  (by its words, or `question add --completeness`); its established or
  partial answer rests on a coverage record naming the areas searched
  (`areas`: allocated, deleted, unallocated, slack, secondary), or the gate
  holds it (`completeness_uncovered`).
- **An established attest names an alternative.** `answer_review.alternatives`
  is `[{explanation, why}]`; an established attest that names none is
  recorded best_candidate, and the reply says so.
- **The run records the confidence.** High stands only on an established
  answer another seat attested established naming its alternatives; any
  other high is recorded medium, said in the reply and shown in the report,
  the metrics (`confidence`) and the calibration score.
- **A missing source is asked for.** A not determinable answer's coverage
  names the acquisition ask (`acquisition_ask: R-<n>`) or why none
  (`acquisition_none_why`); the answers check warns (`WARN:`, `warnings`)
  when it does neither, and holds nothing.

### Fixed: every chained register is sealed, bound, packaged and verified

- The store sweeps (`ledger/sweeps.jsonl`) and the finish register
  (`leads/finish.jsonl`) were sealed by nothing: custody seals both now
  (`seal.sweeps`, `seal.finish`, and their checks), `custody-verify` holds
  both to the seal and an earlier seal as a prefix after a resume, a release
  binds the sweeps in its chains and holds the finish register to the
  verdict, and a package carries both (`ledger-sweeps.jsonl`,
  `finish.jsonl`), walked by `verify`; `--redact` treats a sweep's strings
  and hits like other sensitive text.
- The package's `verify` now walks the operator requests, the network's
  grants and fetches and the model gateway's log against the seal (they
  were copied and not checked), and declares them in `COMPONENTS.json`; a
  release holds the gateway log's sealed lines to the verdict.
- `scripts/chained-registers.ts` lists every chained register in one place;
  `tests/chained-registers.test.ts` holds each to custody, the release, the
  package and both verifies, and fails on a `.jsonl` name the harness uses
  that the list does not classify.

### Fixed: what the Fable review of the fix batches found

An independent review of the first three fix batches found four rules
that held less than their words said and ten smaller gaps.

- **A correction re-points a closure only when nothing but what it cites
  changed.** For a finding, an event, a hypothesis or a search every field
  but what it cites is its conclusion now (a time, what it indicates, a
  status, a completion, an attribution, the value exactly); an answer
  keeps its rule.
- **A review by the seat offered it is recorded** after its offer ran out
  and moved on, the other seat's offer withdrawn; the register accepts a
  reviewer's own offer rather than withdrawing it "reviewed by" itself; a
  taken review whose seat is done or dead lapses at once.
- **Stale evidence clears only on a reviewed examination**: a coverage
  record naming the import, or an entry resting on it, attested by another
  seat; a review made before the evidence came does not count for an answer
  recorded after it. The operator's acceptance made after the evidence came
  excuses it, and its reply says what the finish line still holds.
- **An alternative counts only with the entries that rule it out** and a
  real explanation; filler records the attest a best candidate.
- **The recorded confidence reads only answers recorded under its rule**
  (`confidence_rule`): a finished run's highs read as declared, and say so.
- A confirmation made again after a compaction keeps its batch, and a batch
  confirms what stands after a second correction; an objection to another
  file is a late item; a quiet refusal says "NOT RECORDED:" and its trace
  row keeps the whole record; "at each", "each time" and a doubled space no
  longer mark a completeness claim; a leading form wrapped in "I want you
  to" or "the goal is to" is flagged.

### Fixed: what the round-13 scoring showed

- **The store sweep: a negative is checked against everything the run
  holds.** Two not-determinable answers had their row in an export the run
  itself had made half an hour before, and passed review against their
  coverage's two or three sources. A coverage record now names
  `looked_for` (or `looked_for_none_why`), and the hub searches every job
  output and log, import, capture and kept tool output for those strings,
  in UTF-8 and UTF-16LE, streamed whole (`ledger/sweeps.jsonl`). A pending
  sweep holds a negative like an unreviewed one; a hit outside the record's
  objects holds it until the record is revised to name that object or the
  answer is; a partial sweep names what it did not search and holds unless
  the operator accepts the question. The review offer, `ledger.md`, the
  report and the metrics (`sweeps`) show each sweep.
- **A downgrade needs counter-evidence.** A revision from established or
  partial to not determinable or a bounded negative carries `downgrade:
  {evidence, why}`, or it is refused and pointed to a dispute and a lower
  strength or confidence; the report shows the earlier answer, its disputes
  and the downgrade's evidence.
- **calibrate.ts counts a missing-evidence question by its state at the
  start**: one a late item made present still counts in "Acquisition: k of n
  missing-evidence questions requested the evidence".

### Fixed: what the first pilot on the new flow showed (c10, run s6be12f)

- **A review offer is held for the review, and withdrawn when it is not
  needed.** Of the finished pilot's eleven negative-review offers one was
  taken up, five declined and five had no outcome. A review's first claim
  was a lead offer's minute, and accepting it recorded nothing, so the
  offer passed on while the seat that took it was still reviewing: E-220's
  went from s01 to s05 to s04 in two minutes, and s05's review of E-266
  was deferred to the seat the offer had moved to while three more seats
  declined in its favour. `offer accept` on a review now holds it for ten
  minutes (`SWARM_REVIEW_HOLD_SEC`); the review its seat records takes up
  that seat's offer even after it ran out; an offer whose item needs no
  review any more (the answer superseded, as E-219 was seven seconds after
  its offer; reviewed by any route) is withdrawn, and one that ran out is
  recorded lapsed. The offer names where the gate counts the review ("attest
  E-220 or its coverage record E-218 … not answer_review"), and what is
  offered is what the gate holds.
- **The metrics count coverage reviews as the gate does.** "Coverage
  records: 0 reviewed" beside "Negative answers: 2 reviewed": the reviewers
  attested the answers, which the gate counts for the records they rest on.
  A record now counts reviewed on itself or through the negative answer
  resting on it, both given apart; review offers count withdrawn and taken.
- **Readiness turns ready on the dispositions the done ends on.** Under the
  operator's stop, readiness held on "question:5 is not determinable" to
  the end, and the metrics read "never ready" while the coordinator's done
  passed examination-limited. A disposition that only limits the run no
  longer holds readiness (a best candidate and a route limitation still do,
  as the ADR says), and a done that passes while readiness had not turned
  ready records the ready state in the sentinel's transaction, marked as the
  done's, so the tail is measured.
- **A summary's symbolic citation recorded before still stands.** Reading
  the finished pilot with the new code took down its summary and narrative:
  the answer fingerprint's fields had been reordered, and every recorded
  fingerprint differed. The order is the earlier one again, pinned by a
  test.

- **Confirmations come in batches, and a refresh is re-pointed.** One
  answer revision re-offered confirmation for four to six closures, several
  to one seat. A seat is now offered one confirmation per correction chain,
  confirmed with one `lead_confirm(batch)`; and a correction that changes
  no conclusion (only its refs or its words) holds the closures on the
  standing entry, recorded as `repoint (conclusion unchanged)`. A change of
  value, result or kind still goes to confirm or reopen.
- **The finish tail converges.** The resumed pilot sat in its finish tail
  for over ninety minutes: answers kept being revised, and each revision
  re-offered confirmations and made new late results. While a coordinator
  holds the lease and the registers are met but for late items,
  confirmations or resolutions, the finish is being assembled: another
  seat's answer revision needs `material: why it changes a conclusion`,
  and a rewording is refused quietly (not a refusal). The phase is in the
  finish register, every header and `swarm.sh lead list`. A result post
  that only restates its author's own revision is covered by it.

- **B9 holds the sensitive values, not every word of a sensitive entry.**
  The operator's analyst question "Is there evidence that any activity on
  this system ran automatically (…startup entries)…" was refused because
  "activity." and "entries." ended sentences of sensitive entries, and the
  identifier rule took a word with its full stop for an identifier. B9 now
  holds each sensitive entry's recorded value whole, as a phrase, and from
  its text only the words that are values by their shape (a digit, a
  symbol, a capital inside the word, or a long random string; never an id,
  a number, a date or a time); ordinary words never refuse a question, a
  name or a doing label. The package's redaction scanner is unchanged.
- **B9 takes the value-shaped words from the value only.** The next
  pilot questions naming "PowerShell" and "meeting.txt" were refused
  because a sensitive entry's method and notes named that tool and file.
  The words that are values by their shape now come only from what an
  entry records (its `value`, and the subject an attribution names), never
  from its evidence, source, method or notes; the whole value is still
  held as a phrase.

- **An earlier seal recomputes the attestations and the disputes.** Like the
  lead, question, network and request chains, their first sealed lines are
  now chained again with their own code; a sealed line rewritten with its
  hash fields kept no longer passes as a prefix.
- **A summary citing an answer by its seq is bound to its question.** The
  pilot's summary and narrative cited answers as E-n and fell with every
  revision of each. `record` now turns such a citation into the symbolic
  `question:N` (bound to the answer's conclusion, not its seq) and says so;
  a reworded correction keeps the summary standing.
- **The finish register from the first header, and reviews before any
  done.** The pilot had no `leads/finish.jsonl`: its five finish calls were
  four status reads and an objection refused because no done had named the
  report yet, and readiness was recorded only when it turned. The first
  readiness is now recorded (not posted when not ready), and an ack or
  objection before any done names the report and holds the coordinator's
  done that names it. The writer, the docs, the metrics and the report all
  use `leads/finish.jsonl`.
- **Reviews are offered to one seat.** The pilot had six seats review one
  deferred lead's route within minutes. A limiting route's review (once its
  questions are answered, bound to those answers) and a material negative's
  review are offered to one eligible seat, the relevant first; another
  seat's review of an item reviewed or offered to another returns quietly
  with who has it and records nothing, and a second review says why.
- **A confirmation waits for a compacting closer.** The pilot's L-17 was
  reopened three times because its closer began compacting as each
  confirm-or-reopen offer arrived. Compaction is now a temporary absence:
  the offer waits up to five minutes past the compaction's start; done or
  dead still reopens at once.
- **A call made holding no lead is given to what it named.** The pilot's
  metrics put 136.3M of 240.0M tokens under "holding no lead". Reviews,
  records, route reviews and lead acts made so named a lead, a question or
  an entry: 16.5M are now given to those questions, 0.6M to the finish and
  the report, and the 119.3M left are split by kind (waiting 61.9M,
  coordination 23.1M, reading 23.8M, compaction 7.3M, other 3.1M). That
  part is real: the header's "Yours: none" and the worker prompt now ask a
  seat to hold a lead for sustained work and to take what is offered
  before it waits.
- **The quick start has the running case's commands.** `question add`,
  `requests`, `evidence add`, `material add`, `net`, `extend`, `resume`,
  `metrics` and `tools --candidates`, each with one example and a link to
  usage.md.
- **The kickoff checks the Herdr server first.** `herdr status server` is
  asked with the other host programs, before any pane or VM is made; a
  stopped server refuses the start (and a `--check`) and says how to start
  it. The pilot's kickoff had booted every VM before it found the server
  stopped.
- **A leading form is an imperative at the start of a clause.** "Confirm
  that…", "Show that…", "Prove…" at the start of the question or of a
  sentence are flagged; "…if not, what shows that" is not.

### Fixed: `--stop operator` no longer forces answers; B16 warns on services, not on English words

- **The operator's stop policy adds no stricter answer requirement.** Under
  `--stop operator` (`--until-solved`) the finish line refused `done` while
  any question was not answered or accepted, so a `not_determinable` that
  had passed the negative bar (coverage record, detection opportunity, peer
  review, route plan) could only end by the operator's acceptance, and the
  contract told the agents "an examination-limited finish is not
  accepted". Now every run ends on the same rule: every question in scope
  with a disposition under the bar (established; partial; a bounded
  negative or not determinable on a coverage record another seat reviewed;
  a premise shown not to hold; out of scope; accepted; withdrawn). The
  answers check names each section's disposition (`dispositions`), the
  finish gate carries it on each question and names what else holds a run
  under the policy (`holding`: a defect a limitation only names), and a
  quick negative nobody attested holds its question. The run ends
  `completed` when every question is established or settled by a bounded
  negative that says the event did not happen under the stronger bar, and
  `examination_limited` otherwise; a best candidate never satisfies (B2).
  The kickoff line, SWARM.md's "Until solved" section, the refusal and the
  worker prompt say the negative-bar path plainly: plan the routes, record
  the coverage record, have another seat review it, answer
  `not_determinable`.
- **One rule for the end of a run, under every stop policy.** Under
  cap-pause and cap-stop a limitation that merely named an unanswered
  question let the agents finish, examination-limited, with no coverage
  record and no review. Now `done` needs every question in scope disposed
  under the bar whatever the policy; a cap still pauses or stops the run,
  and the operator still stops it, whatever the questions' state (paused,
  stopped; never completed), and an agent may still abandon outside the
  operator's policy. The contract's Questions section states the rule and
  the way to not_determinable for every run.
- **B16 matches services, not words.** The goal's service names came from
  every label of every denied host, so "what did he search for" named
  search.brave.com and "how did he hide" named hide.me. A bare name now
  comes only from a host that is a service's own name (`google.*`,
  `nominatim`, an adapter's id or service), never a subdomain's label, and
  an ordinary English word among those (hide, archive, medium, proxy…) is
  taken only written as a proper name inside a sentence; hosts, URLs and
  adapter ids are matched as before.

### Added: work another seat did is named, and the process is measured from its registers

- **`similar` at `job_run`.** A command or tool job with a declared scope
  keeps `reuse: {op, objects}` on its `job_accepted` line: its tool or its
  leading command word, and its objects by sha256 (a directory by its path).
  Another seat's job under way or committed with the same tool or the same
  word over at least one of the same objects is named in the answer, with
  its lead, state, status and outputs, the same command or tool and
  arguments first; the whole list is a `job_similar` line. The job runs as
  asked.
- **`same_as` at commit.** A committed job's non-empty file with an earlier
  job's output's sha256 names that job and file (`job_same_as`, the job's
  record and view, its post).
- **`independent: true`** on `job_run` records an intended reproduction; the
  similar jobs are still named.
- **Hints never hold a job up.** `similar` is sought once the job is
  registered and queued; `same_as` is looked up in an index built in the
  background, off the store's commit path. The console's Jobs tab shows both
  for a job, every entry.
- **The shadow merge is retired.** The whole-spec key matched none of 393,
  127 and 190 keyed jobs on the last CTF round; nothing writes
  `job_would_merge` now, and old lines are ignored. Typed recipes are still
  merged.
- **`swarm.sh metrics <run> [--json]`** (`scripts/metrics.ts`): quick and
  unreviewed negatives, coverage completeness, offers by outcome (wakes from
  before offers apart), `done` calls and refusals, the tail from readiness,
  from the first answers and from the final ones, acquisition gaps,
  interpretations still valid, reversals by new evidence or discoverable,
  tokens per question apportioned by lead, duplicates and reproductions, and
  the network's requests, grants and captures; each a count of named
  records by id and code (no free text a record carries), over the
  questions in scope at the run's end, with a missing register said as "not
  recorded", defined in `docs/usage.md`. `--compare <run-A> <run-B>` sets two
  runs of one goal side by side and flags a negative the other asserts and a
  shared negative without complete, current coverage. ADR 0017.

### Added: the report follows each question; outputs carry their sensitivity; the code agents wrote is ranked for the library

- **The report, question by question.** §1 is one screen of every question
  (the goal's, the agents', a person's, and those proposed, excluded or
  withdrawn): its standing, who asked it, its answer by number, its leads,
  the operator's acceptance and its tokens. §2 follows each from who asked
  it (the goal; an agent and the entry that raised it; a person with role,
  claimed or signed) through every verbatim revision, the neutral wording,
  hints, attachments with their provenance, clarifications, the proposition
  its first lead tested, its leads, its coverage, its result and contrary
  evidence, the acceptance, its evidence gaps and its cost; each group of
  questions says why it matters, and the unresolved ones say what would
  settle them. A negative lead is counted in the body; Appendix F holds
  every question and lead event and every disposition with its review.
- **Cost per question.** Each model call the gateway recorded goes to the
  leads its seat held then, split evenly, and to their questions; a call
  outside every hold goes to no question and is shown on its own line. A
  host run's seats' totals are spread over their tool calls, an estimate; a
  seat with a budget the trace cannot place keeps its tokens in an explicit
  unattributed bucket. The per-question figures shown are whole numbers that
  sum to the displayed total (largest-remainder). Appendix F renders every
  register event whole, including one tied to no lead.
- **A release binds the question register.** `release.json.questions`: the
  length and head custody sealed, the questions by origin, every person who
  asked or acted (enrolled, claimed or signed), and what came after the
  verdict. Verification recomputes the bound prefix's own chain, not the
  stored hash fields, whether or not the custody verdict sealed the questions;
  the operator requests and the other register chains are held to a seal the
  same way, by custody-verify, an earlier verdict, a release and a draft.
- **Sensitive outputs, held by their bytes.** `job_run(secret_output: true)`
  seals every output sensitive; a job that executed against a sensitive
  output's bytes — read from the snapshot its scope manifest recorded, so a
  work copy, a store blob, a catalogue link, generation or alias counts,
  through chains of jobs — is sealed sensitive too, as derived; an entry
  citing one is recorded sensitive; a sensitive generation withholds its
  coverage detail from the catalogue projection at the source. `package
  --redact` withholds every file whose bytes are a sensitive job's, wherever
  they sit, names each by a keyed id (never a hash a low-entropy value could
  be brute-forced from; the key and the real digests are in a private sidecar
  kept outside the hand-over), and scans every file and the filenames for the
  sensitive entries' words, a small output's text and the outputs' digests; a
  package without `--redact` names what in it is sensitive (`HYGIENE.json`),
  the same way. An entry citing a cancelled or stopped job's output without
  saying how it treats it is a `partial_output` defect, resolved by the job
  that wrote the bytes so a copy or a `sha256:` citation is held too.
- **Tool harvesting and the library's hint.** `swarm.sh tools <id>
  --candidates` ranks the code agents wrote into command jobs by lines times
  reuse, with its jobs, seats, profiles and the library tools that may cover
  it, and writes each script whole for the maintainer; a work file is taken
  only when the command ran it as code (read no-follow, its bytes matching the
  snapshot), and output hygiene withholds a candidate from a sensitive job or
  one holding a sensitive value before any script is written. A manifest's
  `use` says what a tool reads; a command job that declares its inputs is told
  which library tools read that kind of file, from a cached manifest, bounded
  and under a deadline.
- ADR 0016; README, docs/usage.md, docs/protocol.md, tool-library/README.md
  and the worker prompt say it.

### Added: one seat finishes, work is offered, and a review says how strongly it holds (ADR 0015)

- **One coordinator ends the run.** `leads/finish.jsonl` holds the finish's
  lease (the report's last publisher, else the first seat to call done),
  with a generation and a takeover when its holder is done, dead,
  compacting or silent. Any other seat's `done` is answered "not yours",
  quietly (`done_deferred`), and `markDone` refuses its sentinel. Readiness
  from the registers is in every header and posted when it turns; one check
  result stands per state revision, which now covers the report's digest,
  the shared deliverables, the jobs, the policy and the operator's
  decisions. The report is reviewed with typed acts (`finish ack`), and a
  result, veto or objection that lands after it needs the coordinator's
  typed resolution (`finish resolve`). A limiting route stops holding the
  finish only when its questions are disposed and another seat's
  `route_review` holds it no longer material, or the operator accepted them.
  A summary cites questions as `Q-<n>`, bound to each answer's fingerprint.
  An offer's bookkeeping (made, delivered, declined, lapsed) does not move
  the revision, so a waiting seat's delivery never makes the coordinator's
  check run again; a closure offered to its closer to confirm does.
  The sentinel is written in one transaction with the lease (the holder and
  generation the coordinator's done began with) and what is late against
  the report: a takeover or an objection made while the checks ran refuses
  it. What landed against the report is an obligation until resolved,
  through every later version of it. The revision counts what of each
  job's stdout was handed over, and readiness is cached only for the
  revision its own snapshot was read at. With the case contract (ADR 0014)
  the revision also covers the case policy, the operator requests' chain
  (a delivery claimed, sent or failed does not move it) and each addition
  committed or applied; an addition not yet applied, or an answer recorded
  before new evidence for its question, holds readiness as it holds the
  gate.
- **Reviews say how strongly they hold.** An attest of an answer to a
  question takes `strength` (established or best_candidate) and
  `answer_review`; a medium or low confidence, a part not established, or an
  untaken route named in `would_change` allows only a best candidate, which
  the answers check holds examination-limited. A dispute stays in force on
  the correction of the entry it named until its disputer withdraws it. An
  interpretation is bound to its entry. Agents reopen with `lead_reopen`,
  within the operator's restrictions. An answer's contrary evidence is held
  to its standing as its support is: corrected or disputed since it was
  weighed, it takes the answer down, and a summary citing its question.
- **Work is offered.** Wakes, hand-offs (`lead_handoff`), parked leads, a
  reopen after the operator's note and a closure to confirm are offers: first
  claim for a minute from delivery, bounded, accepted or declined (`offer`),
  invalidated by a revision, restart-safe; a person's question's offers run
  through the same machine. A superseded closure is offered to its closer to
  confirm (`lead_confirm`) or reopen, never re-pointed. A take on questions
  another seat covers is unheld unless it says it is a second route or a
  verification; first choices are staggered at kickoff; names are stable and
  labels follow the held lead. A standing entry is no need; a dropped need is
  withdrawn with why; prerequisites open and link in one act, with a product
  contract, and a loop is refused before either is written. A seat is offered
  one thing at a time across both registers, and a person's question offered
  to a seat holds against a peer's claim and reopen too. A lead is parked
  only when its holder is seen working on another lead; a closure to confirm
  reopens at once when its closer becomes unavailable. The prompts, the library's leads paragraph and the three CTF goals
  say so: a follow-up is opened unheld unless it is started next turn, and
  ending the run is the coordinator's done.
- **The operator sees it.** The console's Leads tab and `swarm.sh lead <run>
  list` show the finish (ready by the registers or what holds it, the
  coordinator, the last check, what is late against the report), the parked
  leads, and on each lead its standing offer, a closure to confirm, a second
  route and its product contract; `leads/leads.md` renders the same.
- **The runtime.** A running job is seen by its outputs, its logs and its CPU
  and I/O (msb's metrics, or the worker's heartbeat): "suspected stall" is
  shown, never acted on, and only on current measurements (a frozen
  heartbeat or a stopped sampler is "unknown", and stillness is not counted
  across missing samples). The regroup nudges a running job's holder first. A
  program missing from a job's image is named with its profile in the job
  record and the console, from the shell's own diagnostic or exit 127, never
  from an application's "not found". The seats' subscription tokens are renewed on the
  host with msb's live secret update, verified against a running VM.

### Added: the case contract: what may come in, what was asked of whom, and where the evidence ends

- **The case policy, complete.** `--more-evidence no|ask|yes` says whether
  evidence may arrive while the run goes on, `--material-use CLASS=USE,...`
  what each class of material from outside the evidence may be used for
  (`evidence`, `reference`, `none`), and `--legal`, `--provider-retention`
  what the operator records beside them; each also from the goal's metadata
  block. A contract that contradicts itself is refused at kickoff (a capture
  as evidence, a published case taking evidence later). The policy is
  written before the custody anchor, which holds its sha256; custody seals
  it and names a rewrite; a release binds it; a resume keeps it and says what
  its options would have changed. The services a goal names are held to the
  policy and the adapter catalogue at kickoff, as warnings.
- **Operator requests, with ids and an outbox.** A lead's needs, an
  acquisition, a clarification, a network item and a stop proposal are each
  a request `R-n` on a chain of their own (`requests/requests.jsonl`, sealed
  by custody), derived from the record that commits it, written once, and
  rendered where every reader has always read them
  (`operator-requests.jsonl`). The lead's request is no longer appended after
  the close with its failure swallowed: a request not yet written is said to
  the agent and written at the next reconciliation. Its lifecycle is pending,
  notified, acknowledged, then answered, declined or withdrawn; `swarm.sh
  requests` and the console's Requests tab act on it, and the header's badge
  counts what waits on the operator.
- **Notifications fired by the hub, with ids only.** `--notify` takes
  `desktop:`, `ntfy:<topic>`, `mailto:<address>` and a command, repeatable,
  kept outside the run; an operator request is notified when it is
  committed, by its id, its kind and the lead's or question's id, never by
  what it asks. The watchdog's polling is now a fallback.
- **The acquisition lane.** An agent asks for evidence the run does not have
  on the lead that needs it (`ask: {kind: acquisition, source, where,
  expected_value, urgency, ...}`); under `more_evidence: no` it is answered
  at once, "no additional input under this case policy", never as a finding
  that something is absent. `swarm.sh evidence <run> add PATH --for R-n`
  seals the evidence in the store as an inventory revision, catalogues it,
  answers the acquisition, and reopens the leads, answers and acceptances
  that rested on the evidence as it was; the agents read it through jobs.
  Calibration tells a late item added this way by its digest.
- **Material with provenance.** `swarm.sh material <run> add` and a
  question's attachment record supplied material as `external` with who
  supplied it, when, from where, its sha256 and what it may be used for;
  `check-answers`, the report and `release.json` name every answer resting on
  external material with its classes, and a record citing a class the policy
  says `none` for is refused.
- **Where the evidence ends.** The report's section 8 gains "Evidence gaps and
  acquisition requests", generated from the records: never collected,
  unavailable, inaccessible, unexamined, inconclusive.
- **Sensitivity.** A name, a `doing` label and a question's text are refused
  when they hold any value the run marks sensitive, whatever its origin: no
  answer-value concept, no exemption for the goal's own words.

### Fixed: the case contract's independent review

- **A resume's egress follows its recorded policy.** `--no-netguard` among a
  resumed run's options no longer opens a run whose recorded case policy is
  closed or dynamic; the generated VM and job specs are held to the policy
  (`case-policy.ts check-spec`) before anything boots.
- **Every notification is identifiers only.** Not only an operator request:
  `evidence_changed`, `finish_failed` and every other event leave as an
  envelope of ids, numbers and counts, the details kept in the run
  (`traces/notify-events.jsonl`, by event id). `mailto:` takes one mailbox,
  never an option, given after `--`.
- **Added evidence and material, committed then applied.** An addition is
  copied into a staging directory of its own, its id reserved by making its
  directory, and committed (record and journal line) one at a time under the
  run's material lock; what follows (the external entry, the acquisition's
  stages, the leads and answers it reopens, the board post) is derived from
  the record, each step once, and replayed after a crash by the hub's round,
  the next addition or `evidence list`; the finish line waits for it
  (`addition_incomplete`). A reason too long for the ledger's entry or a
  lead's reopen is kept whole in the record and named, never cut. Leads
  under a custom question section (`bonus`) are reopened. The documents say
  what the mounts do: an addition is readable at once, read-only, in every
  seat's VM, and its provenance is its ledger entry's.
- **`material_use none` holds on what a record rests on.** A digest of the
  same bytes, a job's output made from them, a coverage record and an
  attestation or dispute are refused as the material's own ref is, and
  `check-answers` fails an answer resting on it (`material_use`). A job's
  output attached as material keeps its lineage downstream.
- **B9 holds what is published.** A name is checked as it would appear
  (tidied) with Unicode folded, and a short value marked sensitive is held
  whole, as a word.
- **Operator requests.** An interrupted migration no longer loses the lines
  of a run from before the chain, and a line an older harness appends is
  imported; a delivery is claimed on the chain before it is sent (never two
  sends), tried again after a backoff, and an imported request the old
  watchdog never notified is notified. The operator's acts go through the
  hub while it runs, their board posts are made from the chain once, and
  their outcome is on the operator's record.
- **B16** names an adapter by its whole id (`rdap_domain`) and a tool name
  built on its service (`virustotal_hash`).
- **The fetch service's per-host interval** is held against when the
  previous request to the host actually left (each hop records `sent_at`).

### Fixed: the question register, after an independent review

- **The hub is the register's one writer.** While a run's hub is up, the
  operator's acts (the CLI and the console, through `swarm.sh`) are handed
  to its admin socket, which prepares each again from what was said, checks
  its signature against that statement, commits and delivers it. With no
  hub the CLI admits the act itself under the registers' lock; the
  acknowledgement says which (`admitted_by`).
- **A signature is carried by the act it signs.** A signed act and its
  signature are one event, written whole or not at all; the act is kept
  exactly as signed (a signed amendment that repeats the text no longer
  invalidates itself). `verify` attributes a signature to the person the
  signed act names, requires the key it carries to have the fingerprint the
  act names and this install's enrolment of that person to hold it, fails on
  `wrong-principal` as well as `bad`, and fails on any act that says it is
  signed and carries none. `lead direct --sign` is refused: a directive is
  not signed.
- **An act's effects survive a crash.** What a withdrawal or a triage
  decision implies on the lead register is reconciled from the chain under
  the lock, in the act's own hold and at every later act and header. A lead
  opened from a finding (`record(kind=finding, opens)`) counts as holding it:
  a withdrawal sends it to triage. A board post or a hint's hypothesis that
  failed leaves the revision pending, with no `deliver` event, and is tried
  again; a delivery finds its post by an exact key in its front matter,
  never by its words. Clarification requests and answers are derived from
  the chain and published once, keyed by `C-n`.
- **Answers are bound to a revision.** An answer to a register question
  names the revision it answers (`question_rev`, in the ledger's hashed
  core), checked under the registers' lock: a revision the question has
  moved past is refused, and one is required once the question has been
  amended. Staleness is by revision, not by time, and an unchanged answer is
  reaffirmed for a new revision as a correction naming it.
- **After the done.** Admitting a proposed question, or amending one into a
  new revision, after the run's done is a follow-up, as a new question
  already was; `resume` takes the follow-ups up as the continuation's work
  (a `continue` event) and puts the reserved `run_resumed` line on the
  trace. A withdrawn goal question is no longer required by the answers
  check or the finish line (its outcome is `withdrawn`).
- **One standing, whatever the name.** `question:N`, `N` and `QN` are held
  to a question's scope and withdrawal as `Q-N` is. The first claim of a
  directive under a person's question no lead has framed states the
  proposition and its negation (`lead_claim`). A goal question is seeded
  whole, through its later paragraphs and sub-questions.
- **Release verification** holds the lead and question registers, and the
  dynamic network's grants and fetches, to the heads the custody verdict it
  binds sealed: appended to is a prefix; cut, deleted or rewritten fails.
- **The console.** An amend or accept form keeps the revision it was
  opened on until you refresh it; a proposed question is a full card, with
  its clarifications to answer; the newest post is carried whole, clamped
  on screen with the whole in its title.

### Added: calibration cases with a truth kept apart, and a scorer for a run's answers

- **`calibration/generate.py`** writes three synthetic cases (a USB drive
  image with a workstation's logs, a web server's logs, a mailbox export
  with a browser history database), each with a goal, its evidence, one
  held-back item for the operator to add mid-run, and a truth file written
  only where `--truth-dir` says: never inside a checkout, the cases
  directory or a run. The facts are planted where examinations miss them
  (deleted, unallocated, slack, rotated compressed logs, two artefacts read
  together, base64) or are absent with a near miss beside them, and the
  generator holds each to the bytes before it writes. Standard library
  only; the same seed gives the same bytes on macOS and Linux.
- **`scripts/calibrate.ts <run-dir> --truth FILE`** scores a finished run's
  ledger answers against the truth: the miss rate on present facts, false
  "not found", forced answers, decoy adoption, unsupported negatives,
  acquisition requests, the late item and the calibration of the stated
  confidence. It reads today's ledger and Plan 3's fields (`result`,
  coverage records, the question register) when they appear, prints a table
  and writes its JSON beside the truth, never into the run.
- `tests/calibration.test.ts` and `tests/calibration-cases.test.sh`: the
  generator's determinism and refusals, every kind of fact, goals that name
  none of them, the facts read again with The Sleuth Kit, gzip and sqlite3,
  each goal launched with `--no-start`, and the scorer on hand-made ledgers.

### Added: three tools from later runs in the library, made general first

- **`ledger_timeline`** (from run `se5fdcd`) writes a run's dated ledger
  entries as one timeline in time order: Markdown, CSV or JSON Lines. It
  reads any run's `ledger/entries.jsonl` with the attestations and disputes
  beside it; kinds, a time range, a regex, excluded seqs, duplicates and
  corrected entries are the caller's choice, and every entry left out is
  counted by why. A sensitive entry is withheld unless asked, `redact` takes
  patterns, and it writes nowhere under `ledger/`, `tools/` or `inputs/`.
  The run's copy had one case's title, closing paragraph and password
  pattern in its script.
- **`contact_sheet`** (from run `s10d40e`, job `j000558`) tiles the images
  of a directory, a list or a tar (read in place) into labelled sheets for
  looking at: each distinct content once, exact duplicates (or look-alikes
  by average hash) listed, not tiled again. Tile size, columns, rows, the
  label format and dedup are parameters; `out_dir` keeps every tile, a
  manifest row per file and an index from tile to file with the whole
  label; a large set is done over several calls within the tool timeout.
  Needs Pillow (pillow_heif for HEIC), and says so when it is missing.
- **`nested_vdi`** (from run `sae6e7d`, job `j000136`) reads a VirtualBox
  VDI that lies inside an E01 or raw image without writing it out: through
  the NTFS data runs of the file holding it (a deleted one too; inline or
  from a file, sparse runs as zeros) or at an offset, then through the
  VDI's block map. `info` gives the header, the block counts and the
  guest's partitions, `ls` lists a guest directory (recursive, paged,
  nothing cut), `extract` writes one guest file, `read` gives guest bytes.
  The job it came from had one case's partition offset and cluster size
  written in and mounted the E01; the image, offset, runs, cluster size and
  header location are parameters now. pyewf for an E01, pytsk3 for `ls` and
  `extract`.
- `tests/tool-library-folded.test.ts` builds every fixture itself: a ledger,
  drawn images, and a FAT12 file system in a VDI with shuffled blocks inside
  four data runs of an outer volume, one of them sparse. Without Pillow,
  pytsk3 or pyewf the tests that need them are skipped; the header, the
  block map and the two-level read are plain Python and always run.
- **`optional_python` in a tool's manifest**: the Python modules only some
  images carry (Pillow and pillow_heif for `contact_sheet`, pyewf and
  pytsk3 for `nested_vdi`), imported under a `try` that catches
  `ImportError` so the tool says one is missing. The library's import check
  in `tests/recipe.test.sh` now reads each script's syntax tree: it sees an
  import inside a function and one by name through `importlib`, refuses one
  by a computed name, holds a declared module to its guard, and names a
  declaration nothing imports.
- The library's README says what each came from and how it was made
  general, which modules only some images have, and which candidates
  (the `$LogFile` scanner and mapping-pairs decoder of run `sae6e7d`) stay
  out of Community.

### Added: results and the negative bar; caps pause the run; a run that ended can be resumed

- **Results.** A question's answer carries `result`: `established`,
  `partial`, `bounded_negative`, `not_determinable`, `out_of_scope` or
  `premise_not_supported` (required on new answers; `inconclusive` reads as
  `not_determinable`). The answers check maps them onto its outcomes and
  names them in its machine line. Run outcomes are `completed`,
  `examination_limited`, `paused`, `stopped`, `abandoned` and
  `verification_unavailable`; an operator's stop writes `done/STOPPED`, and
  stopped is never completed.
- **Coverage records** (`kind=coverage`): the proposition, the objects, the
  time range, the method and settings, what was covered, skipped and failed,
  the results, what is still open, and the detection opportunity. The hub
  stamps the inventory revision and computes `coverage: complete|partial`
  from the inputs the jobs behind it declared, by digest; it never judges
  relevance. Required for every material bounded negative and not
  determinable answer.
- **Routes and quick negatives.** A question's leads carry `routes`; the
  first lead under a question without them is warned, a person's question's
  must carry them, and a material negative close is refused without them. A
  negative close lists the routes nobody examined; one closed after one job
  over one object within two minutes is flagged `quick_negative`.
- **Peer review of material negatives.** `attest(..., review: {detection,
  reproduced, other_route})` by a seat that recorded neither the answer nor
  its coverage; the finish line refuses while one is unreviewed, and the
  ledger, the header and the report say "negative (unreviewed)".
- **Wording.** The report renders a bounded negative as "No evidence that …
  was found in <scope>"; "did not happen" (`asserts_absence`) needs an
  existence question, complete coverage and a detection opportunity, and the
  answers check names an answer worded so without it.
- **Acceptance** (`question accept`) is refused while a lead under the
  question is open or its negative is unreviewed, and makes the run
  examination-limited. A question's disposition follows its answer
  (`dispose` events).
- **Stop policy.** `--stop cap-pause|cap-stop|operator` (default
  `cap-pause`; `--until-solved` is `operator`; a goal's `stop:`). At a cap
  the run pauses: no model call goes out (the extension, the model gateway,
  the hub and the watchdog each hold it), the operator is notified, and
  `swarm.sh extend <run> [--minutes N] [--tokens N] [--usd N]` goes on (the
  watchdog wakes each seat once) or `swarm.sh stop` ends it. The paused time
  does not count against the wall clock. A metered team gets a default token
  cap of 100,000,000. When nothing has yielded for 20 jobs or 30 minutes, a
  stop is proposed to the operator (an operator request of kind
  `decision`), never decided.
- **Resume.** `swarm.sh resume <run> [--question TEXT]... [--questions FILE]
  [--as ID] [--minutes N] [--tokens N] [--usd N] [--no-start]`, and
  "Continue this run" in the console: the same sandbox and chains; what
  marked the end moved whole to `done/history/<k>/`; each seat starts from
  its last hand-off note or compaction summary; new questions are analyst
  questions; refused before anything moves when it would still be over a
  cap. The resume is anchored beside the run; the next stop seals the
  continuation anew; `custody-verify` holds every earlier verdict to the run
  as a prefix and shows each; a release's chains verify as a prefix only
  after an anchored resume; a signed v1 stays valid, and the continuation is
  adopted through a later version. The kickoff keeps its options outside the
  run (0600) for it.
- **Console.** Extend, Continue this run, and a paused run's notice on the
  run page; the list carries the stop policy, the pause, the outcome and the
  resumes. The jobs drawer shows every argument whole (it cut each at 40
  characters), and a job's output is kept whole on disk and served whole
  (`/api/jobs/<id>/output`) where the list carries its last 64 KiB.
- [ADR 0013](docs/adr/0013-a-negative-is-bounded-and-a-cap-pauses.md).
- **After review** (seventeen findings, each with a test that failed before
  its fix): coverage records bind their results by hash (`coverage_stale`);
  `premise_not_supported` rests on a finding and absolute wording is held
  whatever the result; the report states a negative from its coverage
  record; an acceptance is of the answer that stood; coverage names objects
  as the job scopes do and takes directories; release verification runs the
  chains' own verifiers and relaxes to a prefix only after a resume anchored
  at a verified boundary; the bound report is kept at `release/bound/`; a
  gone gateway log breaks an earlier seal; a resume is anchored before
  anything moves; compaction and the pausing call are held while paused;
  extend and stop are ordered under one lock; a pause is told once whoever
  wrote it; the watchdog runs at `--idle-nudge-sec 0` and retries a wake;
  the kept start options hold no secret a pane can read (`resume --env
  KEY=VALUE`; the notify command and the typed `--notify` targets are given
  to the resume's kickoff again from `runs/notify/`), and a resumed run's
  evidence image is attached again. An acceptance also stands only until
  new evidence arrives for its question (`evidence add`).

### Added: a dynamic network, decided by rules and made on the host

- **`--network closed|dynamic|open` and a case policy** (`--policy
  standard|live_adversary|internal|ctf`, with `--lookups`, `--contact`,
  `--disclosure` overrides, or the same keys in the goal's metadata block).
  `closed` stays the default and changes nothing; a contradictory policy is
  refused at kickoff, and so is direct egress it does not permit
  (`--allow-host`, `--allow-install` without `--no-pypi`, a pack's secret
  hosts under `ctf`, `internal` or `live_adversary`). The policy is recorded in `network/policy.json`,
  SWARM.md and the registry (`scripts/case-policy.ts`).
- **`net_request`, `net_fetch`, `network`.** An agent asks for one bounded
  lookup from the adapter catalogue (`network/adapters.json`: RDAP, crt.sh,
  NVD, CISA KEV, CIRCL hashlookup, RIPEstat, Nominatim, Overpass, YouTube
  oEmbed title, an evidence-linked HEAD, VirusTotal with a host-managed key).
  The hub decides it in eight fixed steps with machine-readable reasons
  (`scripts/net-policy.ts`); a refusal closes the avenue, never the lead,
  and opens one operator item per host and lead. Credentials are looked for
  in each URL component as sent and decoded, sensitive values anywhere
  inside one; the evidence link counts only source bytes (never an agent's
  own words); quotas are counted again under the issuing lock. Grants are
  capabilities in `network/grants.jsonl`.
- **The fetch service** (`scripts/net-fetch.ts`) makes exactly a grant's
  request: its own headers only, DNS once with every address checked
  public (IPv6 by its parsed bytes), TLS against the name, no redirect
  beyond an adapter's referral hosts and none past an oversize or stopped
  answer, no CONNECT, the use logged before it leaves, the grant held to
  again after every wait and DNS answer and before publishing, an adapter's
  rate slot reserved per host, an oversize body refused whole. The result is
  written before the capture is published; an attempt left without one is
  reconciled, and custody names any that remains. What no seat is given (a
  filtered response, a partial or withheld body) is kept in
  `<run>.netraw/`, outside every VM, verified by custody, packaged under
  `network/raw/` and purged with the run. Jobs use it through `job_run net_grants`, on the one host
  port their worker is booted with. Each answer is sealed as `net:<k>/<n>`
  and recorded as a ledger entry of the new kind `external`
  (`source_class: external_capture`); what derives from it stays external,
  by what each job resolved (its scope manifest, digests, a broad scope),
  never by how it spelled its inputs.
- **Socket grants (tier 2)** say what they are; `lead note --allow-host`
  makes one, and `--allow-host` names itself a static socket allowance. A
  host is written one canonical way, and the grant, not the legacy host
  line, decides whether it is in force.
- **`swarm.sh net <run> list|grant|deny|revoke`** and the console's
  **Network** tab; every act needs a reason. Custody seals both network
  chains and re-hashes every capture. [ADR 0012](docs/adr/0012-a-dynamic-network-decided-by-rules-and-made-on-the-host.md).

### Added: the question register: what a run is asked, by the goal, an agent or a person, on one chain; analyst questions while it runs; the analyst and observer roles

- **One register.** `questions/questions.jsonl` (rendered as
  `questions/questions.md`), chained with the lead register's code and
  written under its lock, holds every question as `Q-n`: the goal's (seeded
  at kickoff, `Q-n` is `question:n`, so every goal and run keeps working),
  the ones agents open (`question_open`, with the entry that raised it) and
  the ones people ask while the run goes on. Each keeps every verbatim
  revision, a neutral formulation, why, its objective or parent,
  materiality, priority, what it expects, hints, attachments, a suggested
  seat, a deadline, and its origin: who, in which role, from which account,
  host and channel, enrolled or not, claimed or signed. Scope, work and the
  evidential disposition are kept apart. Custody seals the chain; the
  package carries and verifies it.
- **Goals with objectives.** An `## Objectives` section (or a front-matter
  `objectives:` list) declares `O-n`; a goal with objectives and no
  questions is open-ended, and its first agents propose the questions.
  `analyse-inputs.md` gains one.
- **Scope rules and triage.** An agent's question is in scope inside an
  objective or under a question in scope, otherwise proposed into a triage
  queue; an examiner's and the operator's are in scope by authority and may
  add an objective; an analyst's are in scope inside an objective; a
  reviewer's and an observer's are proposed. Only the operator and an
  examiner admit or exclude; an agent never changes a person's question.
- **`swarm.sh question <run> add|list|show|amend|priority|scope|withdraw|clarify-reply|accept|verify`**
  and `swarm.sh lead <run> direct`. `--as ID` names an enrolled person (a
  claim); `--sign` signs the act with their key (namespace
  `dfirswarm-question`, the secret on fd 3). An act is acknowledged only
  after the chain holds it, and is on the operator's record twice: the
  attempt and the outcome naming the event.
- **Delivery.** A person's question is posted from `analyst:<person>`
  (tagged `question`, addressed to the seat it is offered to), ranked first
  in every agent's header, offered to the suggested seat for a minute and
  then to the most suited idle seat; urgent tells the holders under the same
  objective and cancels nothing. A crash between the chain write and the
  post is made good at the next header, and posts nothing twice.
- **Hypothesis framing.** The first agent lead under a person's question
  records the proposition and its negation; its answer carries `contrary` or
  `contrary_none_why`; `result: premise_not_supported` is an answer; leading
  forms are flagged for the critic.
- **The finish line.** Every material question in scope is held to an
  answer; a stale answer (recorded before an amendment) refuses `done`; an
  accepted question limits the run. The sentinel is written under the
  registers' lock against the revision the finish line judged, so a question
  admitted meanwhile refuses the done, and one after it is a follow-up.
- **Roles.** `swarm.sh examiner enroll --role analyst|observer`: an analyst
  adds questions and signs no release; an observer proposes. Every enrolled
  person's register line admits `dfirswarm-question`.
- **The console.** A Questions tab (the add form, the list with origin
  badges and authors, the triage queue, the clarification threads, the
  acting person for the session) and "Add directive" on the Leads tab.
- [ADR 0011](docs/adr/0011-questions-are-a-register-with-their-askers.md).

### Added: the examiner signs with their own secret, from the command line or the console; three kinds of key; a technical reviewer signs their own record

- **Three kinds of key, two roles.** `swarm.sh examiner enroll` records a
  key kind and a role (`--role examiner|reviewer`). An ssh key must have a
  passphrase: `--generate-key` asks for it twice on the terminal (or takes
  it on a descriptor) and feeds it to `ssh-keygen` on stdin in a session
  with no terminal; `--key FILE` is checked to be encrypted (`ssh-keygen -y
  -P ""` must fail). `--no-passphrase` stays, as a command-line trade the
  console refuses. `--fido [--fido-verify-required] [--fido-resident]` makes
  an ed25519-sk key on the authenticator with an `ssh-keygen` found to have
  FIDO support from its files (Homebrew's openssh on macOS; the product
  never probes the key). `--pkcs11-module PATH (--pkcs11-id HEX |
  --pkcs11-uri URI) [--pkcs11-chain FILE]` enrols a token's X.509
  certificate, read without the PIN, keeping its fingerprint, CN, issuer,
  validity, key usage and qualified-certificate statement and refusing one
  that cannot sign; its signatures are CAdES-BES CMS made through OpenSSL
  3's PKCS#11 provider, with the issuing CA inside. A certificate's subject
  is never shown beyond its CN. Older enrolments read as an examiner's ssh
  key.
- **One way for the secret.** A passphrase or a PIN reaches `ssh-keygen`
  (through `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force` and
  `scripts/askpass-fd3.sh`) or OpenSSL's provider (`pin-source=file:/dev/fd/3`)
  only down a pipe on fd 3: never argv, the environment, a file, a job or a
  log.
- **Prepare, then seal.** An adoption renders its final bytes once, with a
  fixed time, into `release/.pending-<nonce>/`, and says what will be
  signed; the seal signs exactly those bytes, and refuses when they, the
  review, custody, the report or the releases moved, after fifteen minutes,
  or for a nonce already used. The gate runs again at the seal. A release
  records `signing`: `via` (console or cli), the consent statement,
  `consent` (`confirmed`, or `presented` with `--yes`), the sha256 shown,
  when it was prepared and confirmed, the key's kind and fingerprint and the
  program that signed; an e-signature is `release.json.p7s`, and a printed
  PDF gets `report.pdf.p7s`. `swarm.sh review <id> --sign` prints the
  summary, asks on the terminal, then takes the secret with echo off;
  `--yes` skips only the confirmation. Release records are schema 2; schema
  1 is still read.
- **The console signs.** A Release tab (the run's releases, how each was
  signed, what verify says, the technical reviews; the adoption: an enrolled
  examiner, the prepared report in a frame with no scripts beside the sha256
  of the bytes shown, the gate, the consent box, a dialog for the passphrase,
  the touch and PIN, or the e-signature PIN), a Technical review tab and an
  Examiners page, over new routes that need the token even when
  `SWARM_UI_TOKEN` is empty, a loopback Host, the console's Origin and JSON,
  refuse while a host-mode run is live, lock a person out for fifteen minutes
  after five wrong secrets (on the operator's record), refuse keys without a
  passphrase or in ssh-agent, and run their scripts directly, never as a job.
  The Ledger tab's old sign button is gone, and the console no longer reads
  the newer review acts as breaks in the chain.
- **Two-stage signing.** A technical review names its outcome
  (`--outcome agreed|issues-resolved|disagreement`, each disagreement with
  `--disagreement`), when it was done, its scope (entries by seq and hash,
  or `--all-answers`) and what it was over (report.md, the ledger's head,
  custody, the dispositions' head). An enrolled reviewer writes and signs it
  with a `countersign` line (SSHSIG in `dfirswarm-review`, or a CMS); a
  record the examiner writes says the reviewer did not sign it, and can be
  countersigned later (after a release, the countersign names it). A reviewer
  elsewhere works from the package (`swarm.sh review <package-dir>
  --technical-review …`, `review-import.jsonl`), and the examiner imports it
  (`--import FILE`), checked against the register and the review's head. A
  reviewer with the examiner's id, name or key is refused.
  `--require-technical-review` at kickoff, or
  `SWARM_REQUIRE_TECHNICAL_REVIEW=1`, makes the seal wait for a current,
  signed review that is not a disagreement. The report and verify list every
  technical review in one of five wordings.
- **Verify, by kind.** The machine's seal reads "machine seal, self-checked"
  and is never checked against an examiner register; a run no examiner
  adopted says "RELEASES HOLD". An e-signature is checked with `openssl cms
  -verify` against `--ca FILE` (with `--ca-intermediate FILE`), naming each
  trust anchor's sha256; without a CA it says "certificate chain not
  checked". The release binds what the kickoff recorded of the signers' keys
  (`signer_keys_hidden`, `signer_isolation`, `earlier_runs_hidden`).
- **Hardware tests** in `tests/hw/` (a FIDO key, the e-signature token, the
  console's seal path), run only with `DFIRSWARM_HW_TESTS=1`; the unit tests
  use a throwaway SoftHSM2 token and skip, saying why, without it.
### Security: the signing keys are kept from a host run's agents

The machine key seals a draft release at stop, unattended, so it has no
passphrase, and an examiner's key may have none either or sit in an
ssh-agent. A microVM mounts none of them; a host run's panes could read them.

- **Denied at the kernel.** A host run's panes are denied each home's
  `machine/` and `examiners/` (made 0700 first, so a mount namespace has
  something to mask), `SWARM_SIGNERS_HOME`, each enrolled examiner's key
  file as its record names it (the key is never read), the custody key, and
  the ssh-agent: `SSH_AUTH_SOCK` is dropped from every pane and its hook,
  its socket is denied (launchd's on macOS by its directory), and
  `--env SSH_AUTH_SOCK=` is refused.
- **Fail closed.** A guard that cannot deny one of them (Landlock alone and
  an agent's socket, a key inside the run, a signers' home that holds what
  the panes need, a key inside something every VM mounts) refuses the run.
  With no guard at all (`--no-write-guard`, or a host without one) the run
  is refused while a signing key exists, `--check` included, unless
  `--accept-signer-exposure`: the run then records `signer_keys_hidden:
  false` and what was exposed, and the kickoff says to rotate.
- **Recorded for every run**: `signer_keys_hidden` and `signer_isolation`
  (isolation, guard, what was denied or exposed, why) in the registry, for
  the draft release to bind; see docs/observability.md.
- **Earlier runs and the reviews.** Every earlier run's sandbox in the
  registry and `runs/reviews/` are denied to a host run's panes where the
  guard can mask a directory (not the whole runs directory: this run and the
  registry are in it); `earlier_runs_hidden` says which, and why not under
  Landlock alone. Until now only `--no-read` hid an earlier run.
- **`swarm.sh machine rotate`** retires the machine key into
  `machine/retired/<id>/` (never deleted; the drafts it sealed carry its
  public key), makes the next one and prints both fingerprints.
  `machineSigner` puts the directory back to 0700 and the key and its record
  to 0600 each time the key is used.
- **fsguard.** A `--no-read` file is covered by `/dev/null` in a mount
  namespace (a directory by an empty tmpfs, as before). In `linux` mode a
  `--no-read` path that exists is left to the mount layer and not carved by
  Landlock: a carve under `runs/` froze that directory for the panes, and
  the registry, rewritten by rename, stopped being readable to the finish
  line. The comment that said only case material warrants a read denial now
  names the signing keys too.

### Added: the report is released, adopted by a named examiner, and reproducible where it can be

A report now has releases: signed records of which bytes were handed over,
sealed by whom. Machine custody and human adoption are kept apart in every
word.

- **The machine's draft at stop.** When custody is taken (the hub's finish,
  `swarm.sh stop`), `release/v0/` is written: a DRAFT sealed by the
  install's machine key (made once outside every run; it says it is no
  examiner), binding the swarm's report as custody sealed it, a rendering
  of it generated at the release's own time with the DRAFT mark, the
  custody verdict and its anchor, the sealed index of `work/`, the head and
  length of the ledger, its attestations and disputes, the journal, the
  trace and the review, the harness commit, the renderer's sha256 and the
  models. Refused when the run is not as custody sealed it; once per
  verdict; its line goes into the anchor beside the run.
- **Examiners are enrolled.** `swarm.sh examiner enroll` (name,
  organisation, competence statement, a key given or made only when asked,
  checked by signing a challenge) prints the fingerprint and the line for
  the organisation's signer register. The registry's kickoff `examiner`
  string is no longer shown as the examiner.
- **Each answer is adopted, qualified, withdrawn or rendered
  inconclusive** by seq and hash (`review --adopt/--qualify/--reject/
  --inconclusive`). An answer whose support is defective cannot be adopted
  or qualified, and a release waits until it is withdrawn or inconclusive;
  repairing it is a new examination. A technical reviewer's record says
  who, on what competence, and which methods were checked.
  `adoptionState()` gives the report body each answer's standing.
- **The examiner's release.** `review --sign` renders the final bytes (no
  DRAFT mark), prints them with `--pdf`, signs `release.json` with the
  examiner's key, and names the release in the review. A later adoption is
  an amendment with a reason (`--amend-reason`). `swarm.sh releases`
  shows, prints, mirrors and verifies them; the package carries every one
  byte for byte and `verify` walks the chain against the signer register.
- **Witnesses.** `--anchor-mirror cmd:|dir:|print` copies each release's
  digest line where the operator's account does not keep it (or prints it
  with a QR-ready string for the case file); an RFC 3161 token over the
  release's signature, checked against the authority's CA;
  `swarm.sh timestamp` obtains one later and dates the proof from then.
  `releases --ots` and `--transparency COMMAND` add an OpenTimestamps proof
  and a transparency log's receipt when available.
- **Custody holds the evidence links.** `inputs/` and each `inputs/<set>`
  must still lead to the source the kickoff recorded; a link moved to
  identical bytes fails the evidence check. Custody seals the agents'
  disputes chain beside the ledger, and the package carries and walks it.
- **`swarm.sh rerun <run> <job>`** runs a sealed job again through the job
  service's worker path, in the image of the recorded digest (another is
  refused), into `<sandbox>.reruns/`, never the store, and names each file
  that differs. A byte mismatch stays one; an equivalence under a named,
  versioned normalisation (`timestamps@1`) is said apart, only when asked.
- **Redaction says what it replaced and what it missed.** `REDACTIONS.json`
  records each change by the sha256 of what it replaced, why and which
  entry; JSON is redacted field by field; a four-character PIN is taken
  out; acts on a sensitive entry are redacted keeping their chain; a
  release's PDF is withheld. A scan after it refuses the package on any
  sensitive word left (case, path separators, JSON escapes, UTF-16),
  naming the file and entry, never the word; `--redact-leaks list` hands it
  over with the hits listed.
- **`swarm.sh certify <package>`** writes a certification template of the
  kind FRE 902(13)/(14) contemplate, with the verification run verbatim,
  for a qualified person to complete and sign. No PAdES: the PDF's sha256
  is bound in the release, under the examiner's detached signature.
### Added: a job sees what it declared; a finding may cite a brain's own output, sealed

- **Declared scope, enforced**: `job_run inputs` left out, `["all"]` and a
  list (an empty one too) are kept apart in the spec and on the journal
  (`default-all`, `all`, `declared`). A declared job's worker is given a view
  the hub builds for it, outside every VM, holding only what it named at the
  paths its brain sees: a declared directory of the evidence or a job's whole
  output bound, and so a whole evidence set the scope covers (one image and
  its segments), a file of a set it covers only in part cloned (or linked
  from the run's one checked copy where the file system cannot clone), a store file linked, an
  agent's file snapshotted by clone or copy and hashed at the start; never a
  hard link to the evidence or to live scratch. A segment set comes whole,
  from the census's record (`catalog/plan.json` `collections`, journalled as
  `input_collection`). A declaration that does not resolve refuses the job;
  there is no broad fallback. Declared, expanded and accessible manifests go
  in `store/jobs/<id>/scope.<attempt>.json`, its sha256 on `job_started`;
  custody holds it and says a declared job's scope was enforced and its reads
  within it not observed. `vm.ts` holds every share before binding it and
  checks each again after the VM is made, before anything runs. An import's
  scope is its source: the worker copies the hub's snapshot.
- **`tool:<seat>/<file>` and `trace:<sha256>` refs**: a whole output the
  harness kept under tool-output/, or one line of the trace, is found on the
  chained trace (attributed by the collector, on the chain), held to the
  trace's digest, sealed by an import job over the hub's snapshot and
  published as `import:<job>/<file>` in `store/imports/<job>/` with its trace
  provenance (`brain_output_sealed`); the record cites the import. Bytes that
  changed since, or what the trace did not capture, are refused with the way
  on: run the work again as a job.
- `JobService.workerSpecFor(job, staging)` builds the worker a recorded job
  had, for a rerun.
- **Experimental, off by default, untested in a VM**: observing a declared
  job's opens with fanotify inside its worker (`SWARM_JOB_OBSERVE=
  fanotify-experimental`), read as complete, partial or unknown, never
  complete when anything was dropped; its VM acceptance tests are
  `tests/job-observe-vm.test.ts`.

### Packs, as integrated

- Two branches changed each of these packs, so the integrated packs take one more patch and are resealed over the merged files: computer-forensics-base 1.3.2, windows-forensics 1.3.2, cloud-forensics, linux-forensics, macos-forensics, memory-forensics, mobile-forensics, network-forensics, reverse-engineering and triage-collection 1.1.2.

### Changed: a lane for short jobs, more workers, room on the host, and the smallest image that holds a job's programs

- **Workers**: unset, 6 on a host with 128 GiB or more and 4 with 64 GiB or
  more (2 otherwise), still lowered to what fits beside the seats.
- **A lane for short jobs**: from 3 workers one is kept for an agent's job
  that declares `timeout_seconds` of 120 or less (stopped at that limit), so
  a quick look never waits behind long parses; the kickoff's recipes and the
  derived catalogue never take it, and an agent's own limit counts each
  lane apart. `job_started` names the lane; job_run and SWARM.md ask for the
  short timeout.
- **Room on the host**: a worker starts only while the host keeps 15% of its
  memory free beside it, asked at each start (runs share a host); until then
  the job waits, on the journal (`job_waits_for_host`, and `host_wait_ms` on
  its start).
- **Fixed**: the queue counted an agent's running jobs, and the derived
  lane's one at a time, by their written start, so one pass of it could
  start more than the limit, and the derived catalogue could run two recipes
  past a ceiling of one generation (a flaky test on Linux CI). It counts the
  jobs it has handed a worker, one pass at a time.
- **A command that names no profile** runs in the smallest job image whose
  own record holds every program it runs, and in the default image whenever
  that is not sure (a heredoc, a quoted script, an import, a script of the
  agents'); `job_started` and job_status say which image and why. Images
  record every program on their PATH (`on_path` in image.json); one built
  before keeps such commands in the default until it is rebuilt.

### Added: several evidence sets in one run

- `--inputs` may be given once per set (a laptop and a phone, the logs of
  three servers), and the console's kickoff form adds sets one at a time,
  each a removable chip. Each set lands at `inputs/<name>/`, named after its
  directory; one set is `inputs/` itself, with the same paths and the same
  manifest as before.
- Every set is copied, or held in place, as one set is: each checked against
  its own source, one kernel rule per set held in place, each mounted
  read-only and no-exec into every VM and every job worker; the size and
  file ceilings hold for the sets together. A directory given twice, one set
  inside another, and two sets that would be one directory are refused.
- `inputs.json` names the sets (`sets: [{name, path, source, files,
  bytes}]`); the agents' check, the pack's `check_inputs` (base pack
  1.3.1), each VM's probe and host custody walk each set through its link,
  and read a manifest without `sets` as they always did.

### Fixed: the record and the report hold to what custody sealed

Three reviews of the reporting path (Claude, Fable, GPT-6-Astra) found that
the verification commands compared less than the seal promised. Each fix has
a test that failed before it.

- **`custody-verify` enforces the seal.** It compared each check's status
  only, so a `work/report.md` edited after the stop, a work file removed or
  added, or a correctly chained ledger entry appended all passed. It now
  holds every chain to the length and head the verdict sealed (the ledger,
  its attestations, the store journal, where examiner notes after the run
  are named and allowed, the gateway log) and every file under `work/` to
  the index custody wrote (`artifacts.json`, whose sha256 the verdict and
  the anchor name), naming each drift.
- **A version 3 ledger is held to the trace.** "Every chained entry is on
  the trace" ran for version 2 entries only, so every current run skipped
  it. The ledger check's reason now says which entries the trace never
  carried.
- **A package carries the seal.** `artifacts.sealed.json` (the index custody
  sealed, byte for byte), `review.jsonl` (the examiner's review) and
  `COMPONENTS.json` (each part present, or absent with why) go into the
  package under its manifest. `verify` fails on a part missing and not
  declared absent, or declared absent against the verdict's seal; holds
  every packaged work file to the sealed index; recomputes every ledger
  entry's core a redaction left readable (it used to recompute the first
  only); lets only examiner notes follow the journal's sealed line; walks
  the review and says what its sign-off is over. `SIGNER.txt` and
  `signer.pub` are written before the manifest, so who signed and when are
  under the signature.
- **The report labels its own report's hash.** §9 prints the sha256 of the
  bytes it reproduces and whether they are the ones custody sealed, and
  "CHANGED SINCE CUSTODY" with the sealed hash when they are not.
- **RFC 3161 tokens are checked against the authority's CA.**
  `--custody-timestamp-ca FILE` (or `SWARM_CUSTODY_TSA_CA`) has custody run
  `openssl ts -verify` on each token and record the result in the anchor;
  `custody-verify --tsa-ca FILE` checks it again and fails on a token that
  does not verify. Without a CA both say "imprint only, signature not
  verified".
- **A sign-off is over a report, and says when it no longer covers it.**
  `review --sign` is refused when there is no report at the path it names;
  `review --show` exits 4 when the ledger's head or the report's hash moved
  since the sign-off; the report's cover says "reviewed and signed" only
  when the sign-off covers the ledger and the report as they stand, and
  otherwise what it is over.
- **A read-only verify writes nothing in the run.** It no longer removes a
  `.verify-*` directory an ended custody left beside the snapshots (it names
  it), loads a kept disk for msb's check under `--scratch` (the host's
  temporary directory by default) instead of beside the snapshots, and
  says what it touched outside the run.

### Fixed: what the basic-flow CTF rounds found in the packs

- **`usn_journal`** read every record of a `$J` all along: its `name` filter
  was a substring match and a run passed it an alternation, so "0 records"
  read as an empty journal. `name` is a case-insensitive regex now, as in
  `mft_records` and `indx_carve`; `records_read` counts every record whatever
  the filter kept, and a filter that keeps none says so. The journal is
  mapped rather than read whole, its sparse front skipped in steps of up to a
  megabyte, and v3 and v4 records are read as well as v2.
- **A pack tool run again as a job** gives the job's `$OUT` every path in the
  agent's own directories however it is written (relative, absolute under the
  run, with `./` or `..`), except one that already held something when the
  agent called the tool: that is its input, and the job reads it where it is.
  `written_to` names where each moved path is sealed, `$OUT` itself included.
- **The mobile recipes** take `--probe-out`, as the kickoff's census asks
  every detect step; they refused it with a usage error, so a phone's tar was
  catalogued as a member list only. `ios-filesystem` and `archive-members`
  open a tar by its magic instead of trying every decompressor, which took the
  LZMA one half a minute on 64 MiB of zeros for every such input.
- **Output paths.** `feature_scan`, `zeek_run`, `sigma_hunt`, `unified_log`,
  `doc_probe` and the twelve tools that keep a whole result in a caller's
  `out_file` or `out_dir` (cloud, macOS, triage, network, Linux) refuse a place
  outside the run directory, the run directory itself or under `inputs/`,
  links resolved first; `jumplist` never writes through a link left in its
  `out_dir`; `mem_fs` mounts under a job's `$OUT`, where a rerun sends it.
- **Nothing cut.** `sigma_hunt` keeps every field of a matched record (it
  kept 12), every rule that fired (25) and every detection, all of them in
  `detections.jsonl` past the page, and the engine's stdout and stderr whole
  in files named by path, size and sha256 (they were dropped, or cut to their
  last 400 and 800 characters). `cloudtrail_parse` and `ual_parse` return
  whole tables rather than their top 20 or 30, and `collection_index` every
  modification date rather than ten.
- **A rerun's answer says where its output's places went:** `paths` maps each
  `<run>/.jobs/<id>/…` (or `.jobs/<id>/…`) its sealed stdout names to
  `store/jobs/<id>/out/…`; the output itself stays as sealed.
- The iOS unified-log method names `unifiedlog_iterator`, the reader
  `unified_log` runs, not the retired UnifiedLogReader.py, so every pack
  seals without a warning; `pack-tools.test.sh` holds them to it.
- Ten packs take a patch version and a new seal.

### Added: a ledger that interprets, answers the critic checks, and a gate that names the fix (ledger v4)

- **Findings interpret.** A finding carries `indicates` (what the observation
  means), `confidence_why` (the quality of the evidence, not a count of
  artefacts), `alternatives` or `alternatives_none_why` when it is inferred,
  and `qualifies` when it rests on a job that did not succeed; `basis` and
  `confidence` are required. The hub writes a canonical `method` record of
  each cited job or import into the entry and its core.
- **Answers are entries.** `record(kind=answer)` per question of the goal,
  plus a summary and a narrative, citing entries by hash; every claimed
  support is checked at record, a token check marks what no cited entry
  holds, and an answer stops standing when what it rests on is superseded or
  disputed, transitively.
- **Acts.** `attest` (how an entry was re-derived, inside the hashed line;
  attestations version 2) and `dispute` (its own chain,
  `ledger/disputes.jsonl`), hub-written.
- **The gate at done.** `check-answers.ts` reads the ledger's answers when no
  `--report` is given; the finish line hands a failing check's output back,
  so the first `done` is told each defect and its fix and the next passes
  once a limitation names each one left. Every library goal names the report
  author and the critic, the answer entries and the critic's acts; the
  `SIGN-OFF:` post is gone from them, from the packs' own goals and from the
  operator's shelf in `prompts/goals/` too. The packs whose goals changed
  are one patch up and resealed: cloud-forensics 1.1.1, encrypted-containers
  1.2.1, linux-forensics 1.1.1, macos-forensics 1.1.1, memory-forensics
  1.1.1, mobile-forensics 1.1.1, network-forensics 1.1.1,
  ransomware-response 1.0.3, reverse-engineering 1.1.1, triage-collection
  1.1.1, windows-forensics 1.3.1.
- **Old ledgers verify as they did**: explicit version dispatch keeps the v2
  and v3 cores byte for byte, an unknown version is refused, and custody
  holds every chained entry of any version to the trace.
- `tests/fixtures/ledger-v4/` is a small run with every kind and act, for
  the report renderer to build against.

### Fixed: a compaction that never ends, an agent that only waits, what a seat sees of its peers, a runtime's cache in work/

- **A compaction is bounded.** Each summary attempt stops at 300 s or 48,000
  characters (`SWARM_COMPACT_SUMMARY_SEC`), whatever the provider does with
  `maxTokens`: the openai-codex API sends no output limit, and on run
  sedf827 two summaries ran on to 128,000 output tokens. What a stopped
  attempt wrote is kept whole under `tool-output/<id>/`. A compaction still
  running after 900 s (`SWARM_COMPACT_TIMEOUT_SEC`) is stopped by the seat
  and counted as failed (`compact_stalled`), so it is retried and then the
  lock released, where on run s6895a8 a seat was silently lost. The idle
  watchdog nudges no compacting seat (Pi refuses the prompt) and says a
  compaction open past 1200 s on the board; a hub prompt refused during one
  is recorded as refused.
- **Waiting is idle after ten minutes.** An agent that has called only
  `wait` and `inbox` for 600 s (`SWARM_WAIT_IDLE_SEC`) is steered, unless a
  job of its own is running; a steer now ends an open `wait` (`reason:
  prompt`). The echo of a nudge no longer counts as the agent's activity.
- **A seat no longer reads the trace or its peers' sessions and kept
  outputs** (run s306463 grepped its peers' transcripts). In a microVM,
  `traces/` is an empty read-only veil, and `.pi-sessions/` and
  `tool-output/` are veils holding only the seat's own directory; each VM's
  probe checks all three and the kickoff refuses a VM that sees one. A
  seat's `done` gets the finish line from the hub, which runs the
  operator's checks on the host (they read the trace) and answers the whole
  run; markDone takes that same run, and the refusal names each failing
  check and what makes it pass. The host's collector, custody and console,
  and a host run's `done`, are unchanged. `list_team` now shows, per peer,
  its name and what it is doing, its last post, its open jobs and its latest
  ledger entries, from the board, the store and the ledger, never the trace.
- **Node's compile cache is out of work/.** The kickoff points
  `NODE_COMPILE_CACHE` at the run's `.runtime-cache/`, so the artifact index
  and the package no longer carry `work/.tmp/node-compile-cache/` (run
  s2a59b2).

### Changed: every image profile reviewed as a DFIR examiner would (Codex)

- Each of the nine profiles (base, disk, memory, linux, mobile, network, re,
  web, full) was reviewed by its own Codex reviewer, which rebuilt the image,
  ran every program, tool and recipe on the sample and CTF evidence where it
  could and on synthetic fixtures where no evidence fitted, and fixed what it
  found in the packs it owned.
- **Nothing cut.** Tools that stopped at a limit or sliced a value keep the
  whole result: a page for the agent and the rest in a named JSON Lines file
  (the library's pager, inlined in each tool so a copied tool runs), or an
  `out_file`. Parsers that failed while reporting success now fail: YARA on a
  rule error, the macOS unified-log reader (replaced by Mandiant's
  `unifiedlog_iterator` 0.7.0), capture engines with a non-zero exit.
- **Wrong answers fixed.** UTF-16LE BitLocker recovery keys were missed; a
  64-bit crash dump's run map was read eight bytes early; an extended
  partition was taken for ext; an unreadable encrypted partition was counted
  as a filesystem; a disk image was called a logical collection; files over
  512 MiB had no hash; CloudTrail attribution depended on input order; pcapng
  timestamps ignored their resolution and offset.
- **Added.** `linux_triage` and the `linux-target` recipe; `pcap_extract`,
  `suricata_run` (JA3/JA4), `network_log_summary` and the `network-capture`
  recipe; `fuzzy_hash` (ssdeep, TLSH), UPX and the `static-binary` recipe; two
  iOS catalogue recipes and the SEGB and unified-log methods; YARA in the
  memory image; LVM, XFS and Btrfs programs; CJK and Noto fonts for the
  browser; the ransomware pack on `re`.
- **The browser tool** writes screenshots in the agent's own directory, holds
  navigation, redirects, subresources and WebSockets to one policy, blocks
  service workers and refuses downloads, naming what it refused.
- **memory-windows** runs Volatility on the image's symbols first and asks
  the symbol server only when the image has none for the kernel, and says
  which. The images empty apt's cache as they build and list the packages a
  profile adds in `tools.md`.

### Changed: the agents boot the base, the programs are in the job images

- In a microVM run with jobs and packs, each agent's VM boots the base image
  and the packs' programs are in an image per profile: `job_run
  profile=<name>` names one, a pack tool or a recipe runs in its pack's, and
  a job with none in the image holding every pack. `images/<profile>/tools.md`
  lists each image's programs, SWARM.md's "Job images" maps packs to images,
  the journal declares the images (`job_images`) and custody holds each job
  to them. `--brains-with-packs` keeps the agents on the packs' image.

### Changed: the ledger's version 3 and a custody that can be verified (Fable and Codex)

- **Ledger.** Two kinds, `hypothesis` (with its status) and `limitation`
  (with its reason), and typed fields for what the agents were writing in
  prose: `answers`, `rel`, `sensitive`, `clock`, `precision`, `basis`,
  `completion`, `attribution`, `locators`, `because`, all in the chained
  core when present; older ledgers verify as before. A second author is an
  attestation beside the entry (`ledger/attestations.jsonl`, chained) and
  `entries.jsonl` is never rewritten; a correction is compared on
  everything an entry says; a refused record keeps its whole arguments on
  the trace; an entry resting on a failed job's output is told so.
- **check-answers** takes the entries tagged for a section as well as those
  it cites, counts a limitation as examination-limited and never a
  hypothesis, refuses a finding resting on `unresolved:` refs only, checks
  an absence's refs and completion, names a failed job, and answers nothing
  from a broken ledger.
- **Custody** says every check's status, seals each chain's length and
  head, matches the operator's audit to the trace, compares acquisition
  hashes (`start --inputs-hashes`), verifies job logs and catalogue
  generations against their seals, records its cost and the models, can be
  signed (`--custody-sign-key`), timestamped by an RFC 3161 authority
  (`--custody-timestamp-url`) and hold a reference clock's offset
  (`--time-reference`), and exits 4 on an adverse check. `custody-verify`
  re-checks a run writing nothing and names the lines after the seal.
- **Hand-over.** `package --redact` takes out what a sensitive entry says
  and cites while every chain still walks (REDACTIONS.txt), `--with-outputs`
  includes the jobs' outputs, and `verify` re-walks the package's chains
  against the seal and refuses a path outside it. `export --redact` does the
  same for a CSV. An examiner's sign-off is bound to the report's hash and
  the rejections standing.
- **Report and console.** The chain of custody is arranged for a court
  (checks, seal, acquisition, audit, signature, timestamp, clock, models,
  cost, the command to check it again, the operator's actions); the report
  and the console show hypotheses, limitations, standing contradictions, the
  questions answered and sensitive material.

### Changed: one agent's abandon is a vote while others work

- `done` with `abandon: true` ends the run only when a second agent has
  abandoned too, or when no other agent is still working (every peer has a
  `.done` or `.dead` marker). Before that it is recorded under
  `done/abandon/<id>.md`, the board is asked once, and the agent is told to
  post what blocked its slice and carry on. The hub applies the same rule to
  a seat's `markDone`, and a refused seat stays up. Run sfeeebb: one seat of
  ten abandoned a BelkaCTF case after six minutes because its own slice had
  not come together, and the sentinel stopped the nine others.

### Added: findings name what they rest on (ledger refs)

- `record` takes `refs`: the run's objects an entry rests on —
  `input:<path>`, `job:<id>/<path>`, `import:<id>/<path>`,
  `member:<generation>#<n>`, `sha256:<hex>`, or `unresolved:<why>` when none
  can be named. Each is resolved when the entry is written; one that does
  not resolve refuses it, with the nearest names. The refs are in the
  entry's chained core when present (an entry without them keeps the core it
  always had), so one added, removed or changed later breaks the chain.
- A finding without refs is taken, with a note asking for them. Recorded
  again with refs where the standing entry has none, it becomes that entry's
  correction; with other refs than the standing entry's, it is merged and
  told its refs were not added.
- `ledger.md` and the report ("Rests on") show them. Custody resolves them
  again and counts the standing findings by what they rest on: refs (those
  that no longer resolve named), a path in the prose only, or nothing (an
  audit gap). The pilot's four runs had 2/24, 11/21, 6/27 and 3/21 findings
  citing nothing, by the prose count.
- A goal can ask that its answers rest on the ledger:
  `scripts/check-answers.ts --report work/report.md --sections 1,2,3`, called
  from `## Checks` through `$SWARM_HARNESS` (which await-done.sh now sets),
  passes when each section cites a standing finding whose refs resolve, or a
  search that found nothing. It does not ask for confidence. Decided with
  Fable and Codex in place of a hub gate: the goal owns done (ADR 0002).
- In a run with tool jobs, a shell command over `inputs/` that runs a minute
  or more is told once (three times per agent at most) that a job would
  have sealed its output (`job_hint`); a finding without refs that cites a
  file in an agent's own `work/` is told so by the file's name.
- `job_run import=work/<id>/<file>` seals a file or directory an agent made
  in its own VM: a job copies it into the store as it is now (each file
  hashed before and after the copy up to 2 GiB; links left out, named) and
  says it was copied live; one that changed while it was copied fails.
- **The derived catalogue, on by default** (`--no-derived-catalog` turns it
  off). What jobs make — tool, command and import jobs, whatever their
  status — is offered by content to the derived recipes whose own
  `min_bytes`, `suffixes` or `magic` take it. It runs in the lowest lane (one
  job, only when no other waits, largest objects first, 32 pairs a pass),
  within 300 worker-seconds each 10 minutes and at most 50 generations and 2 GiB
  a run, nothing dropped (`derived_offered`, `detect_answered`,
  `detect_unanswered`, `derived_deferred`, `derived_bounded`). Complete
  derived catalogues are posted to all; a partial one goes to its maker with
  why, and is linked to its readable form (`generation_related`).
  `catalog_search` v9 lists generations (`which=generations`) and says why a
  partial one is partial. Custody holds every revision and generation to the
  journal. Before it: what a worker writes cannot steer a host read
  (index.tsv confined to the sealed manifest), each probe's whole output is
  kept, 7z listings stream, zip directories are bounded by bytes, and
  disk-volumes finds a volume at sector 63 or 2048 with no table
  (computer-forensics-base 1.2.19). After the measuring runs:
  archive-members is offered a compressed tar by its name ending only, not by
  a bare gzip, bzip2, xz or zstd header, which 480 objects in the recorded
  runs matched and none was an archive (computer-forensics-base 1.2.20); and
  the readable-form link follows content, so the same bytes remade under
  another job still lead back to the partial catalogue; and an object of the
  store named in a request carries its manifest's sha256, so asking for one
  the derived catalogue already has dedups with it and the agent is told
  which generation to read (run s8c228e catalogued the decrypted vault twice,
  13 s apart). memory-windows asks about 64 MiB and up, not 64 KiB: no
  Windows memory image is smaller, and of its 16 derived offers in the
  recorded runs the 10 under 64 MiB were SQLite dumps and screenshots, none
  memory (computer-forensics-base 1.2.21).
- Four workers by default on a host with 64 GiB or more; `create_ms` in
  each job's record.
- The console has a Jobs tab (with Files and the Ledger): the run's jobs
  from the store's journal, paged, with totals, the job service's notices,
  the examiner's notes and custody's store line; a job's record, its
  journal lines, its manifest and its logs, paged or whole. "Committed"
  (sealed) is shown apart from the job's outcome, never as a success.

### Added: tool jobs in worker VMs, a sealed store, a catalogue that grows

- **The job service** (`scripts/job-service.ts`, in the hub). A tool job — a
  pack or forged tool with its arguments, a shell command, a recipe over one
  object — runs in a throwaway worker VM of the run's image. It sees what an
  agent sees, read-only (the evidence no-exec, `store/`, `catalog/`,
  `tools/`, `tool-output/`, the packs, all of `work/`), and writes only its
  own directory (`$OUT`); no network unless the job asks for the run's
  allowlist (plus PyPI with `--allow-install`, pip's list kept before and
  after), no credential, nothing of the board or the run's own records.
  Every step is a line of `store/journal.jsonl`, hash-chained, fsynced and
  anchored beside the run (`<sandbox>.journal-anchor.json`): accepted (who
  asked, with the name and doing it had given itself), started (the scope it
  declared, the mounts it was given, the network, the image, the worker's
  size; what it read is said to be unknown), finished, fenced, committed.
  Nothing of a staging directory is read before its worker is gone. A failed
  or timed-out job keeps what it wrote, and its stderr is shown whatever its
  exit; recovery after a crash finishes each job from the step it stopped
  at, and runs a job the hub's death interrupted once more only when it had
  no network. `--workers N` (default 2), `--worker-cpus`, `--worker-memory`
  (4 GiB on a host with 64 GiB or more, else 2), `--no-jobs`.
- **Agents' tools**: `job_run` (a command, or a tool with its arguments; a
  short job answers in the call, a longer one is posted when done, never
  both), `job_status` (a job's record and its stdout paged whole; cancel
  one's own), `catalog_request` (a recipe, or a detect pass that finds the
  recipes that apply, over one object of the run). A job's file is cited as
  `job:<id>/<path>`.
  The same recipe over the same object is one job: a second request is
  journalled (`job_deduplicated`) and its agent told when the job is done.
- **Workers are made by a child process, and a fence is a fence.** On Ali
  Hadi #10 every worker after the 64th failed to boot inside the hub's
  long-lived msb SDK ("insert run: FOREIGN KEY constraint failed"), while a
  fresh process made one fine, and each was recorded as fenced although msb
  listed it afterwards. The hub now makes and runs each worker through a
  short-lived `vm.ts worker-once`, one made at a time; the fence needs that
  process gone, inspect not knowing the worker and msb's list, read whole
  and understood, not showing it. A worker msb refused to start before
  anything ran is removed and made once more, the first error kept. After
  three jobs in a row that ran in no worker, every agent is told once to do
  that work in its own VM, and again when a job runs.
- **An examiner's note on the record**: `evidence-store.ts note <sandbox>
  --by NAME --text TEXT [--job ID]...` chains an attributed correction onto a
  finished run's journal, never an edit; refused while the hub runs. Custody
  counts the notes.
- **The store** (`scripts/evidence-store.ts`): a job's output sealed into
  `store/jobs/<id>/out/` — links, FIFOs, sockets and devices recorded and
  left out, names kept as bytes, files read-only and hard-linked to
  `store/blobs/<sha256>` so the same bytes are kept once — with a manifest
  of every file. Custody checks the journal against its anchor (telling an
  anchor one step behind, a crash between two writes, from one off the
  chain), hashes every committed file again against its manifest and names
  staging left unsealed, and names the findings that cite no object of the
  run (a job, an input, a path of its objects) as an audit gap; `package` exports the journal, its anchor, each
  job's record, manifest and logs, the census, the plan, every generation
  and revision, and the recipes that made them.
- **Catalogue recipes are the packs'** (`recipes/<name>/` with a
  recipe.json and an entry answering `detect` and `run`): computer-forensics-
  base 1.2.17 ships disk-volumes (The Sleuth Kit), memory-windows
  (Volatility) and archive-members (a tar, zip or 7z member list without
  extracting; names kept as bytes, duplicates as rows, zip DOS times marked
  zone unknown, a truncated tar reported partial, a name that is not UTF-8
  flagged as one macOS cannot store). The harness takes the
  census (`scripts/evidence_catalog.py`): each recipe says the smallest
  object it is asked about, so a small zip is offered to the archive recipe
  and not to the disk one. In a microVM run the census plans the recipes and
  the job service runs them while the agents work: each result is a
  generation under `catalog/gen/`, each change a new revision under
  `catalog/revisions/<n>/`, announced on the board; a disk's file list is
  also linked at `catalog/<input>/` as before.
- **catalog_search** v8 reads the newest complete revision (or the one
  named), a generation by its id, and an archive's `members`, and says which
  revision it read.

### Changed: agents run in microVMs by default (breaking)

- **`--isolation microvm` is the default.** A run with no `--isolation` and
  no `SWARM_ISOLATION` puts every agent in its own microVM, and so does
  `netcheck`. The old behaviour is `--isolation host` (or
  `SWARM_ISOLATION=host`): every agent a Pi process on this machine, held by
  the host guards. Host mode is kept and supported; the kickoff, `help`
  and the console call it unisolated wherever it is chosen.
- A host that cannot boot the VMs (an Intel Mac, Linux without KVM or glibc,
  no msb, an image that is not there and cannot be pulled, VMs that do not
  fit) is refused before anything is written, with what it lacks, how to fix
  it (the base image's build commands among them) and `--isolation host` as
  the unisolated way on. It never falls back to a host run on its own.
- A host guard's flag (`--no-write-guard`, `--no-seal-herdr`,
  `--inputs-enforce`, `--key-from-env`, `--probe-violation`) with no
  `--isolation` is refused with the hint to add `--isolation host`.
- The console's New swarm form has the microVM switch on by default and
  always passes `--isolation` explicitly; its API takes `isolation: "host"`
  for a host run.
- A registry record with no isolation (every run from before this change)
  is a host run, and `list`, `status`, the console and the report show it as
  one.
- The kickoff prints an `Isolation:` line. The quick start builds the base
  image before the first run; the keyless proofs it shows are host runs, as
  they were proven.

### Changed for host runs

What the microVM work changed for host runs as well, so a host operator is
not surprised:

- Every trace line carries its process's id and count (`sid`, `seq`) and the
  collector's `recv_ts`; the idle watchdog and the console order by the
  latter. The watchdogs spill to `traces/system-spill.jsonl`, not `work/`.
- A kickoff that stops after registering puts away what it started and
  records the run as `failed`. The registry is written under a lock. The
  host is asked not to sleep for the run (`caffeinate`, `systemd-inhibit`;
  neither holds against a closed laptop lid; one the system refuses, such as
  systemd-inhibit for a user with no login session, is said as a WARN, not
  claimed). A sandbox a running run uses is refused.
- `stop` takes custody (see Added; `--no-custody` skips it,
  `--custody-timeout SEC` bounds it, 14400 by default) and says where it was
  if interrupted. Custody re-reads every evidence file, so a stop on a large
  case takes as long as hashing the evidence once more. `reap <id>` touches
  only that run.
- The console binds `127.0.0.1` by default. It bound `0.0.0.0`, so anyone on
  the LAN could read the board and the trace without a token; `--host
  0.0.0.0` opens it to the LAN on purpose.
- The finish line `done` runs is read from the registry only. It looked for
  the registry beside the sandbox and fell back to the agent-writable
  `SWARM.md` in silence; panes now get `SWARM_RUNS_DIR`, and a finish line
  that is met but was read from anywhere else cannot certify a run
  (abandoning still ends it).
- The trace token and the console's token are masked in every trace line. A
  shell's `env` in a tool output had put both into the trace.
- Pack and library tools are registered at session start with forging off,
  and named in `--tools`. They loaded only with `--allow-tool-forging`,
  although the contract listed them as ready. A `--tools-from` tool of the
  same name no longer replaces a pack's tool: the pack's copy is kept, and
  different bytes are said.
- Pack secrets are implemented (`docs/packs.md` §4): a pack tool gets its
  pack's secrets in its own child's environment, and the trace row and the
  output carry `[secret NAME]`. On the host that needs `--allow-pack-secrets`,
  since a pane can read what its extension can; a pack that requires a
  secret is refused without it. The secrets live in
  `$DFIRSWARM_HOME/secrets/<pack>.env` (`~/.dfirswarm` by default), not inside
  the pack; a reinstall moves an old one, and a pack that declares secrets
  and still has a `secrets.env` in its directory stops the kickoff in either
  mode. Shipped packs were resealed with corrected install lines
  (`pff-tools`, `libfwsi-python`, plaso from PyPI), pinned downloads, and
  after the review with names checked against Debian 12 and PyPI (zeek,
  suricata and radare2 are manual, `libfwsi-python` is a Python library, the
  encrypted-containers pack installs pybde, pyvhdi, pyluksde, pytsk3 and
  dfvfs, and `vss_stores` and `mem_fs` mount under the seat's own
  directory).
- `--allow-install` sets `PIP_BREAK_SYSTEM_PACKAGES=1` in every pane:
  `pip install --user` was refused on a PEP 668 system. The installs still
  go under `work/.toolchain/`, and the Python install paths now reach a
  forged or pack tool's child, which could not import what an agent had
  installed. The inventory also reads a venv an agent made under
  `work/.toolchain/`.
- The inputs integrity walk no longer stops at 5,000 files and 12 levels.
  Every manifest file past it read as missing, so a KAPE-style triage set
  failed the check on every sweep.
- `start --no-start` no longer leaves the collector, the gate and the broker
  running.
- The report says when refused connections are not observable, where it said
  "nothing was refused" with no log behind it, and names each model's
  provider hosts, recorded at kickoff.
- `tools --save` keeps only sealed tools, with `provenance.json` and without a
  `pack` field; `pack.sh adopt` takes a saved tool into a pack. The toolbox's
  use column read " head -1" for every tool; fixed.
- The netguard allowlist takes a provider's host from `models.json` for a
  built-in provider too, and from Pi's model list for the providers Pi ships;
  `--provider-host` adds one. `--local-only` refuses a cloud `--compact-model`.
- The console: a `failed` state, a packs field, `*.name` allowlist entries.
- `microsandbox` is an optional dependency (`npm ci --omit=optional` for a
  host-only install).
- The idle watchdog is a host run's stop from outside the panes: past a cap
  or the wall clock it claims the stop clock (and says so on the board) when
  no pane has, and past the grace period writes the sentinel as the harness.
- Custody opens nothing through a link and waits on no FIFO; every evidence
  file is re-hashed in full whatever its size, against one deadline checked
  inside the read, and an unfinished re-hash says so rather than
  "unchanged"; the trace is read a line at a time; the ledger is held to the
  trace (an entry deleted from its end, or written without the tool, is
  named); `artifacts.json` indexes `work/`; the verdict's hash is anchored
  outside the run. `stop` bounds it from outside too.
- The ledger's chain covers each entry's provenance (source, evidence,
  confidence); an unchained line after chained ones breaks it, and so does
  a version 1 entry after version 2 ones.
- Evidence FIFOs, sockets and device nodes are recorded by their kind and
  checked by kind; the evidence manifest and its anchor are read-only on
  disk, and the manifest's hash is in the run's record.
- A peer's own directory is refused for claims and writes; the report reads
  the swarm's own report only inside the run and never through a link; the
  package copies only regular files (a link left in place of a spill had
  put a host file into the handover).
- A trace line a pane could write nowhere is said on its next line and
  counted by custody; the host spill is watched as append-only.
- Pack secrets are refused on a suffix; two packs' tools of one name keep the
  first. `tools --save` copies a tool only as its sealed version, with what
  it ran with. A forged tool may name the programs it calls (`requires`).
- `list` has a `HELD` column; run ids are six hex digits; a pane helper that
  opened a workspace no longer loses it (they ran in a subshell); a kickoff
  that fails before its record is written clears what it started.
- Warnings: a run kept in a synced folder, a Mac on battery, a suffix in the
  allowlist, writable evidence directories, a host run whose panes cannot be
  kept from a live VM run's hub, a run started as root. An IPv6 allow entry
  is written `[v6]:port`, and netguard reads it. GitHub Copilot's token host
  is allowed.
- **Event times carry their zone.** A ledger `ts` without `Z` or an offset
  is refused, and so is a form like `01/02/2024`; a date alone is that day
  at 00:00Z. A zone-less time was read in the host's own zone, so one entry
  was 12:44Z on the droplet and 09:44Z on a Mac in Istanbul. An offset is
  converted to UTC, and the text as written is kept as `ts_raw` and shown
  beside the UTC time in `ledger.md`. The agents and the run's own
  processes (the hub, the collector, the watchdogs) run with `TZ=UTC`,
  which an `--env TZ=` overrides; the registry records the host's clock as
  the run found it (`host_clock`: zone, offset, and whether it was synced,
  where the host can say).
- **The run records what produced it** (`provenance`: the harness commit and
  whether the checkout had local changes, Node, Pi, msb and the image digest
  for a VM run, the OS). The report shows it with the host clock, says that
  an AI agent swarm prepared it and that its findings are the agents'
  conclusions until an examiner reviews them, names each exhibit's model,
  and lists the tools the agents forged as not independently validated.
- **The operator is on the record.** Every `start`, `stop`, `reap`, `say`,
  `package`, `report`, `tools`, `review`, `export`, `hold`, `release`,
  `purge` and `verify` is a line in `runs/operator-audit.jsonl`
  beside the registry: when, the OS user and host, through what (the command
  line, the console, the hub's own clear-up), the arguments with `--env`
  values and the goal left out, and the sha256 of the line before. A
  `start`, `stop`, `reap`, `say`, `review`, `export`, `hold` or `release` of
  a live run is on its trace too, as `operator_action`; from a shell that is not the kickoff's it is marked
  unverified there, and custody, the report and the summary count such
  lines as the operator's actions, not as lines no pane accounts for.
- **Node 22.19 is the floor.** `engines` said 22.6, but the pinned Pi and
  its HTTP client declare 22.19.0, and on an older 22 the harness extension
  does not load. A CI job runs the typecheck and the node suites on exactly
  22.19.0.
- **A host run started as root is refused** unless `--allow-root`: root is
  not bound by the read-only modes a host run relies on. A microVM run
  started as root is warned about.
- **The caps are taken before each model call too.** A seat past its grace
  period, or whose swarm the sentinel ended, is stopped before the call goes
  out, with the same outcome as the stop it replaces and a
  `budget_precall_stop` line. On the host this is the brake; in a VM it is
  advisory, and the hub's cap stop and wall clock are the host's brakes.
- **A long command run a second time is pointed at its first run's output.**
  A shell command that took a minute or more (`SWARM_REPEAT_HINT_MIN_MS`),
  ended without error and was kept whole under `tool-output/` is
  remembered; the same agent running it again gets one paragraph naming the
  kept file to grep or read instead (`repeat_hint`, once per command). The
  harness names no tool.
- **The kickoff records whether the runs' volume is encrypted at rest**
  (`disk_encryption`: FileVault and APFS on macOS, a crypt device under the
  mount on Linux), prints it as a `Disk:` line and warns when it is off.
- **The evidence copy keeps the evidence's links as links.** `cp -RL`
  followed every link: an extracted root's `etc/hosts` became the examiner's
  own file, vouched for by the manifest. Only a link at the top of
  `--inputs` (the operator's own) is followed; links that lead out of the
  evidence are listed at kickoff. The copy is checked against its source by
  name, kind and size, and then by content: each copied file's source is read
  again and its SHA-256 compared with the manifest's (`source_checked`); a
  mismatch (names merged on a case-insensitive volume, a short read, other
  bytes) stops the kickoff. `--no-verify-copy` keeps the first check only. A name that is
  not UTF-8 is kept exactly (`path_b64`, `link_b64`) and compared as bytes
  by the agents' check and by custody, so a Windows-1254 name on ext4 is no
  longer both missing and added.
- **The manifest carries SHA-1 and MD5 beside SHA-256**, from the same read,
  to match an imager's acquisition hashes. Custody and the agents' `inputs`
  check compare them when the manifest has them; SHA-256 decides, and a
  file whose SHA-256 matches while another digest does not is listed as
  `digest_mismatch`. The report and the summary list them beside SHA-256
  and say how the copy was checked against its source.
- **A synced folder is refused, not only warned about.** A copy of the
  evidence, or the VMs' kept disks, is not put in a folder a sync client
  uploads (Dropbox, iCloud Drive, OneDrive, …) unless
  `--allow-synced-folder`, or a `.dfirswarm-allow-synced` file of the
  operator's at the top of that synced folder (or between it and the
  destination); the registry says which allowed it. The check runs before
  anything is written, where it used to run after the evidence was copied
  there. A run directory there is still warned about for what the agents
  derive.
- **Custody writes nothing through a link.** The previous verdict is set
  aside as `custody.previous-<stamp>.json` before anything is checked, and
  every file custody writes goes to a fresh file renamed into place: a host
  pane's link had made custody copy a credential file into the run and
  overwrite an operator's file with its own JSON. A custody ended by its
  deadline, a signal or an error writes what it found and names what it
  never reached (`not_reached`), so after a failed custody `custody.json` is
  that partial verdict or absent, never the older one. A directory of more
  than 125,000 evidence files, or a manifest over 256 MiB, no longer breaks
  it; a file the host cannot read is `unreadable`, not missing; the ledger
  is held to the trace whatever the trace carries, and a seat's spill fills
  only its own gaps. The report, the summary and the console say whether
  `custody.json` matches the verdict anchored outside the run, and the
  report says "NOT FULLY RE-HASHED", not "NO", when custody ran out of time.
  Custody's verdicts and `artifacts.json` are harness files no seat claims
  or writes. The artifact index is ordered by code unit, so its anchored
  hash no longer depends on the locale.
- `start --custody-timeout SEC` bounds the custody taken at the run's end,
  by the hub or by `stop`; it is recorded (`custody_timeout_sec`), and
  `stop --custody-timeout` overrides it for that stop.
- **The console shows an agent's HTML without scripts**, the report too: a
  script could navigate the frame with the file's contents to any host,
  past every allowlist of the run. **Open with scripts** runs one file's
  scripts in that view after a warning, through a one-time grant (it needs
  the console token, is bound to the file's sha256, is spent on first use
  and lapses after a minute), and each opening is on the run's trace as
  `artifact_scripts`.
- A trace that is there and cannot be read is said so, rather than shown as
  no trace: by the report, the summary, the dossier and the console's trace
  and swarm views. The report checks the chain a line at a time, so a trace
  past 512 MB is read and checked.
- `budget.json`, history's index and a ledger merge are written whole (a
  temporary file and a rename); a usage report refuses a `budget.json` it
  cannot read rather than rebuilding the run's caps from defaults. A peer's
  ledger merge (an author added) is no longer charged to a seat's shell
  call as RECORD REWRITTEN. A lost trace line is counted once.
- `stop` ends a daemon only when its pid is that daemon for that run: after
  a reboot, or with a pid file a pane rewrote, it could have named any of
  the operator's processes. A `stop` of a run nothing of which is alive
  says the host restarted or the run crashed, with the trace's last time.
  Two host kickoffs at once no longer share one netguard proxy. The
  console's host kickoff stays a host run whatever `SWARM_ISOLATION` says.
- New trace names (`operator_action`, `artifact_scripts`,
  `collector_restarted`) are reserved: no forged tool takes them.

### Added

- **Every image says what it holds, in the VM: `/etc/dfirswarm/tools.md`.**
  One line a program: its name, what it is for (its pack's own `why`), its
  pack, and the version its package record holds (a `--version` probe had
  answered "invalid option" for a third of them); then the Python libraries
  the packs and the tool library install, with the note on each one's line;
  then what a pack names that the image does not hold. `install.py` writes it
  beside `image.json`, the NOTICE and the SBOM, in the base and in every
  profile, and the image check records it in `toolbox.json` (`tools_md`).
- **The programs the sixth CTF round's agents went looking for are in the
  images.** Each had been searched for, pip-installed by hand, or forged:
  - `pdftotext` (poppler-utils, with `pdfinfo`, `pdfimages`, `pdftohtml`) in
    computer-forensics-base 1.2.13: five agents shared a forged PDF reader and
    two pip-installed pypdf because the image had none.
  - `ccl_indexeddb_dump`, a pinned source of ccl_chromium_reader 0.3.18 (not on
    PyPI) with its library in a venv of its own, in computer-forensics-base:
    Element's IndexedDB on the BelkaCTF #6 laptop had no reader.
  - `heif-convert` (libheif-examples) and `pillow-heif` in mobile-forensics
    1.0.4, for an iPhone's HEIC photos.
  - `impacket` and `dpapick3` in windows-forensics 1.2.9, for DPAPI, the
    Credential Manager and Windows Vault read offline (both were pip-installed
    on "Encrypt Them All").
- **GnuPG in the encrypted-containers images** (encrypted-containers 1.1.2):
  `gpg`, to read an OpenPGP message's packets before any key is known, import
  a private key found on the evidence, and decrypt once its passphrase is. Only
  `gpgv` was there; on the sixth CTF round an agent on "Encrypt Them All"
  spent its turns looking for an OpenPGP reader on PyPI, where `gpg` needs
  `gpgme.h` to build.

- **Every program a pack names is in the image profile that holds it, or
  said not to belong in one.** The recipe knew an apt line, a pip line and a
  pinned download, and listed everything else as manual, never installed:
  Eric Zimmerman's tools, RegRipper, Zircolite, bulk_extractor, mac_apt,
  UnifiedLogReader, iLEAPP, ALEAPP, Zeek, Suricata and radare2 were in no
  image. A pack's `requires/host.json` now says how, as data, and the harness
  knows only the kinds: a pinned `.deb` per architecture, handed to apt
  (radare2 6.2.2, Zeek 8.0.10 from the Zeek project's Debian 12 packages); a
  tag's source (`install.source`) unpacked under `/opt/dfir/src/<name>`, its
  requirements in a venv of its own, its entry on PATH through its
  interpreter (Zircolite 4.0.0, UnifiedLogReader, iLEAPP 2026.4.2, ALEAPP
  2026.4.1, and mac_apt 1.33.2 for amd64 only: on Linux arm64 it stops at
  import, and an arm64 image says so); `env` and `arches` on a source or a
  build say what its build needs and which architectures it is for; a
  program run by another the image holds
  (`run`: MFTECmd, EvtxECmd and RECmd 2026.5.0 on the .NET 9.0.20 runtime,
  which the pack pins as a download of its own); a source compiled in a
  builder stage (`install.build`), so the image carries the program and not
  the compiler (bulk_extractor 2.2.0); and an apt line from the image's own
  backports (Suricata 7.0.10 from bookworm-backports). RegRipper is Debian
  12's `regripper`. Each artefact is checked against its sha256 before
  anything is unpacked, installed or built, and is in `image.json`, the
  NOTICE and the SBOM with its kind; an optional one that fails is recorded,
  not fatal. Apple's `log` and CyLR are marked `not_in_image`: `image.json`,
  the NOTICE and a VM's toolbox check list them as not applicable, never as
  missing, the probe asks no image for them, and `pack.sh seal` refuses one a
  pack requires. Every profile was built on arm64 and each program run in
  it, in a container and in a VM (`images/README.md`). Resealed:
  computer-forensics-base 1.2.12, windows-forensics 1.2.8, macos-forensics
  1.0.3, mobile-forensics 1.0.3, network-forensics 1.0.3,
  reverse-engineering 1.0.3, triage-collection 1.0.3.

- **The examiner's review of the ledger** (`swarm.sh review <id>`): accept,
  reject (with a note) or amend (with a note) each entry, and sign off the
  ledger once the run has ended, over its current head. Kept beside the
  registry where no agent reaches (`runs/reviews/<id>.jsonl`, 0600), each
  line chained to the one before, appended and never rewritten. The report
  shows each exhibit's standing (accepted, rejected, amended, not reviewed,
  or review unreadable) on its head and in its rows, the counts, whether the
  review's chain verifies, whether the sign-off covers the ledger's current
  head, and "reviewed and signed by" on the cover; until then it says every
  finding is the agents' conclusion. The console's Ledger tab takes the
  review through the same command.
- **Ledger corrections and searches that found nothing.** `record(…,
  supersedes=<seq>)` records a correction; nothing is deleted, the corrected
  entry is marked "superseded by #N" where it stands and the correction
  "corrects #M", and the link is in the chained core, so it cannot be moved.
  An entry is corrected once. `record(kind=absence)` is a search that found
  nothing, with what was looked for, what was searched, and the query, the
  tool and its version and the scope, all required; `ledger.md`, the report
  and the summary list absences apart, valid only for that scope, never as
  findings. Both are optional.
- **Coverage and grounding** (`scripts/coverage.ts`): which evidence files no
  command on the trace named, and, for each ledger entry, whether a call
  before it named its source. Generic path matching over every call's
  arguments; it knows no tool, and "named" is not "examined", which every
  place it appears says. The report (a "Named by" column, the list of
  unnamed evidence, "not grounded in the trace" on an exhibit), the summary
  and the console carry it, and the idle watchdog posts the unnamed inputs at
  a quarter, a half and three quarters of the wall clock, assigning them to
  nobody.
- **A package that can be signed and checked.** `swarm.sh package <id>
  --sign [--key FILE]` signs the manifest with an ssh key (`ssh-keygen -Y
  sign`, namespace `dfirswarm-package`) and writes the signature, the public
  key and who signed beside it; `swarm.sh verify <dir|zip>
  [--allowed-signers FILE]` re-hashes every file (none missing, changed or
  added) and checks the signature (exit 0, 3, 4 or 1). The package also
  carries `court-set.json` (every file handed over, with its size and sha256
  or why it is absent) and this run's lines of the operator's record, and
  the report lists the files handed over with it.
- **Export**: `swarm.sh export <id> --format csv|timesketch` writes the
  ledger as CSV (every field, the entry hash, superseded by, the review,
  grounding) or as a CSV Timesketch imports. A text cell a spreadsheet would
  run as a formula gets a leading apostrophe.
- **Retention**: `swarm.sh hold <id> [--reason]` keeps a run from purge,
  from a new run in its sandbox and from the VM reaper; `release <id>` lifts
  it. `swarm.sh purge <id> --yes` deletes a finished run's sandbox, its kept
  disks and its hub directory, refuses a held or running run, keeps the run
  in the registry as `purged`, and writes a destruction record (what, with
  sizes, and the hashes of the inputs manifest, the custody verdict and the
  package manifest) on the operator's record.
- **`--notify CMD`**: a command of the operator's hears a run's
  `finished`, `finish_failed`, `stop_incomplete`, `budget_cap`,
  `wall_clock`, `evidence_changed`, `chain_broken`, `agent_dead`,
  `collector_unreachable` and `hub_down`, as one JSON line on stdin,
  detached, within 30 seconds. It is kept outside the run
  (`runs/notify/<id>.cmd`, 0600); the registry records only that there is
  one, and the command line is redacted on the operator's record.
- **`--ledger-from RUN`**: an earlier run's ledger as hypotheses to
  re-derive or refute, in `prior/ledger.md` (read-only; with the earlier
  run's review, only the entries the examiner accepted or amended; without,
  every entry marked unreviewed), never in the new ledger. The worker prompt
  says to cite the evidence, not the prior entry.
- **The model gateway (`--model-gateway`, VM runs, off by default).** Every
  model call a VM makes to a provider the gateway fronts goes through one
  process on the host. It holds the provider's key in memory, reads each
  call's usage off the provider's own answer (OpenAI chat and responses and
  Anthropic messages, JSON and streaming, priced as Pi prices them), refuses
  a stopped seat's call at once and a call past a cap or the wall clock
  three minutes after it was crossed, and is not a general proxy. The VM
  holds a seat token, never that provider's key. The hub folds the measured
  spend into `budget.json` (`metered_by: "model-gateway"`), so every cap
  reads it; `traces/model-gateway.jsonl` has one chained line per call and
  no bodies, custody checks its chain and anchors its hash, and the report
  says which spend was metered on the host. Subscriptions, Bedrock, Vertex,
  Google, Mistral, OpenRouter, Fireworks, Azure and local models keep msb's
  placeholder path, and the kickoff names each. docs/model-gateway.md.
- **VM runs: each seat's socket serves only its own VM.** The kickoff makes a
  token per seat, gives it to that VM (`SWARM_SEAT_TOKEN`) and to the hub,
  and every connection must open with it or is refused and named on the
  trace (`seat_auth`). The tokens rest in the hub directory, the VM's
  environment and msb's database while the VM lives; never in the trace,
  the registry, a VM record or a package. The hub also cuts `replies.jsonl`
  back to the answers it keeps, bounds each seat's file history
  (`SWARM_HISTORY_QUOTA_MB`, 1 GiB; past it a revision is recorded by its
  hash and the seat is told once), puts a seat that said done away when it
  was due across a hub restart, and calls `--notify`. The keeper, the stop
  the hub runs, the idle watchdog and the gateway run from the run's frozen
  copy of the harness.
- **`swarm.sh start --check`** runs every refusal and preflight of a start,
  the same code, and writes nothing (no sandbox, registry entry, hook,
  daemon, VM, pull or operator-record line): exit 0 when the start would go
  ahead, 2 when it would be refused. **`swarm.sh image-for [--pack ID]...
  [--tools-from DIR] [--playwright]`** prints, as JSON, the image a kickoff
  with those packs would boot, its digest when known, and why. The console's
  New swarm form uses both before Start.
- **`scripts/score.ts`**: an accuracy check the operator runs by hand
  against an answers file of their own; it prints found, not found or
  contradicted per question and writes nothing anywhere.
- **The console shows a microVM run as itself.** An isolation chip on every
  run; a VM panel with each probe check and what it means, what the hub
  refused, hub and collector restarts, a keeper that gave up, the kept disks
  (path, size, hash, or why not, with the remedy) and msb's database; one
  timeline of the run's life across its VMs; a seat's state from one source,
  the hub while it hears from the VM, watched where it lives; `system via
  <seat>` posts shown as that seat's; a Custody tab; coverage, corrections
  and absences in the Ledger tab; a record dialog to hold and release,
  export, package (signed or not, downloaded as a zip), verify and, behind
  the run id typed out, purge. The kickoff form checks the host can boot the
  VMs, shows the image the packs choose, and takes the new options; it never
  shows an `--env` value or the notify command. Stop takes custody's options.
- **CI**: actions are pinned by commit; a job runs the node suites on the
  Node floor; `image-boot.yml` builds every image profile once a week, boots
  each as an agent's VM (the probe, its verdict and Pi end to end), checks
  it against its packs with the kickoff's `imageFit`, and does the same for
  base on arm64 where the runner has KVM. Nothing is pushed.
- **The worker prompt** asks agents to read a tool's usage for the options
  that change what its output means before relying on it, to keep a large
  artefact's full walk under `work/<id>/` and grep it, to correct a ledger
  entry with `supersedes`, and to record a meaningful empty search as an
  `absence` with its scope. It names no tool.
- **Agents in microVMs (`--isolation microvm`).** Every agent runs Pi inside
  its own microVM (microsandbox 0.7.2; macOS on Apple silicon, Linux with
  KVM), created at kickoff through the SDK (`scripts/vm.ts`) and put away by
  `stop` with each disk kept as a snapshot msb can verify. ADR 0009.
  - The run is a read-only floor in each VM; the agent writes only its own
    `work/<id>/`, `work/extracted/<id>/` and `work/quarantine/<id>/` (both
    no-exec), `tool-output/<id>/` and Pi session. A shared file is written
    by the hub through `publish_file`, claimed and recorded. `--inputs` is
    used in place and mounted read-only; `--inputs-copy` gives the run its
    own read-only copy.
  - The board has one writer, the hub (`scripts/vm-hub.ts`); who is asking
    is the vsock port. The harness's own functions are not on the agents'
    channel, a sentinel is written only when the finish line passes on the
    host (a reason starting `ABANDONED: ` is let through unchecked, and a
    seat leaving on its own cap writes none), spend reports may only grow,
    and paths are resolved on the host without following a planted link.
    The hub keeps the wall clock itself; the caps apply to the spend each
    seat reports. A keeper (`scripts/hub-supervise.sh`) restarts a dead
    hub from its saved state until the run's stop.
  - No credential enters a VM: placeholders, swapped in by msb on the way
    to the credential's own hosts only, stopped and logged anywhere else.
    Subscriptions need `--allow-oauth-in-vm`. `--provider-host P=HOST` names
    a provider's host when the harness cannot (Pi's own model list names the
    hosts of the providers it ships); a provider with none is refused.
    msb keeps a live VM's secret values in its own database on the host: the
    kickoff makes `~/.microsandbox` its user's alone, and a finish that
    removed VMs rewrites that database without their leftover bytes
    (`sqlite3` on the host; `stop` warns when it could not).
  - The image is the smallest profile that serves the packs, pulled before
    the run starts, booted by one digest; a program a pack requires that the
    image lacks stops the kickoff. Images carry a NOTICE, pinned downloads
    checked by sha256, and refuse to bake programs marked not redistributable
    without `--allow-nonredistributable` (`images/README.md`).
  - `netcheck --isolation microvm` asks msb what a run's VMs would reach.
    The report and the console's VM panel say what each VM was given, found
    and left: probe, image fit, clock, live state, installs outside the image.
  - The console starts a VM run (`isolation`, `image`, `vm_cpus`,
    `vm_memory`, `vm_disk`, `vm_snapshot`, `allow_oauth_in_vm`,
    `provider_hosts`); its default "copy" of the evidence is sent as
    `--inputs-copy` in a VM run, and a run whose hub could not put its VMs
    away shows as `finish_failed`.
- **Host custody at stop** (`scripts/custody.ts` → `custody.json`, printed by
  `stop` and carried by the report), both modes: the evidence re-hashed in
  full against a manifest anchored outside the run, every session file
  sealed, every kept output checked against the trace, the trace and the
  ledger chains, spilled and lost trace lines by their numbers, and every
  kept VM disk checked against its record and by msb.
- **VM integration tests** (`npm run test:vm`) on real VMs, one of them end to
  end with a scripted model, and a CI job that runs them on a KVM runner with
  the base and disk images built from this repository.
- **What the final review of the microVM work changed** (ADR 0009):
  - The hub never opens a file under a seat's own directory: a revision, a
    publish and the disk side of a diff come from the VM with the call (32,
    32 and 16 MiB), a seat restores its own file in its own VM, and a
    forged tool runs only as its sealed bytes. The host's own reads are
    checked again after the open (on Linux against `/proc/self/fd`).
  - The hub bounds each seat (connections, bytes buffered, calls, a rate for
    posts and records), answers a resent call once, keeps its lines
    numbered, refuses to run twice, resumes a finish it died in, clears up
    the run with `stop --after-hub`, and is kept by `scripts/hub-supervise.sh`;
    it runs from a frozen copy of the harness. A seat that is done has its
    VM put away a grace period later.
  - `stop` exits 3 and records `stop_incomplete` while a VM of the run is up,
    and waits for a hub that is finishing. Below 4 GiB free a VM is kept
    rather than snapshotted and removed; `--vm-snapshot-dir` puts the disks
    elsewhere.
  - `work/extracted/` and `work/quarantine/` are no-exec in every VM, a
    peer's corner as well as one's own. Each VM's probe checks that, that
    the evidence is no-exec, and that it can reach its model's hosts.
  - Pack secrets need `--allow-pack-secrets` in a VM too (the placeholder is
    in the whole VM's environment); `--local-only` withholds them; a local
    model's real key is refused; credential headers are swapped at every
    depth; a LAN model's name is resolved on the host; llama.cpp gets its
    environment; Pi's model catalog goes into the guest.
  - The catalog VM leaves only files and directories, is put away on `^C`
    and reaped if left; a VM that does not come up times out; `msb` other
    than 0.7.2 is warned about; a lock pinned by tag is refused.
- **What the second review of the microVM work changed** (ADR 0009):
  - The hubs live in `~/.dfirswarm/hubs`, one directory per user, 0700, and
    refused when it is a link or someone else's (`SWARM_HUBS_DIR` moves it).
    Under the caller's `$TMPDIR` a stop from ssh, cron or sudo found no hub
    and left it and its tokens running, one `/tmp/dfirswarm-hubs` served
    every Linux user, and on macOS the six-hex run ids put an agent's socket
    past the 104 bytes a socket path may have, so every VM kickoff from a
    Mac terminal ended with "the VM hub did not come up". The kickoff now
    refuses a socket path over 103 bytes before it starts anything, and a
    reboot no longer takes the hub's state with it. The console, `watch.sh`
    and `await-done.sh` look for hubs there too, and a hub started with a
    longer socket path stops with an error naming the path and its length,
    where it died on a bare EINVAL.
  - What one seat holds in the hub counts lines waiting their turn and calls
    queued or running against its 160 MB; past it the seat's connections
    pause. A call that carries no file is refused past 8 MB. The hub, not
    the seat, picks how often `wait` polls. `done` is paced (three, then one
    a minute), and dones that arrive together share one run of the finish
    line. A `state` report is one of four states with at most 200
    characters of detail and no terminal control characters, and Herdr gets
    at most one report per seat every quarter second. A collector socket
    cut on a timeout fails only its own lines.
  - The hub stops a seat over its own or its model's cap for real: the
    seat's `done` marker is written and the stop is on the trace with its
    outcome. It had been refused in silence and retried every two minutes.
  - A harness post sent from inside a VM reaches peers as
    `from: "system via <seat>"`: the harness code in a VM is the guest's,
    so its word is that seat's, not the harness's.
  - A seat cannot publish onto the harness's own files in `work/` (the
    trace spill custody reads, the install area, the temp directory).
  - In a VM a seat's shell watch walks only its own directories, so a
    peer's large extraction no longer leaves the seat's own files unwatched.
  - The keeper also brings back a VM run's trace collector
    (`collector_restarted`) and counts crashes in a row; a keeper that gave
    up is not second-guessed by the idle watchdog.
  - A finish touches its lock as it works, and only a dead or silent
    owner's lock is broken; two finishes had worked the same VMs after half
    an hour. A second finish keeps the disk an earlier one kept until it has
    a new one, and the free-space floor counts the VM's own disk size.
  - msb's database scrub says "scrubbed" only when the checkpoint completed
    and no free page is left. The outcome is on each removed VM's record
    and on the hub's `vm_finish` line; `stop` warns about any removed VM
    whose bytes were not cleared, whoever removed it, and custody, the
    report, the summary and the console name it.
  - The hub takes custody at a run's finish within the operator's bound
    (`--custody-timeout`, `SWARM_CUSTODY_TIMEOUT`), where it was a fixed
    four hours.
  - Lower-case proxy variables in `--env` no longer reach a VM, and a failed
    `msb list` is said as that at kickoff and at reap.
  - Every shell suite runs with its own msb home and hubs directory: the
    stop suite had run the scrub on the developer's own msb database.

- **Agents compact their own context.** On by default at kickoff
  (`--no-self-compact` turns it off): each agent watches its context against
  an effective ceiling the harness sets per model (`extensions/context-ceiling.ts`:
  272k for the GPT-5.4/5.5 family, 200k for grok-4.6, 300k for a million-token
  model, the declared window otherwise), receives a transient notice at 40%
  and a warning at 50%, and at the compact line (60%) every tool except
  `self_compact`, `budget` and `done` is refused until it hands off with
  `self_compact(note_to_self)`. The context is summarized with the harness's
  own prompt (`prompts/compaction-summary.md`, written for a forensic swarm)
  and the note comes back verbatim under a header of facts read from files:
  the agent's name, its live claims, its unread posts, the ledger, the
  sentinel, its spend. The three lines take token counts or percentages
  (`--compact-notice-at`, `--compact-warn-at`, `--compact-at`,
  `--compact-prompt-file`) from the CLI and the console's kickoff form; the
  registry records them as `self_compact`. Pi's own overflow compaction stays
  as the safety net, runs with our prompt, and is recorded as one. The
  kickoff pins Pi's `reserveTokens` and `keepRecentTokens` in the sandbox's
  `.pi/settings.json`. Every crossing, hold, note and compaction is on the
  trace, with one `context` row per turn; `budget.json` carries the ceiling,
  the level, the lock, the compaction count and cost and the hand-offs per
  agent; the `budget` tool returns the same numbers to the agent; the
  summary and the report gained a Context and a Compactions column; the
  console shows the lines on the context bar, the compaction ticks on the
  activity span, and a Context section with the agent's context over time
  and its compaction history. Decided in ADR 0008; the run data behind it
  is in `docs/self-compaction-plan.md`. Proven end to end through the real
  CLI with a scripted provider (`tests/self-compact-e2e.test.ts`).
- **The trace keeps everything whole.** Arguments, results and reasoning
  are no longer clipped at 20,000, 2,000 and 2,000 characters; the collector
  and the gate accept lines up to 64 MB. The `_truncated` marker is read
  from archived runs and never written again.
- **Nothing a tool produced is dropped: `tool-output/`.** When a result
  reaches the model as a prefix, the whole output is a file in the sandbox
  and the trace row names it (`full_output`: path, bytes, lines, sha256):
  Pi's `bash` spill past 50 KB is moved in from the host's temp directory and
  the model's trailer names the sandbox path; a forged tool's stdout and
  stderr stream to it past 64 KB; `browser_check` keeps the whole page text
  the same way (`full_text`). `read`, `grep`, `find` and `ls` slices are
  recorded as such (`view`). The console links each file from the trace row
  (`GET /api/swarms/:id/tool-output/<path>`), and the forged tool's own trace
  row now carries its output, whole, where it carried a byte count.
- **No silent cut remains in the harness.** An `inbox` or `wait` row lists
  every delivered post's sender and id (the lists stopped at twenty); a
  provider's error text, a forged tool's error and an agent's `doing` are
  whole; the ledger's `source` and `evidence` (1,000 and 4,000 characters), a
  forged tool's parameter descriptions and its example (400) are refused
  over their limits with the reason, where they were cut in silence.
- **`inbox` and `wait` page by whole posts.** One delivery carries at most
  `--inbox-page-chars` characters of post text (40,000 by default, 0 for no
  bound; the console form has the field, the registry records it): a post is
  never cut, the delivery stops before the post that would break the bound,
  what stayed behind is still unread, the result says `remaining` and why,
  and `wait` returns at once while anything is unread. The two `wait` results
  of 578 posts and 64k tokens each on the Linux run s3096 are what this is
  for.
- **Per-model compaction lines.** Each of `--compact-at`,
  `--compact-warn-at` and `--compact-notice-at` takes a seat value followed
  by per-model overrides (`60%,openai/gpt-5.4-mini=55%,grok-4.6=70%`; a key
  with a slash is a `provider/id`, one without matches the model id under any
  provider). Resolved per seat against its own model; `compact_config`
  records which entry applied under `matched`. Same syntax in the console.
- **`--compact-model P/ID`: a summarizer for expensive seats.** Every
  summary call goes to that model; it is credential-checked and its provider's
  hosts join the netguard allowlist like a seat's model, and it is never a
  seat. Recorded as `self_compact.model`; `compact_config` says which model a
  seat will use and why, `compact_done` which one wrote each summary; a model
  Pi's registry does not know falls back to the agent's own with the reason
  on the trace. The console's form and goal panel carry it.
- **`swarm.sh context <id>`**, the context history of a run from its trace
  (`scripts/context-audit.ts`, Markdown or `--json`): per agent the model,
  the ceiling and the lines, the turns, the peak, the crossings, the holds,
  the hand-offs and Pi's own fallbacks with what each summary cost and which
  model wrote it, the largest climb in one turn, the outputs kept under
  `tool-output/`, the deliveries paged; then one sentence per thing the
  record says about the lines. What the defaults are revisited from.
- **The write guard reaches a pane whose login shell is bash.** The only
  hook was `$ZDOTDIR/.zshenv`, so a bash account was refused at kickoff (or,
  before that check, ran every pane unguarded). On such an account the panes
  are now given `HOME=<sandbox>/.bash`, whose `.bashrc` and `.bash_profile`
  put the panes' `HOME` back (an `--env HOME` if one was given), re-run the
  same bash under `fsguard.sh`, and then read the user's own configuration.
  `HOME` is moved for a bash account only, so a shell that reads neither
  hook keeps its own. The login-shell check now runs whenever a hook is
  written, `--no-write-guard` with `--inputs` or `--quarantine` included: a
  shell that is neither zsh nor bash is refused while the write guard or
  `--inputs-enforce on` depends on it, and warned about otherwise. A login
  shell the account database does not give is warned about rather than
  taken for zsh; before, a `getent` that exited non-zero (as it does for a
  user it does not know) ended the kickoff under `pipefail` with no message.
  Verified
  live on Ubuntu with Herdr 0.9.1 (`s5038` in `docs/verified-runs.md`).

### Changed

- **A team on a subscription is braked by tokens (breaking for such runs).**
  A seat whose provider is an OAuth login in Pi's store (`openai-codex`) no
  longer makes a team metered: Pi's dollars for it are an estimate, and on the
  BelkaCTF #6 run a Luna seat with ten million tokens read $0.13 beside a
  Daybreak seat's $14. A team with no metered seat needs `--cap-tokens`, as a
  team of local models does; `--cap-usd`, `--cap-per-agent` and a `@cap` on a
  model are said to brake nothing there. New: `--cap-per-agent-tokens`, the
  per-seat brake in tokens (budget.json and the registry as
  `cap_per_agent_tokens`).
- **Caps change while the run goes on: `swarm.sh cap <id>`** with `--usd`,
  `--tokens`, `--per-agent-usd`, `--per-agent-tokens`, `--wall-clock`. Made
  under the table lock the usage folds take, kept in `budget.json` as
  `cap_changes` with the caps each left (the shell watch no longer reports
  such a change as the agent's write, and now also watches the per-agent and
  per-model caps), put on the trace as the operator's, merged into the run
  record and said on the board. A swarm-wide stop the run is no longer over
  is withdrawn; a seat's own cap steer lifts on its next check. The run keeps
  its brake and a finished run stays finished.
- **`wait` sleeps through posts addressed only to other agents.** A post on
  `main` whose `to` names teammates and not the waiting agent no longer wakes
  it; it stays unread and the next delivery carries it, and the result counts
  it as `passed`. A post to all, to the agent by id or by the name it chose,
  or to no one on the team (a role, a word) still wakes it, as does any post
  in a side thread it is in; `every_post: true` wakes on everything, for a
  seat that follows the whole board. On the BelkaCTF #6 run 586 of 1,291
  wake-ups on posts were for posts to someone else, each a model turn with the
  whole context resent; the three GPT-6-Luna seats spent most of their 87M
  tokens that way.
- **The contract names no program when the image describes itself.** A
  microVM run whose image has `tools.md` gets one paragraph, "## Programs",
  that points at the file inside the VM; the table of sixty programs, a third
  of `SWARM.md` and read by every agent at every start, is gone for it. An
  image without the file, and a host run, keep the checked table.
- **A pack's tools are said to be in the tool list, not listed as another
  case's.** They sat under "Seeded tools (case-specific) … written against
  another case", with "baked: offset 20000" for a limit and an example
  FILETIME taken for an offset. The contract now says the packs put N tools
  in the tool list, each described there, general and fed by the arguments.
  Only `--tools-from` copies are listed as another case's, and "baked" is an
  `inputs/` path or an offset their example gives.
- **The goal's check on the trace for `inputs_check` says the harness writes
  it.** Read bare, `grep -q '"tool":"inputs_check"' traces/events.jsonl`
  sent five agents of sixteen on the sixth CTF round to forge a tool by that
  name to satisfy it (refused, as a reserved name). The contract adds, in
  prose, that `done` writes the line when it verifies the inputs.
- **A shell write in the writer's own directories takes no lease.** No peer
  may claim or write there, so the implicit claim protected nothing: one
  ileapp run was 507 of a run's 644 `claim_file` lines, each a lock file. The
  write is still snapshotted.
- **The kickoff's encrypted-volume warning is not given to a VM run that has
  `encrypted-containers`**: it told operators who had passed the pack to start
  again with it.

- The pinned `@earendil-works/pi-coding-agent` is **0.87.0** (was 0.85.1):
  npm `latest`, and what the Linux host already ran. The provider contract
  changed between the two (a transcript with system messages instead of
  `{systemPrompt, tools}`); the scripted provider behind the self-compaction
  e2e speaks both, and the suite passes on both.

### Fixed

- **Every input has a row in the catalog's coverage.** `evidence-catalog.sh`
  skipped an input under 64 KB, or one that was neither a disk nor a memory
  image, without a word: BelkaCTF #6's 5.1 GB iPhone tar had no catalogue and
  no mention in the index, and ten agents listed it with `tar -t` 59 times,
  7.2% of the run's input tokens. `catalog/coverage.tsv` now has one row per
  input with its status (catalogued, partial, segment, not catalogued, not
  probed) and why; the summary line counts them, and the index names what was
  not catalogued or catalogued in part, twenty of each and the count of the
  rest. A memory probe that finds no Windows image keeps what `vol` said under
  `catalog/probes/`. Inputs are enumerated NUL-separated, so a name with a
  newline in it is one input, and a tab, newline or backslash in a name is
  written escaped in the coverage file, the index and its notes.
- **A catalog step's stderr is kept whole.** A failed step kept 200
  characters of stderr in the index and deleted the rest; every step's stderr
  now stays beside its output as `<file>.stderr`, listed in the index, and a
  failure's note quotes its start and names that file.
- **`catalog_search` keeps every match.** It returned the first `limit`
  matches (200 by default) and dropped the rest, so an agent that wanted them
  searched again with a bigger limit: single results reached 70K characters,
  and search results were 2.7 to 12.5% of a run's input tokens. It returns 50
  by default with the count of all of them, pages with `offset` and
  `next_offset`, and when a page is not all of them writes every match, with
  its line number in the catalogue file, to
  `work/<agent>/catalog-search/<which>-<hash>.txt` and names it
  (`all_matches`). Version 7, in computer-forensics-base 1.2.14.
- **The library's catalog searches read the case in front of them.**
  `tool-library/catalog_search` was a first version that read
  `catalog/SysInternalsCase.E01` and nothing else, and `grep_filelist` read
  the AF-Case2 list on every case, while the docs hand the library to any run
  with `--tools-from tool-library`. The library's `catalog_search` is the
  pack's; `grep_filelist` (version 4) takes `path` or the only file list the
  catalogue has, and keeps every match past its hundred in a named file.
- **The agents are told the catalog's coverage.** The contract and the worker
  prompt said to read the catalog instead of running the same commands again,
  which was wrong for an input it did not cover; they now say to start from
  it, check `coverage.tsv`, and open what it did not catalogue with other
  tools.
- **A pack tool gets the timeout its manifest asks for**, up to an hour
  (`PACK_TOOL_TIMEOUT_MAX_SECONDS`). Every run clamped pack tools to the
  forged-tool ceiling of 120 s while telling the model the manifest's figure:
  26 of them ask for 300 to 3600 s, and `timeline_super` (3600 s) and
  `mem_carve` (900 s) died at 120 s. A forged tool keeps the 120 s ceiling, and
  the description and the timeout message say the timeout actually applied.
- **A failed tool call reaches the model as an error.** Pi takes a failure only
  from a throw and drops an `isError: true` a tool returns, so every refusal
  (`publish_file`, `record`, `done`, `name`, `make_tool`) and every failed pack
  or forged tool reached the model and its session as a success. The
  `tool_result` hook sets the flag from `ok: false` in the result's details.
- **A VM's probe asks the hub again.** With eighteen VMs running and a third
  run coming up, two seats of eight had their first connection close with no
  answer, twice, and the kickoff stopped with "no answer" and nothing else.
  The probe tries five times, three seconds apart, and records what the hub
  said, or that it said nothing, and how many tries it took. A close with
  nothing said reads the same whether the platform reports it as a clean
  close, a reset or a broken pipe, with the error kept beside it.
- **`regkv`, `regkeys` and `shellbags` answer a key that is not there** with
  the deepest key that is and the names under it (windows-forensics 1.2.9,
  the tool library's regkv 3 and regkeys 4). regkv printed regipy's
  traceback, twice on the sixth CTF round, for keys an agent had guessed.
- **`chunk_needles` streams what `icat` gives it** (computer-forensics-base
  1.2.13, the tool library's 3). It held icat's whole output in memory, and on
  a pagefile the VM's kernel killed it with nothing said, twice on the sixth
  CTF round. A failed icat says why, with how far the scan got.
- **`sqlite_query` gives back bytes that are not UTF-8 as `\xNN` escapes**
  where it died on a `UnicodeDecodeError` (an ActivitiesCache Payload).
- **`browser_history` runs several statements one by one** (windows-forensics
  1.2.9, the tool library's 2), each answered in `results`, where "schema;
  count" was "You can only execute one statement at a time". A `;` inside a
  string stays in its statement, every statement must still be a SELECT, WITH
  or PRAGMA, and a refused query is quoted whole.
- **`sqlite_query` says when a file is not SQLite** (computer-forensics-base
  1.2.13, the tool library's 4): its header, the first page's entropy, and
  whether that reads as an encrypted database (SQLCipher or an app's own) or
  another format, where sqlite3 said only "file is not a database". A missing
  database is a JSON answer too.

- **`sigma_hunt` passed Zircolite `--noexternal`**, which Zircolite 3
  removed and refuses. Its `auto` engine prefers Zircolite, so once the disk
  image held Zircolite it would have failed at the argument error where it
  ran hayabusa before. It no longer passes the flag (2.x without it uses its
  bundled evtx_dump).
- **`unified_log` gave UnifiedLogReader three places where it takes
  four** (uuidtext, timesync, the tracev3 files, and its output), so off a
  Mac it only ever got an argparse error. It now passes all four, for a
  `.logarchive` and for a copy of `/private/var/db`.
- The windows-forensics pack named RegRipper `rip` under "GPL". Debian
  installs it as `regripper`, and it is MIT, by its own licence file and
  Debian's copyright. computer-forensics-base called bulk_extractor MIT; its
  2.2.0 release says GPL-3.0-or-later for the code since 2015, public domain
  for the original NPS work, and bundled third-party code under its own.
- **A seat's large file froze its link to the hub, and the seat was
  stopped mid-case** (real CTF runs on macOS and Linux). Recording a file
  a seat had just extracted sent its bytes as one RPC line; msb's vsock
  path from guest to host stops moving on a single write of about 256 KiB
  (measured: ~215 KB crosses, ~262 KB stalls; the network path is not
  affected), and every later call on that connection, the liveness check
  among them, waited behind it until `hub_lost_stop`. No line on a seat's
  link is now larger than one part (32 KiB of payload, 44,716 bytes on the
  wire): larger requests, answers, trace lines and prompts travel in parts,
  each acknowledged, checked by size and sha256. A call that times out or
  a write queue that has not moved in 20 s replaces the link, and RETRIED
  calls resend with their request id. A VM test publishes 8 MiB while the
  budget answers within seconds.
- `catalog_search` (computer-forensics-base 1.2.4) failed every call on an
  unbound name; a static scan of every pack and library tool now fails on
  one.
- An installed pack older than the one the checkout ships ran without a
  word; the kickoff says so and names the update command. Pack warnings no
  longer name tools, skills or programs a dependency carries.
- An unpacked `git archive` knows its commit (`scripts/HARNESS_COMMIT`),
  and no longer claims "local changes" it cannot see. `start --check`
  names the isolation, the image and what the model gateway would front.
  `stop` no longer prints Herdr's JSON.
- **A VM seat whose Pi restarted could spend past its cap unseen.** The hub
  dropped the Pi session id from a seat's report and checked each report
  against the seat's whole row, so a restarted Pi's reports (its own totals,
  from zero again) were refused as going backwards until the new session
  alone passed the old total: a seat really at $1.5 stayed recorded at $0.8,
  under a $1 cap. The hub now passes the session id, a report is checked
  against its own session's last one, and a new session is added to the
  seat's total; the row still never goes down.
- The console no longer refreshes its claims view on the table lock's own
  files (`.probe.*`, `.table.lock.break`, a released lock's rename), and a
  pane's shell that writes `done/ALL_AGENTS_DEAD` is caught like one that
  writes the sentinel.
- **No agent could publish a shared file.** `publish_file` was registered
  but missing from the tool allowlist swarm.sh gives Pi, and in a VM it is
  the only way `work/report.md` is written. In the second CTF round the
  agents on both hosts wrote their reports under their own directories and
  abandoned the run with the finish line unmet. A test now fails on any
  registered tool the allowlist does not name.
- **A request with a `%` near its start was stopped as a leaked
  credential.** msb 0.7.2 reads the placeholder in the Authorization header
  as "in the body" when the first TLS record also holds a `%` or a `\u`
  escape of a Content-Length body, and closes the connection; Pi reports
  "Connection error." One agent's every compaction summary failed on it
  (its conversation began with a URL-encoded access log). In a VM the
  extension now sends a body to a secret's host chunked, which reaches msb
  apart from the headers; a VM test shows the plain request stopped and the
  chunked one answered. A failed compaction now names Pi's own fallback
  failure as well as ours.
- **Custody, the report and the console called every placeholder msb
  stopped "aimed at a host not its own".** The Linux CTF's 52 stops were
  all to api.openai.com, the host the credential is bound to (the
  percent-sign false positive above). The VM record now names the variable
  each secret is held under, custody marks a stop on the credential's own
  host and says it as a failed request, not a leak, with where msb found
  the placeholder, and the report and the Custody tab show the two apart.
- **On a macOS host, grep called every large mounted file binary.** msb
  passes a guest's `SEEK_DATA`/`SEEK_HOLE` to macOS unchanged, and macOS
  numbers the two the other way round, so each file under a mount looked
  like one hole and GNU grep printed "binary file matches" instead of the
  lines of a catalogue file list. The base image preloads `seekfix`, which
  swaps them back only on a FUSE file whose server answers the swapped
  pair; a VM test reads a 264 KB mounted list with grep.
- `start --pack A --pack B` kept only B: a second `--pack` replaced the
  first without a word (the Linux web-server CTF asked for
  windows-forensics and memory-forensics and ran without the former's
  twenty tools). Repeated, the flags now add up, as `image-for`'s did.
- The first prompt told each agent to read `threads/main` (a directory)
  and `done/SWARM_DONE` (absent until the end): two failed calls per agent
  at every start. It now sends them to `inbox`, which answers both.
- Pack tools the round found failing on every call: `catalog_search` looked
  for the filesystem in `p0`, where the catalogue names it by its first
  sector (`p2048`); `esedb_query` passed `esedbexport` a `-q` the Debian
  build lacks; `sqlite_query` passed `sqlite3` a `-uri` it never had, and
  lost the CSV header on a newer shell. `icat_extract` and `chunk_needles`
  now find an image without an extension by its catalogue (a raw `dd` named
  after the host) and default the offset to the one filesystem the
  catalogue lists (`icat` at sector 0 of Case4.E01 said "Cannot determine
  file system type"). `esedb_query` named each table by libesedb's
  export file (`Container_1.6`), so `table=Container_1` was "no such
  table"; it now lists and reads tables by their own names. `shellbags`
  never decoded a shell item (regipy gives a REG_BINARY as a hex string,
  the tool took only bytes), read a root folder's GUID two bytes early,
  and, like `regkv` and `regkeys`, looked keys up without a leading
  backslash, which regipy answers by dropping the path's first part: a
  UsrClass.dat's BagMRU was "not there", and an NTUSER.DAT answered
  Software\...\BagMRU under the Local Settings name. `catalog_search`
  takes a catalogue by the name the index lists (`catalog=Case4.E01`, or
  `Case4.E01/p2048`), which was a traceback; `sqlite_query` without `sql`
  and `ioc_scan` on a missing path answer in JSON instead of raising.
  With a disk and a memory image catalogued, the disk's catalogue (the one
  with `partitions.txt`) is the default instead of "several catalogues".
  `icat_extract` refuses an inode the catalogue lists only as a directory
  (an agent extracted Edge's History directory as `EdgeHistory.db`: 272
  bytes of `$INDEX_ROOT`, then "file is not a database") and answers a
  file's catalogued path with it.
  `lnk_parse` on a missing path says so instead of raising.
  computer-forensics-base 1.2.10, windows-forensics 1.2.6.
- A forged tool's environment carried the calling pane's
  `SWARM_TRACE_TOKEN` in a host run, and the tool may be another agent's
  code. The token is a credential and is kept out now, like the console's.
  From @elhoim (#36).
- **The spend brake could come off.** A seat whose Pi session restarted
  reported from zero and its row was replaced, so a swarm over its cap read
  as under it and the stop steer was cleared; the fold now keeps each
  session's last report by session id, and a seat's row only grows. (In a
  microVM the hub refuses a report smaller than the row, so a restarted
  session counts once it passes the old one.) Under Landlock alone the
  sandbox root allows no new file, so the atomic write of `budget.json`
  failed on every fold; it is written in place there. An unparseable
  `budget.json` is read once more, then left alone with a
  `BUDGET UNREADABLE` veto on the board (through the hub from a VM).
  `--cap-usd 0` is refused for a team that bills. From @elhoim (#28).
- **Two processes could be inside the table lock at once.** Two waiters
  could both break one stale lock, the second removing the lock the first
  had just taken; release removed the lock whoever held it; and staleness
  was asked of a pid, which says nothing across a Linux host's per-pane pid
  namespaces. A holder now heartbeats its lock, a break happens under
  `<lock>.break`, release removes only its own lock, and a claim, a budget
  fold, a ledger entry or a history write checks the lock is still its own
  before it commits. A pid is trusted only in the waiter's own namespace:
  pid namespace and boot on Linux, the boot session on macOS (not the host
  name, which can follow the network across a sleep). From @elhoim (#30).
- **A collector restarted mid-run fused the next line onto a torn one.** In
  a microVM run the keeper restarts a dead collector with the same anchor;
  one killed mid-append left part of a line, the keeper's own
  `collector_restarted` line landed on it, and custody called the harness's
  record "edited". A restarted collector now cuts a fragment the anchor
  accounts for into `traces/events.fragment-<ts>.partial` and says so on
  the chain (`trace_fragment_cut`, size and sha256), keeps an anchor the
  file does not match as `<run>.trace-anchor.prev.json`
  (`trace_anchor_mismatch`), and refuses a line onto any other torn tail;
  the watchdogs' shell fallback spills around one too. `package` carries
  the fragment and the kept anchor. From @elhoim (#27).
- **A run whose every agent died waited out its timeout, and in a microVM
  it was then called finished.** The reaper writes `done/ALL_AGENTS_DEAD`,
  never the sentinel, once every seat is done or dead and one is dead;
  `await-done.sh` fails at once, the watchdog and the VM hub's backstop stop
  for it instead of writing `done/SWARM_DONE` past the wall clock, and the
  summary and the report say every agent died. From @elhoim (#45).
- The report, the dossier and the console's preview took seconds on a long
  line of `|` after a table header, or of `[` or `[a](` (100,000 pipes: 11
  s). The table divider and the link are read in linear time. From @elhoim
  (#37).
- `cron_dump` took time quadratic in a timer's blank lines (about 40,000
  passed its 60 s timeout, and the sweep printed nothing), and gave an
  empty `Unit=` the next line as its value. It reads a unit line by line.
  linux-forensics 1.0.1. From @elhoim (#38).
- `file_carver`, `mem_carve` and `timeline_super` wrote wherever their
  output path pointed, `../` and `inputs/` included; like `icat_extract`,
  they refuse a path outside the run or under `inputs/`.
  computer-forensics-base 1.2.11, memory-forensics 1.0.3. From @elhoim
  (#44).
- A malware entry's checks could not tell a run without `--quarantine`: the
  flag was only in the registry. `inputs.json` says whether the no-exec
  held (`"quarantine": true` in every microVM run, and in a host run with a
  kernel guard; false with `--inputs-enforce off` or no guard, whatever the
  flag), and the five malware entries check it. From @elhoim (#40).
- `--toolbox auto` read a goal's metadata block with its text, and the
  library's common words (`gpg`, "container") asked for the crypto set in
  most entries. A goal's `toolbox:` key names its sets now (every library
  entry has one, an unknown set is a BLOCKER); without it only the body is
  read, and a VHD(X), VMDK, QCOW2 or encrypted container under the inputs
  adds crypto. A Python library is found by its import (pybde, pyvhdi,
  pytsk3 and dfvfs were always "missing"), the crypto set checks libvshadow
  (`vshadowinfo`, `pyvshadow`) and the linux set xfsprogs (`xfs_db`) and
  libvslvm (`vslvminfo`, `pyvslvm`). So on a host, `--toolbox-required`
  now also requires these VSS, XFS and LVM readers wherever their set is
  asked for; in a microVM run it still blocks only on what a pack requires.
  From @elhoim (#41).
- The Windows Q1s (host intrusion, domain controller, ransomware host, IIS)
  ask for the audit policy in force and each log's range, so an absent
  event reads as not audited, rolled over or cleared, not as never
  happened. Pack and prompt goals use the library's sign-off and
  `inputs_check` checks, and a lint holds them to it. cloud-forensics
  1.0.2, encrypted-containers 1.1.1, linux-forensics 1.0.2, macos-forensics
  1.0.2, memory-forensics 1.0.4, mobile-forensics 1.0.2, network-forensics
  1.0.2, ransomware-response 1.0.1, reverse-engineering 1.0.2,
  triage-collection 1.0.2, windows-forensics 1.2.7. From @elhoim (#43).

- **The venv was 642 claims and seven violations, and the panes' temp
  files were more.** With `--allow-install` one agent's pip created
  `work/.toolchain/`; the shell-write watch took every file in it as that
  agent's implicit claim, the next agent's pip into the same venv as seven
  `CLAIM VIOLATION` posts, and the thousands of files pushed the watch past
  its budget so every agent was told `work/` was no longer covered (run 6,
  Linux, 2026-09-22). Pi's own bash spill files, written to the panes'
  `TMPDIR` under `work/.tmp/`, were claims and a violation too. The watch
  now leaves `work/.toolchain/` and `work/.tmp/` alone (`SHARED_WORK_DIRS`),
  and the spill file is removed once its whole copy is under `tool-output/`.
- **After a hand-off, agents answered the hand-off message with a status and
  ended their turns.** All four agents on run 6 did, a few tool calls after
  their notes came back ("they only asked for a compaction hand-off"), and
  three sat idle for ten minutes. The hand-off header and the system prompt
  now say the message is the harness, not a person, that it is not to be
  answered with a status, and that a turn that ends is not waiting.
- **The idle watchdog was found dead a minute after the kickoff started
  it, on runs 5 and 6 (Linux).** An empty log, no state file, nothing in
  the journal; a probe of the same detach from the same tmux session
  survives, so the cause is not established. The kickoff now looks two
  seconds after starting it, starts it once more with stdin closed when it
  is gone, and prints which happened; `swarm.sh status` reports every
  daemon's liveness from its pid file, so a dead watchdog is a line rather
  than a silence. On run 6 the watchdog, run by hand, woke all four agents.
- `swarm.sh context` no longer lists the watchdog's `system` rows as a seat.
- **A forged tool was killed at 64 KB of output and the rest was dropped
  unrecorded.** A parser that emits a large CSV, the normal case on a
  forensic run, ended with `SIGKILL` and a prefix. The tool now runs to its
  end; the model receives the first 64 KB with a trailer naming the whole
  stream under `tool-output/`, with its size and hash.
- **A shell loop writing to a peer's file flooded the board.** On the Linux
  run s3096 one agent's loop produced 566 `CLAIM VIOLATION` posts in
  fourteen minutes, and every peer's next `wait` delivered all of them: 240k
  characters, 64k tokens, a quarter of a working context spent reading one
  sentence. The board post now comes once per path per minute and says how
  many repeats the minute held; every write is still a `claim_violation` row
  on the trace.
- **A run account with no `~/.zshrc` never started an agent on Ubuntu.** zsh
  opened its new-user wizard in every pane and read the `pi` command line as
  the wizard's menu answer; `herdr agent start` then timed out "waiting for
  agent startup" with four idle panes, and the kickoff exited 1 after the
  sandbox, the daemons and the layout were all in place (measured on the
  Linux host, 2026-09-22). The pane hook now hands `ZDOTDIR` back to the home
  only when the home has a `.zshrc`; otherwise the pane keeps the sandbox's
  `.zsh/`, where an empty `.zshrc` stands in. `docs/linux-server.md` says to
  create the file anyway.
- **On Linux the trace gate was started without its key, so every line it
  forwarded was written unverified while the kickoff recorded
  `attribution: ancestry`.** The stdin line's shape was keyed off a variable
  `start_trace_gate` clears first. The gate and the collector now read one
  schema, `{tokens, gate}`, built once when the tokens are minted; the gate
  always gets the key and the collector gets it only once the gate is up.
  Both log what they were handed, and `tests/trace-gate.test.sh` asserts it
  after a real kickoff; `tests/trace-stdin.test.sh` asserts the shapes on
  any host.
- The kickoff line and the quarantine line named the `linux` and `landlock`
  guards as `none (detect + heal only)`; every mode fsguard has is labelled.
- The custody section said the trace anchor was writable by the panes on
  every host but macOS. It is out of a pane's reach under any write
  allowlist: seatbelt, Landlock with or without the namespace, and the
  namespace mode when bubblewrap makes the root read-only.
- The unenforced terminal-socket line explained the gap as "no seatbelt"; on
  a Landlock-only host the socket is reachable because Landlock cannot mask
  a socket, and the line now says so.

### Changed

- One walk writes the inputs manifest for the copy, the bind and the
  attached image (`write_inputs_manifest`), where there were three copies of
  it. `host_caps` runs once per kickoff and feeds both the contract and the
  registry. fsguard builds the Landlock argument list as an array and passes
  it without `eval`; `--subreaper` belongs to the pane's exec, not to the
  rule set.

- **Licensed under the GNU Affero General Public License v3 or later, with a
  commercial licence alongside it.** Nothing was ever released and the
  repository has never been public, so the licence is decided once here
  rather than inherited. The AGPL asks nothing of anyone running this
  software: on their own machines, on a client's case, whatever they bill for
  the work, modified or not, as long as the modified version stays inside one
  organisation. Section 13 attaches to a single use, offering a modified
  version to other people over a network without publishing those
  modifications, which is the one use that would hollow a project like this
  out. `LICENSE` is the FSF's text verbatim, `NOTICE` carries the copyright
  and the source link, and `package.json` is `AGPL-3.0-or-later`.
  `COMMERCIAL-LICENSE.md` states when a commercial licence is needed and,
  more usefully, the common cases where it is not. The trademark policy rests
  on the licence's sections 7(c) and 7(e). Herdr (Apache 2.0) and Pi (MIT)
  are both compatible and neither is bundled. The 0.3.0 entry below still
  records the MIT `LICENSE` that version shipped.
- **The console offers its own source, because it is a network service.**
  Section 13 asks a modified version reached over a network to offer its
  users that version's source. The page footer and the server's startup
  banner both carry the link, so an unmodified run complies by default and a
  fork changes one constant.
- **Renamed to DFIR Swarm, in a fresh repository.** The name now says both
  what this is and what it was built and proven for: an agent swarm for
  digital forensics and incident response. The repository is
  `halilozturkci/dfirswarm`, started from one root commit holding the tree
  as it stood on 2026-09-19; the package is `dfirswarm`, and the wordmark,
  the page title, the server's banner and every document follow. The
  previous repository, `halilozturkci/dfir-swarm`, is kept archived: its
  pull requests are the ones this changelog and the plans cite by number.
  The extension file keeps its name — `extensions/agent-swarm.ts` is a code
  path, not the product — and the published cases keep their screenshots as
  they were taken.
- **The harness assigns nothing.** `--seats`, the `dfir` seat preset and the
  Seats table in `SWARM.md` are gone, and nothing writes a seat into
  `team.json` or into an agent's system prompt. An agent reads the goal, reads
  the board, decides what it is taking on and says so with the new `name`
  tool; `names.json` records what each one said, every post carries its
  author's name, and the console and the summary show it beside the id. Two
  agents cannot answer to the same name, and an agent may rename itself
  whenever its work changes. The only boundaries the harness draws are the
  sandbox's own: read-only inputs, the no-exec quarantine, the network
  setting, the caps and the protocol.
- The console bundle is split into a vendor chunk (React, the router) and the
  app chunk, so a UI change no longer invalidates the vendor bytes in the
  browser cache and no chunk passes Vite's size warning.
- `@types/node` follows the runtime again (22.x, as `.nvmrc` and
  `engines.node`); Dependabot no longer proposes a newer major for it.
- CI runs with no warnings: git's `init.defaultBranch` hint under
  `actions/checkout` is silenced, and the netguard suite no longer echoes the
  proxy-only fallback it already reports as the detected mode.
- **The extension is type-checked against Pi's own types.** Pi's package
  (`@earendil-works/pi-coding-agent`, pinned) is a devDependency, the ambient
  stub and the separate server tsconfig are gone, and `npm run typecheck`
  covers `extensions/agent-swarm.ts` and every node test with the one
  config. The eight type errors this found were real, small and are fixed.
  A24's fault, two functions called and never imported, is now a compiler
  error. `npm ci` grows by Pi's package; a real run still needs `pi` on
  `PATH`.
- **The change bus drops what the console cannot show, and says what moved
  per swarm.** Pi appends to its session file on every message, the netguard
  proxy logs every connection, the idle watchdog writes its state every half
  minute and every post or claim takes and drops the lock-table mutex; none of
  it changes anything on screen, and together it was most of the events a
  running swarm produced. Those writes are classified (`sessions`, `logs`,
  `internal`) and dropped at the server, so neither the clients nor the
  finish line's change stamp see them. A `change` event now carries
  `by_swarm`, the kinds that moved under each swarm, and each panel keys its
  refetch on the kinds it reads: the board on `threads`, the trace on
  `events`, the files on `history`, the tool source on `tools`, the goal on
  `contract`. The view and the finish line still refetch on any kind, so a
  panel can never be more stale than the page around it. Two more things
  the bus does now, both measured on a post to a fixture swarm: a burst
  ends 200 ms after its last filesystem event rather than its first (one
  post used to arrive as three `change` events on macOS), flushing after a
  second at most under a steady stream; and a path reported again with the
  same size and mtime is not a change (the filesystem re-reports a write
  for a second or more, and a sync client touching attributes reports it
  once more). One post is one event, one appended trace line is one event.
- **The console refetches what changed, not everything.** A swarm's page is
  keyed on that swarm's changes plus the registry's, not on every change in
  the fleet; a burst of changes is one refetch after the request in flight
  lands, not one per change; the elapsed counters tick on the client instead
  of refetching every fifteen seconds. On the server, one swarm's view no
  longer rebuilds every swarm's row to find its own, the event log and a
  thread's posts are parsed once per change and shared, and the finish
  line's shell checks run again only when something under the sandbox moved
  (`/api/health` counts the runs). Same data on screen, a fraction of the
  requests and reads.
- **The shell-write watch caches hashes and says when it is full.** Every
  `bash` call hashes every file under `work/` before and after; a run whose
  extractions reached a gigabyte paid over a second per shell call for it. A
  file whose size, mtime and ctime have not moved is not read again, and the
  watch walks eight levels deep instead of four. When `work/` holds more than
  500 files the harness says so once, on the trace (`watch_truncated`) and on
  the board, instead of leaving the files it no longer covers unwatched in
  silence.
- `npm test` runs the Pi loader suite too (it skips where Pi is not
  installed), and `npm run test:bash` runs every shell suite and reports each
  one instead of stopping at the first failure (`scripts/test-bash.sh`).
- Dead code left the console: an unused messaging timeline, an unused tabs
  primitive and three Radix packages nothing imported; the grace-clock
  formatter and the post-tag colours are defined once.
- Docs brought back in line with the code: the roadmap no longer lists local
  models and the tool library as future work, `--tools-from` reads
  `manifest.json`, the usage page names every tool the agents get, the
  protocol page describes `name:` rather than `seat:` on a post, and the quick
  start cites the Pi version the runs used.

### Added

- **A second run on BelkaCTF #6, in a clean room, and an agent that walked out
  of the network guard.** `s83fd` worked the same evidence and the same goal
  as the first run with the first run's answers denied at the kernel
  (`--no-read`) and no tools carried forward. It reached 9 high-confidence
  answers to the first run's 6, for $68.89 against $77.32, while short-handed:
  four agents had been pointed at one Azure deployment and it rate-limited.
  The isolation was proved from inside a pane before the agents started — 17
  checks — and watched for the whole hour: zero reaches toward the previous
  run across 2,339 tool calls. The run also produced the finding that names
  the limit of this platform. Given `--allow-install --no-pypi`, an agent was
  refused by the proxy eight times and then ran `env -u HTTP_PROXY … pip
  install`, which worked, because netguard on macOS is environment variables
  rather than a network namespace. Four kernel-enforced guards held; the one
  advisory guard did not. `docs/use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md`
  is the whole account, and the contract now tells the truth under `--no-pypi`
  — it had promised the agents an allowlist entry the flag had removed, which
  is why they went looking in the first place.

- **A pane writes inside its run and nowhere else.** The seatbelt profile was
  `(allow default)` with a deny under `inputs/`: it protected the evidence
  from the agents and the machine from nobody. Measured inside a real guard, a
  pane could list the examiner's home, see `~/.ssh`, see every other case on
  the machine, and write outside its sandbox — including `runs/registry.json`,
  which is where `await-done.sh` reads the definition of done from before
  `eval`-ing it as the examiner. `fsguard.sh --rw DIR` now builds a write
  allowlist: `(deny file-write* (subpath "/"))` and the run's own tree allowed
  back, plus the devices a tool needs. Reads stay open on purpose — a
  deny-default profile cannot start `/bin/echo`. `TMPDIR` moves inside the
  run, which let the per-user temp area stay closed with python's
  `NamedTemporaryFile`, git, node, sqlite3 and tar all still working. On by
  default; `--no-write-guard` turns it off; macOS only, and `fsguard` says so
  rather than pretending on a host that cannot apply it.

- **The trace has a writer the agents cannot reach.** `traces/events.jsonl`
  lived in the directory the panes can write, and the only protection was a
  size-and-prefix comparison that announces a rewrite as `blocked: false`. On
  BelkaCTF #6 it fired once — "RECORD REWRITTEN … Nothing can restore it" —
  nobody answered it, and the file turns out to be intact: 2,287 of 2,287
  lines parse. The run's loudest integrity alarm was a false positive. Now a
  collector process outside the pane's profile holds the only writable handle,
  the panes reach it over a Unix socket and get `traces/` read-only, and every
  line carries the sha256 of the line before it — so a line edited or removed
  from the middle breaks something a reader can check, which "the file grew"
  never could. Without a collector a run behaves exactly as before and the
  report says "not chained" instead of claiming a chain it does not have.

- **A record the agents cannot forge, only fail to write.** The chain closed
  an edit in the middle and left two ways round it. A line appended after the
  last one still chained, so a trace could be *extended*: the head of the
  chain is now written to an anchor beside the registry, outside the sandbox
  and out of a pane's reach, and `verifyEventChain` reports `edited`,
  `appended`, `shortened` or `head` rather than a bare boolean. And the
  socket believed whoever wrote to it — any pane could send a line as any
  agent. Each pane now gets a token in its environment (which on macOS no
  other process can read, and which Herdr's API does not expose — both
  measured), the collector takes the token map on stdin where neither argv
  nor the filesystem leaks it, and a line's `agent` is decided from the
  token. A line claiming to be someone else is still written, with
  `claimed_agent` beside it: an attempt on the record is itself a finding.
  `idle-nudge.sh` and `reap.sh` append through `scripts/trace-emit.mjs`
  instead of writing the file directly — their unchained line used to break
  the *next* collector line, so a run with the watchdog on called its own
  record edited every three minutes.

- **The terminal multiplexer's control socket is out of the panes' reach.**
  Herdr puts `HERDR_SOCKET_PATH` into every pane, and that socket
  authenticates nobody: every method is dispatched to whoever connected, and
  the 0600 mode on the file is the whole boundary — which the panes are
  inside of. Measured from within the write guard: it answered. Through it,
  `layout.apply` starts a process with arbitrary argv and environment that
  the server owns, so it is not under the pane's profile and every write rule
  was optional; `pane.send_text` types into a peer's terminal;
  `pane.report_agent` forges another pane's lifecycle state; `server.stop`
  ends the run. `fsguard.sh --no-socket` denies it (a directory denies every
  socket under it, `literal` for a single path), on by default with the write
  guard and `--no-seal-herdr` to restore the hole. The one call the harness
  made from inside a pane — waking idle peers when a `done` finishes the
  swarm — goes through `scripts/nudge-broker.mjs`, where the pane names a
  `kind` and the broker owns the words: an agent can wake a peer and cannot
  tell it anything. The run record carries `herdr_socket` and the report
  prints "Terminal socket". Agent detection is unaffected — Herdr reads Pi's
  state off the screen, and the idle watchdog runs outside the panes.

- **What two review passes found in the two entries above, and what it cost
  to fix.** The anchor did not do what it was built to do: it checked two
  relations between the record and the length it remembered and let the rest
  through, so a line appended with a correctly computed `prev` — and the hash
  that needs is the previous line, which every pane can read — still verified
  as intact. So did a whole rewrite padded past the anchor's count. Stripping
  every `prev` skipped the anchor entirely and printed as "this run had no
  trace collector", the one sentence that tells a reader to stop worrying.
  The anchor also re-read its line count from the file, so truncating the
  trace and letting one more line through moved it *down* to the shorter
  count. Every relation is now decided, the count only ever grows, and the
  collector brackets each append with two anchor writes so that a reader in
  the window between them can tell it from a deleted last line.
  `attribute()` passed the sender's own `agent_unverified` and
  `claimed_agent` straight through, which let an agent stamp its own lines
  unattributable and repudiate them later. `trace-emit` and `sendToCollector`
  reported success when the bytes reached the kernel, so a line the collector
  refused vanished and the fallback built for that case never ran; both wait
  for the collector to say it wrote. The watchdogs' fallback appended to the
  trace itself, putting an unchained line in a chained record — the harness
  raising a corruption alarm against itself — and now spills instead, unless
  the record has no chain to protect. The watchdogs had no token, so every
  line they wrote came back unattributed. The socket deny was written with
  the path as given, and seatbelt matches the resolved one: on macOS
  `$TMPDIR` is `/var/...` for `/private/var/...`, so a rule could be present
  and deny nothing. It was also skipped entirely when the socket did not
  exist yet — the ordinary case — while the run record still said `sealed`.
  The broker checked its roster against a file inside the sandbox, which
  every pane may write, and sent "the swarm is finished, stop" on request
  without checking whether it was: a run-wide kill switch reachable by any
  agent. Neither daemon had a connection limit (300 senders took the
  collector to 821 MB; now bounded and it keeps serving) and neither noticed
  when its run was deleted — 307 orphaned daemons were found running on the
  development machine, and they now exit on their own.

- **An alarm about evidence that never changed.** The integrity check
  fingerprints bytes, mode and link count together, so a returning write bit
  read as "the evidence was modified". One archived run recorded 374 of those
  on two files whose sha256 still match the manifest exactly — 27% of its
  whole trace, every one of them `healed: failed`. Content drift and metadata
  drift are now different things, with `content_ok` answering the evidence
  question on its own, different board wording, and a metadata finding
  repeated at most once per path per ten minutes.

- **The record says which guard was achieved, not which was asked for.** The
  registry said `netguard: true` while the sidecar starts `--mode proxy-only`,
  which netguard's own header calls advisory — sitting beside `inputs.guard`,
  which is measured per pane. `netguard_mode` is recorded and printed, the
  report's custody section carries "Egress enforcement" and "Egress refused",
  and the harness's own `pi.dev` telemetry is dropped from the refusals: it is
  130 of the 172 on that run and it buries the one line that matters, an agent
  resolving a `bit.ly` link it had read inside the seized phone.

- **What a run installed is recorded, and what a tool returned.**
  `--allow-install` wrote nothing down: a report citing a finding produced by
  a library could not name the library's version. The harness now reads every
  `dist-info` under the run's own prefix — name, version, installer, the index
  URL pip recorded, and the sha256 of the package's own `RECORD` — into
  `toolchain.json`, the trace, the board, the report and the handover package.
  And a built-in tool's result carries the first 2,000 characters of its
  output beside `ok`, because `ok: true` is not correctness: 27 of 28
  `bde_unlock*` calls on that run returned `ok: true, exit_code: 0` with
  `InvalidTag` in the payload.

- **The evidence is the one input an adversary wrote, and nothing said so.** A
  search of the prompts, the docs and the code for "prompt injection",
  "untrusted" or "hostile input" returned nothing. The worker prompt and the
  generated contract now say that `inputs/`, `catalog/` and `work/extracted/`
  are material and never instruction, and name the refusal: no network
  request, no install, no execution because of something read in the evidence.
  A `confidence: high` claim wants a second independent artefact, and a
  sign-off by the agent that wrote the files is not a sign-off.

- **`--inputs-image`: evidence the host kernel holds.** A `:ro` bind mount is
  not a write block — `--cap-add SYS_ADMIN`, the capability that mounting a
  forensic image needs, remounts it read-write and edits the host's file
  (measured). So the obvious "give them root in a container" design destroys
  the guarantee the platform rests on. An image attached read-only on the host
  survives the same container, and `--inputs-image FILE` makes that a run
  mode: the manifest records `guard: "image"` with the mode and link count it
  found, the mount point is read-only to the panes (a pane can unmount the
  image — measured — and must not be able to write a replacement in its
  place), and `stop` detaches. The test
  asserts **both** halves, including that the bind mount is defeated, so
  nobody simplifies it back.

- **Every long list is paged.** An agent's trace is 229 calls, the artifact
  index 131 files, the ledger 57 entries — each of them one endless column
  where, past the first screenful, scrolling stops telling you where you are
  and there is no way back to a row you saw a minute ago. One control under
  every long list now: "51–100 of 229 calls", first and last always
  reachable, 25 / 50 / 100 / 250 per page, and a control that does not grow
  with the list. The page resets when a filter makes it a different list —
  page 5 of a list that no longer has five pages is an empty screen with no
  explanation — and a live trace's **Follow** moves to the last page instead
  of fighting it. The raw trace, an agent's trace, its reasoning, the
  ledger's timeline / indicators / findings, the artifact index and the files
  with history all use it.

- **An opened trace row reads like a record, not like JSON.** It was two
  bordered boxes of pretty-printed JSON: `{ "path": "SWARM.md" }` across
  three lines beside `{ "ok": true, "duration_ms": 10 }` in another — four
  lines of punctuation around six characters of fact. Now each argument and
  each result field is its own line, name beside value, wrapping; anything
  long or structured gets a block underneath; `ok` is coloured, because
  whether the call worked is what a reader looks for first; and RAW and COPY
  are there because this is an audit trail and somebody will want the bytes.
  One row is open at a time — two open rows pushed the list so far apart
  that the first was off the screen by the time you opened the second.

- **The trace kept 80 characters of an argument, and dropped every
  structure.** `summarizeArgs` cut each string at 80 characters and discarded
  objects and arrays without a word. So a shell line went into the audit
  trail as `ls -la catalog/ work/ 2>/dev/null; ls catalog/ | head; echo
  '---'; tar tf inp...`, losing the half that said which file it read; and a
  refused `make_tool` recorded `{name, runtime}`, leaving the trace holding
  the error `param "db" must match /^[a-z][a-z0-9_]{2,31}$/` about params the
  record did not contain. An audit trail that quietly shortens what it audits
  is worse than one that says it cannot. It now keeps 20,000 characters — a valve against one
  pathological argument, not a budget; on that run the longest argument, after
  the old clip, was 80 — keeps a structure as a structure while it fits, and when it does clip
  something records the true length under `_truncated` — so the console can
  say how much of how much it holds instead of leaving an ellipsis to be read
  as the whole thing. `make_tool`'s refusal path records the params
  it was asked for, the same as the path through.

- **A trace row opens where it sits, instead of covering the page.** Clicking
  a call used to throw a dialog over the trace: reading two calls meant
  opening and closing two of them, and the list you were reading vanished
  behind the thing you asked about. The row is now a disclosure — call and
  result unfold underneath it, inside the list, as many at once as you like.
  Both panes wrap, which the dialog's did not: a path that was stored whole
  was cut at the pane's edge, so the console looked like it was hiding
  something it was not.

- **What the board adds up to.** The Every-post tab rendered one row per
  thread — on most runs, one row — a pulse line, and then half a page of
  white space, under a run whose 104 posts are the only record of how ten
  strangers divided a case between them. Under the list now: six figures
  (posts and characters, who spoke of the team and who never did, the span,
  the median gap between posts, the longest silence and who broke it); the
  tag mix as one bar and again per speaker, so a team of reporters reads
  differently from a team that asks; a **who named whom** matrix built from
  the agent ids written in post bodies, where the empty rows say as much as
  the full ones; every **hold, veto and stop** on the board, with the
  harness's own marked as its own — on BelkaCTF #6 that is three claim
  violations and a record rewrite nobody would otherwise read; the **paths
  the posts cited**, counted and linked where the run kept the file; and the
  three longest silences with the line that ended each. Every figure is
  counted from `threads/` on disk by a pure module with its own tests —
  nothing here is a model's summary of what it thinks happened. A new
  `GET /api/swarms/:id/posts` returns every post across every thread, bodies
  included, because the swarm view ships only each post's clock, author and
  tag.

- **Every line of reasoning in every run rendered blank.** The harness writes
  a reasoning event as `logEvent(cwd, agent, "thinking", {}, { text, chars })`
  — empty args, the text in the **result** — and the console read `args.text`.
  It printed the empty string, in the raw trace, in an agent's own trace and
  in the "right now" strip, for every reasoning event since the tab existed.
  Two things hid it: the row also echoed `→ {"text":"…","chars":694}` on the
  right, so it read as a formatting quirk rather than a missing field; and on
  the BelkaCTF #6 run three of ten agents — every agent on
  `azure-foundry/grok-4.6` — genuinely emitted no reasoning at all, which made
  a reader's "the thinking blocks are empty" look like a fact about the
  models. The renderer now reads `result.text` and falls back to the old args
  shape so archived traces keep working, and the reasoning row no longer
  repeats its own text as a result.

- **THINKING is a document, not a list.** Reasoning is the one thing in a
  trace written in sentences, and it was clipped to whatever fitted between
  the clock and the duration on a single line. It is now one wrapped block per
  turn, the clock in the margin, the agent's colour down the side. Where the
  harness kept only an opening, a note under the block says how much of how
  much — measured from the text in hand, so a run recorded under the old
  240-character limit is described honestly rather than by today's constant.
  That limit itself is now 2,000 characters: 240 was barely the first
  sentence, so the reason an agent changed direction was never in the record,
  and at 2,000 a ten-agent run's whole trace is still under a megabyte.

- **An empty panel says which kind of empty it is.** "No trace lines —
  traces/events.jsonl is empty for this selection" was shown to an agent whose
  model returns no reasoning, to an agent with seven hundred lines and no
  failures, and to an agent that died before its first turn. The THINKING
  empty state now asks the harness for the per-agent reasoning census — one
  request, `limit=1`, using the new `matched_by_agent` on the traces API,
  which counts the *filtered* set per agent — and says which of three facts it
  found: this model returned none anywhere in the run (naming the models that
  did, with their line counts), this agent alone was quiet while its shipmates
  on the same model were not, or nobody in the run reasoned at all. The other
  lenses get their own sentences: nothing failed, it never posted or read the
  board, it left no trace at all.

- **"Right now" is not a thing a finished run has.** The Agents tab opened
  with five unlabelled rows of raw trace above the agents themselves — on a
  run that had ended, always the same five: `session end`, `session end`,
  `done`, `inputs check`. They were written to show a live team's newest
  lines and nobody had asked what they become once the team has gone home.
  A live run keeps them, with a heading that says what they are; a finished
  one opens on its agents.

- **The run's header is the run, and the page below it is the work.** Three
  things moved. The numbers and the team now sit side by side in the band
  instead of stacked, so neither the vitals nor a box of ten agents owns the
  full width and the right half is no longer empty at every size. The four
  setting chips — Herdr panes, hard-kill, tool forging, the inputs guard —
  left the band entirely: each was already stated where it is used, and all of
  them are now together under **the frame it ran under** in "How this run was
  started", beside the command, with the network allowlist, the toolbox sets,
  the catalog, the quarantine and the per-agent cap that were never shown at
  all. And the section tabs moved up into the band as one row, groups divided
  by a rule rather than by four labels that read as tabs nobody could click.
  The white page now opens on the work itself rather than on four rows of
  navigation.

- **A name is not permanent, and the console now says so.** `name()` can be
  called again whenever the work changes, and on a real run it is: one agent
  opened as "Laptop Triage" and four minutes later was "Dependency &
  Timeline"; another asked for "iPhone identity", was refused because a peer
  already answered to it, took it a second later anyway and renamed itself
  "Docs and money" half a minute on. `names.json` keeps only the last of
  those, so an agent's page showed one title for a decision it had made three
  times. The page now carries the whole sequence — when it named itself, when
  it renamed, when it kept the name and rewrote the job, and every refusal
  with the peer that caused it, which is how two agents worked out they were
  about to do the same work. It reads the trace route rather than the view's
  tail, because an agent names itself in its first minute and a fifty-minute
  run has long scrolled past it.

- **The team, where the model identifiers used to be.** A run's header
  carried a row of grey pills reading `azure-foundry/DeepSeek-V4-Pro`,
  `lmstudio/qwen3.8-27b-uncensored` — the one fact about a mixed team a reader
  cannot act on. It said nothing about who ran on what, what those agents
  called themselves, which of them finished, or where the money went. The
  strip is now one column per model: the agents on it under their own chosen
  names, a dot each for finished / working / quiet / reaped, the model's spend
  and its share of the bill, and every name a link to that agent. Ten agents
  across four providers and one local model is the most interesting thing on
  the page, and it is finally legible.

- **Seven things the console was getting wrong, found by reading it over a
  finished run.** The ledger's timeline wanted 1,645 px and got a horizontal
  scrollbar with its last column cut off, on a screen with room to spare: the
  tables are fixed-layout with shares of the width now, machine strings break
  inside their cell, and the shell is 1,680 px rather than 1,440. The agents
  vital said "6 done" where ten had started and four had ended a provider
  error away from a marker — it reads `6 of 10 · 4 never finished`. A
  `work/*.md` was shown as a monospace block, which is the source of a
  document rather than the document; the report's own renderer moved to
  `ui/src/lib/markdown.ts` and draws them in both places. "Open in new tab"
  downloaded the file, because every artifact was served as
  `application/octet-stream`: the route sends a real content type and
  `content-disposition: inline`, `?download=1` is the one that saves, and the
  panel has a **View** and a **Download** button instead of one that did the
  wrong one. The goal library was a native `<select>` — a full-screen grey
  system menu listing names and nothing else — and is now a control this
  application drew, with a filter, each goal's check count and a warning on
  the ones with no definition of done. The kickoff's field labels wrapped and
  pushed their inputs out of line, so they are shorter and their boxes reserve
  the same height. And the Goal tab opens with **how this run was started**:
  the `swarm.sh start` command, with `--env` values redacted, recorded in the
  registry at kickoff and copyable — the first thing anybody asks of a
  finished run, and the one thing the console could not answer.

- **The forensic report is a document now, not a dump.** The old one opened
  with a key-value list and a numbered list of forty-word sentences, and its
  five-column timeline pushed the page sideways on every long evidence string.
  The cover carries the case number, one sentence of verdict and six numbers —
  findings, indicators, dated events, evidence files, elapsed, spend — so a
  reader decides from the first page how much of the rest they need. The
  findings are verdict cards grouped by confidence, each with its exhibit
  number and the source it rests on, because what a run stands behind and what
  it is only offering are not the same claim. The timeline is a rail rather
  than a table: stamp, claim, source, evidence, nothing to scroll sideways
  for. Every table is `table-layout: fixed` with breaking inside the cell, the
  contents page carries a line about what each section is for, and the print
  stylesheet gives the cover and the contents a page of their own. Two bugs
  went with it: `swarm.sh stop` deleted `netguard.allow` along with the pid and
  the port, so every report written after a run finished said "netguard
  allowlist not recorded" about a run whose allowlist had been enforced all
  along — the record is kept now, and an older run that lost it has its
  allowlist read back from the proxy log and labelled as the weaker source it
  is.

- **A run can install what the case needs, without root.** BelkaCTF #6 found a
  BitLocker volume hidden in an alternate data stream, recovered its recovery
  key from a note inside an iTunes backup, and then spent half an hour failing
  to open it: no `dislocker`, no libbde, no libvhdi on the host. The agents
  never asked for root — they ran `brew install dislocker` and then
  `pip3 install dislocker`, and netguard denied `pypi.org` seventeen times.
  B14 had already found this half of the problem on challenge 9 and only the
  toolbox half was fixed. `--allow-install` fixes the other half: `pypi.org`
  and `files.pythonhosted.org` join the allowlist, `PYTHONUSERBASE` points at
  `work/.toolchain/` inside the sandbox, and what a run installs goes when the
  run goes. Off by default, stated in the contract, recorded in the ledger,
  and offered as a switch on the console's Case card. Root stays refused on
  the examiner's host — these panes are the examiner's own processes, and the
  read-only guard over `inputs/` is exactly what root would undo; a case that
  genuinely needs a mount wants a disposable container (B17), and most do not,
  because libbde, libvhdi, libluksde and pytsk3 read those volumes in place.

- **The crypto toolbox set names the class, not one tool of it.** It gains
  libbde (`bdeinfo`, `pybde`), libvhdi (`vhdiinfo`, `pyvhdi`), libluksde and
  `qemu-img`, all of which read a volume without mounting it. `--toolbox auto`
  now reads the goal document and adds the sets it asks for, and the evidence
  catalog warns when it has just seen a BitLocker or virtual-disk signature on
  a run with no crypto set. The BelkaCTF run was started with `--toolbox dfir`
  and nothing connected "the goal says encrypted container" to "you did not
  ask for crypto" until minute forty.

- **A segmented image is catalogued once.** libewf resolves a whole set from
  any one segment, so `--catalog` was producing an identical partition table,
  body file and timeline for `.E01` through `.E06` — six catalogues of one
  8.7 GB disk, and six times the minutes. The continuations are counted and
  named in `catalog/README.md` instead, so the gap does not read as a file
  that was skipped.

- **A provider failure is an event, not a silence.** Both `deepseek` agents on
  the BelkaCTF run died six seconds apart on `402 Insufficient Balance`. The
  console counted them among "10 working" for the rest of the hour, the board
  said nothing, and the idle watchdog spent all three of its nudges on each of
  them against retries that could only fail the same way. A turn that ends in
  a provider error now writes `agent_error` to the trace and posts the
  provider's own words to the board, and the watchdog leaves that agent alone
  until it works again.

- **A local model gets its first turn.** The LM Studio seat took about four
  minutes to read a 10 KB contract and was nudged twice before it had emitted
  a token; `--idle-sec` is tuned to cloud latency. A seat on a locally served
  model now has `--local-first-turn-sec` (600) before its first silence counts.

- **The package stops carrying the evidence it says it leaves behind.**
  `package` excludes `work/extracted/` and `work/quarantine/` and then wrote
  35 MB of registry hives and browser databases from the agents' own scratch
  directories. Provenance from the trace was tried and dropped — it identified
  0 of the 15 files it had to — so the rule is what a handover is for: binaries
  over `SWARM_PACKAGE_MAX_BINARY_KB` (256 by default) stay in the sandbox and
  are named with their hashes in `LEFT-BEHIND.txt`, next to the hash every one
  of them already has in `artifacts.json`.

- **The swarm page's tab strip stops pretending.** `THE RUN`, `EVIDENCE`,
  `THE FRAME` and `OUTPUT` were small-caps spans inline with the pills in one
  wrapping row: four things that looked like tabs, were not clickable, and
  could wrap away from the tabs they labelled. Each group now has its own row
  with the label in a column of its own. The Tools tab's empty state says
  which of three states it is in — forging off, forging on with N hints and
  nothing forged, or nothing seeded — because on this run an operator read it
  as "the agents are not forging" while the harness had asked five times.

- **The console can start a case, not just a task.** The kickoff form had the
  team, the caps and the read-only inputs, but none of the settings that turn
  a goal into an investigation, so every forensic run so far had to be typed
  at a terminal. `/new` now carries a **Case** card: the evidence catalog
  (the first pass over the inputs, refused without an input set, because a
  first pass over nothing is a kickoff that fails three minutes in),
  quarantine, the toolbox sets, a per-agent USD cap, the case id and the
  examiner. They reach `swarm.sh` as `--catalog`, `--quarantine`,
  `--toolbox`, `--cap-per-agent`, `--case-id` and `--examiner`, and the
  command preview shows them; a per-agent cap above the swarm's own cap, an
  unknown toolbox set and a case id or examiner that has no business on a
  command line are all refused in the browser rather than in a shell job
  somebody has to go and read. First used to start the BelkaCTF #6 run from
  the console.

- **A mark, drawn on the palette the console already had.** Two brackets
  holding five peers: the brackets are the harness, the part that is not
  negotiable, and inside them five agents of five specialisms, all the same
  size because none of them outranks another and nothing was handed out. The
  five colours are `brick`, `slate`, `saffron`, `kelp` and `moss` from
  `ui/src/index.css`, so the mark and the product it belongs to use one
  palette rather than two. `brand/` holds it for a dark ground, for a light
  one, and in `currentColor` for print and for anywhere colour is lost, with
  the usage rules beside them. The console header carries it, reading those
  tokens as CSS variables rather than repeating their hexes, so a retuned
  palette moves the mark with it; the tab icon, until now three dots on a
  teal square that matched nothing, is the same mark on the console's own
  band colour; and the README shows it above the title, switching with the
  reader's theme.

- **What a repository needs before it is public, and not a line more.** The
  Apache licence covers the code; two things it deliberately does not cover
  are now written down. `CLA.md` is the contributor agreement: it leaves the
  contributor's copyright with them and keeps a later decision about the
  project's own terms with the maintainer, which is a decision that stops
  being the maintainer's the moment one outside patch lands without it. It is
  referenced from the contributing guide and ticked in the pull-request
  template. `TRADEMARK.md` says what section 6 of the licence means in
  practice: fork freely, give the fork its own name, and use the name
  truthfully to refer to this project. A forensic tool has a reason to care
  which build a result came from.
- An issue chooser (`.github/ISSUE_TEMPLATE/config.yml`) that routes a
  vulnerability to the security policy rather than to a public issue.
- The upstream licences in the credits: Herdr is Apache 2.0 and Pi is MIT,
  both permissive, and neither is bundled here. Worth stating in a repository
  that cannot run without either of them.

- **Local models.** A team served from this machine or this network — a
  `models.json` provider on loopback, a private range or `.local`, or Pi's
  `llama.cpp` provider — is recognised at kickoff. It bills nothing and Pi
  reports its cost as an exact $0, so the USD cap could never stop it: such a
  team must be given `--cap-tokens N`, `budget.json` records `metered: false`
  and `cap_tokens`, the cap machinery brakes on tokens (`TOKEN_CAP_STEER`),
  and the summary speaks in tokens rather than "$0.00 spent". Before any
  pane opens the kickoff probes the server: that it answers, that it has the
  model, and, for Ollama, the context it will really give against what
  `models.json` declares; a missing `compat` block is warned about. A keyless
  local provider gets a BLOCKER with the placeholder `apiKey` to add rather
  than a pointer to `pi /login`, and `--key-from-env` is refused for it. The
  allowlist takes the literal host from `baseUrl` and its other spelling
  (`127.0.0.1` ↔ `localhost`); IPv6 literals no longer break `host_of_url`.
  `--local-only` turns the allowlist into the local endpoints alone
  (`netguard --only`) and sets `PI_OFFLINE=1` in the panes; the registry
  records `net: "local"`, `metered`, `cap_tokens` and `local_models`.
  `--cap-usd` is now checked to be a number. The console follows: the model
  picker lists every local provider from `models.json` even when Pi omits it
  for want of a key, readiness says "local · needs a placeholder apiKey"
  instead of "not logged in", the kickoff form has a token cap and a
  "Local only" network mode and refuses the wrong combination before
  `swarm.sh` has to, the budget tab speaks in tokens and says "free" when
  nothing was charged, and the fleet's spend line counts free runs
  separately rather than as "$0.00 of $0.00". Plan and evidence:
  `docs/local-models-plan.md`.
- **A forged tool can outlive its sandbox.** `--tools-from DIR` seeds `tools/`
  from a library of tools written in earlier runs — one directory per tool with
  its manifest and script — so they are in every agent's list from the first
  turn with their author and version kept. `swarm.sh tools <id>` lists what a
  run forged and `--save DIR` copies it into such a library. Six Windows cases
  rewrote an event-log filter and two rewrote a prefetch parser under different
  names, because tools died with the sandbox.
- **`make_tool` answers a near-duplicate.** Before anything is written it looks
  for a tool that already does this: the same runtime, overlapping parameter
  names and a description made of the same words. The refusal names the tool
  and its author, so the agent calls that instead of forging one capability
  under a second name — which two seats did six seconds apart on the Azure run,
  before either announcement reached the board.
- **Three network settings at kickoff instead of one switch.** The console's
  kickoff form asks what the panes may reach: *Guarded*, netguard's allowlist
  and nothing else, which stays the default; *Guarded + hosts*, the same
  allowlist plus the names you give, one `--allow-host` each; or *Open*, which
  takes the guard off and says so. Host names are validated before they reach a
  command line, at most twenty, and the old `netguard: false` body still means
  *Open*. The registry records the setting, so a run can be asked afterwards
  what network it had — which a forensic report has to be able to answer.
- **The seat travels with the post.** Every board post carries the author's
  seat in its front matter, and the console shows it under the agent id on the
  board and beside the author in the ledger. An agent id (`s864a06`) belongs to
  one run; the seat ("Key material and cryptography") is what a reader follows
  and the only part of the identity that means the same thing in the next run.
- **Forensic runs.** `--catalog` runs the standard first pass over the inputs
  once, before the agents start (partition tables, body files, MAC
  timelines, path lists; Volatility's process, command-line, network and
  injection lists for a memory image) into a read-only `catalog/` rendered
  into `SWARM.md`. `--toolbox dfir` checks the forensic tools on the host
  into `toolbox.json` and the contract, with install commands for what is
  missing (`--toolbox-required` makes that a blocker). `--quarantine` makes
  `work/extracted/` and `work/quarantine/` no-exec at the kernel
  (`fsguard.sh --noexec`) and strips execute bits there. `record` and
  `ledger` tools keep a shared ledger of dated events, indicators and
  findings with their evidence, deduped across authors, rendered by the
  harness into `ledger/ledger.md` after every record. `--seats dfir` (or a
  `## Seats` list in the goal) gives every agent a seat before the first
  post. `--cap-per-agent USD` stops one seat over its own budget without
  stopping the swarm. `--allow-host` adds a host to the netguard allowlist.
  `--case-id` and `--examiner` go into the contract, the registry and the
  summary. `swarm.sh summary` prints a run summary from the files;
  `swarm.sh package` writes the hand-over with a hashed manifest. See
  `docs/improvement-plan.md` for where each of these came from.
- **Azure OpenAI** as a team provider: `azure-openai-responses/<model>` in
  `--models`, the key variable and the resource host known to the kickoff
  (from the shell or Pi's credential store, with a warning and
  `--allow-host` when neither has it), the Azure settings forwarded to the
  panes. Any provider defined in Pi's own `models.json` — an Azure AI
  Foundry resource serving Grok or DeepSeek deployments, a gateway, a local
  server — now contributes the host of its `baseUrl` to the netguard
  allowlist, so a mixed team of third-party models on one Azure resource
  needs no `--allow-host`. See `docs/credentials-and-teams.md`.
- **Lessons from the first forensic run.** A shell write to an unclaimed
  `work/` file becomes the writer's claim instead of a notice; the agent
  whose `done` creates the sentinel prompts every idle peer once through
  Herdr (`await-done.sh --nudge` does the same from outside); the eighth
  `bash` call with the same command word earns a hint to forge a tool;
  `swarm.sh stop` records `done` when the sentinel exists; the Budget tab
  shows spend by model and marks agents over their own cap; the agents'
  prompt sends scratch files to `work/<id>/`; an idle watchdog
  (`scripts/idle-nudge.sh`, `--idle-nudge-sec`) prompts an agent that has
  made no tool call for three minutes to continue, and to hold `wait` open
  instead of ending its turn. The evidence catalog also reads a logical
  volume image with no partition table (the second challenge's raw NTFS
  volume was skipped at first). A change seen across a `bash` call is
  charged to it only when the command names the path or the file has
  stopped changing and is not a peer's scratch file: a peer's long shell job
  no longer gets every overlapping call blamed for it. The
  console's swarm page gains a Ledger tab: the events, indicators and
  findings the agents recorded, with authors, seats and evidence, live.

- **Read-only inputs** (`--inputs DIR`): hand the swarm a directory it can
  read and never change. The kickoff copies it into `inputs/` with no write
  bits, keeps a pristine clone and a hashed manifest; `edit`/`write`/
  `claim_file` refuse it, a shell write is detected and healed from the clone
  and announced, and where the host can (macOS `sandbox-exec`, Linux mount
  namespace) the whole pane runs with `inputs/` read-only at the kernel
  through `scripts/fsguard.sh` and a `ZDOTDIR` hook. Each agent records what
  guarded it (`inputs_guard`), an `inputs` tool lists the files, `done`
  records an `inputs_check`; a forged tool gets the same bracket as `bash`,
  and a sweep at every turn end heals what a background process changed. The console offers sets from
  `SWARM_INPUTS_ROOT` on the kickoff form and shows the inputs, the guard per
  pane and the healed writes on the Files tab. `--inputs-enforce on` refuses
  to start without a kernel guard. See `docs/inputs.md` and ADR 0005.
- **Forged tools** (`--allow-tool-forging`, off by default): an agent writes a
  tool with `make_tool` — python3, node or bash, JSON on stdin, stdout as the
  result — and every peer's harness registers it as a real tool on its next
  `inbox` / `wait`. `tools/` is harness-owned; names are exclusive; the author
  owns replacements while active; scripts must match their manifest's hash to
  run; timeouts kill the process group; output is capped. A Tools tab in the
  console shows each tool's script and calls; the trace marks forged calls.
  Proven with the real Pi loader and with two Pi agents on the scripted
  provider. See `docs/forged-tools.md` and ADR 0004.

- **A documented use case**: `docs/use-cases/dfir-web-server-case/` — seven
  agents on two providers investigating a 26 GB forensic case handed over
  as read-only inputs, with the board, the trace, the report, the forged
  tool, console and pane captures, and the bill.

### Added

- **`swarm.sh report <id>`: one self-contained document to hand over.** Cover,
  summary of findings, scope and evidence with a sha256 per file, the timeline
  and the exhibits, the method, the artifacts with their hashes, the
  limitations and the chain of custody — plus the swarm's own
  `work/report.md` reproduced verbatim with its headings demoted so the
  document keeps one outline. Exhibit numbers are the ledger's own `seq`, so
  the console, `ledger.jsonl` and the report all name the same row. It fetches
  no stylesheet, script, font or image: it is read in a room that may have no
  network, years after the run. There is no Markdown library either — none of
  the eighteen delivered reports contains an image, a link or raw HTML, so a
  hundred-line renderer covers the vocabulary and the repo keeps its one
  runtime dependency. `--pdf` prints it through Chrome, Chromium or Edge when
  one is installed; `--lint` checks the citations; `package` writes it too.
- **The print stylesheet, which is where "excellent PDF" actually lives.** A4
  page box, `break-inside: avoid` on every exhibit and row, `break-after:
  avoid` on headings, widow and orphan limits, `thead` set to repeat so a
  forty-row timeline carries its column headers onto every page, a 64-character
  hash that wraps instead of overflowing, and chips that keep their ground
  under the printer's "no background graphics" default. What it does *not* do
  is claim page numbers: `@page` margin boxes are unimplemented in Chrome and
  a `position: fixed` running head is anchored to the first page there, so the
  browser numbers the pages and the document asks to be cited by section. The
  document says so rather than being quietly different.
- **`artifacts.json`: every file under `work/`, hashed.** Walked to any depth
  and streamed, so the extracted tree does not have to fit in memory.
  `work/extracted/` and `work/quarantine/` are hashed and listed with
  `packaged: false` — the ledger cites those paths and sometimes their hashes,
  and a reader has to be able to check one without the package carrying live
  material. Symlinks are named and skipped, never followed.
- **The dossier as files, from the console.** `/api/swarms/:id/dossier/`
  serves `report.html`, `summary.md`, `artifacts.json`, `ledger.jsonl`,
  `ledger.md` and `trace.jsonl` with a filename. Nothing is newly exposed; the
  view routes already returned all of it without a token. What is new is that
  the trace arrives whole — `/traces` clamps to the last 5000 events, which on
  a long run drops the beginning of the case — and that the path says
  "dossier" rather than "download", which is a common content-blocker pattern.
- **A Report tab, and a tab strip in four groups.** The panel shows the report
  at A4 proportions beside every dossier file with its size and hash. The
  strip had grown to eleven tabs with no order to it and the evidence hashes
  were hidden inside `files`; it is now *the run*, *evidence*, *the frame* and
  *output*. `docs/improvement-plan.md` B8 claimed the console linked the
  package; after this it does.
- **`HashChip`, `EvidenceRow`, `DownloadRow`, `FileFacts`, `PrintSheet`.** The
  design system's new pieces, so an input, an artifact and a dossier file all
  say the same thing the same way. `HashChip` falls back to a hidden textarea
  when `navigator.clipboard` is missing, which is exactly the case over plain
  http to a LAN address.
- **The design system carries the evidence components.**
  `ui/src/design-system.ts` and `.design-sync/` are on the same branch as the
  components now, which is where they have to be: the barrel is
  hand-maintained, and a component added to `ui/src/components/` and not added
  there is invisible to every future sync with no warning. `HashChip`,
  `EvidenceRow`, `DownloadRow`, `FileFacts` and `PrintSheet` are in the barrel
  and the `componentSrcMap`, each with a preview, and the conventions header
  states the rule they exist for: anything that names a file names its sha256
  beside it. `cssEntry` is re-pointed at the rebuilt stylesheet — a stale hash
  there ships the old CSS and renders unstyled with no error.
- **The sixteen use-case goal documents are in the goal library**, each with a
  header naming the run it came from and the filenames to change. The library
  went from three, two of which draw a pelican, to nineteen.

- **Six tools for the gaps the corpus left.** `esedb_query` closes the one a
  delivered report recorded in its own words — *no `esedbexport`, so
  `WebCacheV01.dat` and `spartan.edb` could not be parsed as tables* — and the
  same wrapper opens SRUDB.dat and Edge's database. `browser_history` copies a
  database and any `-wal` beside it and opens the copy read-write so the
  write-ahead log is replayed rather than ignored, which is what made
  `sqlite_query` fail on those files in one case. `usn_journal` parses
  `$UsnJrnl:$J`, skipping the sparse front and saying where it started.
  `amcache_apps` reads whichever of the two Amcache layouts the hive has and
  names it. `recyclebin_i` parses `$I` metadata and refuses to decode a path
  from an unknown header version. `yara_scan` sweeps with rules the caller
  names — no rule set ships here, because a stale rule reads like a finding.
  `esedbexport` joins the `dfir` toolbox set.

### Changed

- **`record` requires `source` and `evidence`.** Across fifteen cases all 1501
  ledger entries already carried both, so this costs a working run nothing;
  what it stops is the entry that reads like a conclusion and cannot be
  checked.
- **The fixture is a forensic case.** A compromised web server with hashed
  evidence, an attack path, extracted material, a Prefetch timeline and a
  ledger whose entries cite their source; then a USB policy question, a
  ransomware triage, a single-hive triage and a carve stopped by its cap. The
  run ids and the shapes they exercise are unchanged, so the console coverage
  is the same. What changed is that somebody evaluating a forensic tool no
  longer opens it on `pelican-svg` and `raytracer-stopped`. Re-seeding the
  same directory works now, too: `seedInputs` leaves the tree read-only and
  `rm` could not clear it.
- **The corrected report-citation rule.** `docs/improvement-plan.md` B10
  proposed "every `## N.` section cites at least one path under `inputs/`,
  `catalog/` or `work/`". Measured against the eighteen delivered reports that
  rule rejects **60 of their 127 numbered sections**, because a forensic
  citation is usually not a path — it is an inode, a record id, an event id or
  a registry key. The rule that ships accepts any of those, and all 127 pass.
- **`--color-moss-ink` and `--color-slate-ink` are tokens.** `Chip` had been
  hard-coding `#2f5a1c` and `#2c4660` while every other tone used a token;
  two other call sites moved onto them.
- **Every library tool works on more than one case.** `icat_root`,
  `master_icat` and `hdfs_node_icat` hard-coded the image they were written
  for, so they were unusable anywhere else. Those filenames are defaults now
  and `image` and `offset` name any other. Measured over the eighteen traces
  under `docs/use-cases`: `catalog_grep` was called 152 times, `regkv` 84,
  `evtx_query` 64, and four tools never. That is in the library's README as a
  measurement, not a verdict — three of the four were written late, and one is
  the only AES Crypt implementation here. Nothing was deleted.
- **`split_failures` reaches the console.** A pane that fell back to its own
  tab is a pane the operator is not looking at, and the kickoff has always
  recorded it.

### Fixed

- **Who last wrote an artifact is the snapshot, not the trace.** The index
  treated `claim_file` as a write, so a lease looked like authorship. It now
  reads `history/`: a claim is a lease, the snapshot names the writer.
- **The Report tab's download rows had no hash.** They were a hardcoded list
  with no size and no sha256, while the component next to them exists to
  carry both. `GET /api/swarms/:id/dossier` now returns the handover as one
  product — the HTML, the artifact index, and every file with the hash of
  the bytes it is — so the number beside the button is the number of the
  file the button writes. `package` builds that set once instead of three
  node processes hashing `work/` twice.
- **Four icat writers could land under `inputs/`.** A prefix check on the
  path the caller typed misses `work/../inputs/x` and an absolute path.
  `icat_extract`, `icat_root`, `hdfs_node_icat` and `master_icat` now resolve
  the destination the way `aescrypt_v2_decrypt` already did, and refuse
  before `icat` runs.
- **`.jsonl`, `.yaml` and `.xml` were text in the artifact index and binary
  on the console's work/ list.** One table now answers both.

- **`package` shipped less than the run produced.** It globbed
  `work/*.md`, so a timeline CSV, a JSON export and anything in a
  subdirectory were left out of the handover without a word, and it never
  copied `tools/` although the improvement plan said it kept the run's tools.
  It now copies every regular file under `work/`, the run's `tools/` with
  their manifests, `layout.json` and `netguard.allow`, and hashes all of
  them. `work/extracted/` and `work/quarantine/` stay in the sandbox on
  purpose — that material came out of the evidence and may be live — and the
  command says how many files it left behind. Symlinks are not followed, so
  a link an agent dropped cannot pull an outside file into the package.
- **The ledger and the trace are watched for growth, not for equality.** A
  peer recording a finding while another agent's shell call was running
  changed `ledger/entries.jsonl`, and the watch, which compared hashes,
  reported that peer's `record` as this call's unattributed write to a
  protected path. The two append-only files are now marked by length and by
  the hash of that prefix: a file that only grew is the swarm working, and a
  file whose existing bytes changed is a rewrite, reported as
  `record_violation` on the board with the path named.
- **Three library tools answered confidently when they had failed.**
  `extract_stream` ran `icat … 2>&1 | base64`, so an error message came back
  base64-encoded as if it were file content and the pipe made every call exit
  0; failures are now JSON carrying icat's status and its stderr.
  `sigscan_e01` fell back to a hard-coded 42949672960 bytes whenever
  `img_stat` failed and reported that as the image's media size, so on any
  other image it walked a range that does not exist and called the result
  "no hits"; it now refuses unless the caller bounds the scan with `length`,
  says where the size came from, and lists ranges it could not read.
  `regkeys` decoded every `REG_BINARY` value as UTF-16LE with
  `errors="replace"`, turning a ShimCache or UserAssist blob into mojibake
  that reads like text — and because `"replace"` never raises, the hex
  fallback beneath it was unreachable; values are now rendered by their
  registry type, with binary as hex, matching what `regkv` and
  `reg_hive_query` already answered for the same value.
- **Two claims in `docs/improvement-plan.md` that were not true.** B8 said
  the console links the handover package and B12 said the console offers the
  tool library at kickoff; it does neither. Both rows now say what ships and
  what does not.

- **Three claims in the documents that were not true.** The security policy
  told a reporter to email the address on the maintainer's GitHub profile,
  and there is no public address there; it now names private vulnerability
  reporting first and the profile's own contact route as the fallback. Its
  out-of-scope entry said the console's reads are open to the LAN without
  saying what that returns: the goal document, the board, the whole trace,
  every revision of every `work/` file, any artifact, and the `swarm.sh`
  output of each start, stop and reap. The release checklist claimed no
  personal paths were in tracked files, while the maintainer's home path
  appears 2,594 times in the published pane captures and custody sections;
  the row now says what is there, that it is `~/DFIR/SampleCases` and
  nothing else, and why rewriting a verbatim terminal capture would cost it
  the thing it is published for.
- One broken relative link, out of every link in 259 Markdown files: the
  browser-policy case pointed at pane captures that were not kept for that
  run.

- **Six correctness bugs in the seeded tool library, and a test that keeps
  the library honest.** These are the tools agents wrote during the published
  cases and that every later run is handed, so a wrong answer from one of
  them is a wrong answer in a report.
  - **The BitLocker parser read four fields from the wrong offsets** and
    still printed well-formed JSON — the worst way for a forensic tool to
    fail. It took the metadata size from the block header's own size field,
    fell back to a `uint32` at the same offset when that looked too small
    (yielding the size and the version read as one number), took the
    encryption method 20 bytes past where it lives, took the VMK protection
    type 2 bytes short of it, and started entries at 64 rather than 48. Every
    offset now follows the layout libbde documents, the metadata size is read
    from the metadata header and checked against the copy the format keeps 12
    bytes later, and a disagreement is a refusal rather than a walk over
    arbitrary bytes. The fixture in the test was built to the parser's own
    layout, so it agreed with whatever the parser did; it is rebuilt from the
    documented layout, and the old parser cannot read it at all.
  - **The AES Crypt tool's `inputs/` guard was a string prefix**, which
    `work/../inputs/x` and any absolute path walked straight past. It
    resolves the destination and refuses anything landing in the read-only
    inputs or outside the run directory. A truncated file raised `IndexError`
    where the harness can only relay a traceback; lengths are checked and
    named instead. The manifest's example carried a real case password, which
    an agent would copy into a live call; it is a placeholder now.
  - **`icat_root` exited on `icat`'s code with nothing on either stream**, so
    a failure reached the agent as a bare non-zero with no way to tell a bad
    inode from a missing image. It reports the exit code and `icat`'s stderr.
  - **`grep_filelist` raised on an invalid pattern and on a missing catalog**;
    both are JSON refusals now, the pattern is compiled once, and a result set
    cut to the first 100 says so instead of reading as the whole answer.
  - **`master_icat` read stdin twice**, so the second reader got EOF and, under
    `set -e`, the script died before `icat` ran — the tool never worked. It
    reads its arguments once, validates the inode, refuses an output that
    escapes the run directory, and its refusals reach stdout instead of being
    swallowed by command substitution.
  - **Five manifests no longer matched their scripts** after these edits, and
    the harness refuses a tool whose bytes disagree with its manifest. All are
    rehashed and their versions bumped, the library README is regenerated from
    the manifests (its `fls_root` row had described a tool two versions old),
    and two new tests assert both: every manifest hashes the script beside it,
    and the table says what the manifests say. That drift was invisible until
    a run needed the tool.

- **Thirty-two findings from a second review, one commit each.** The ones
  that changed what the harness does:
  - **A per-agent cap stop wrote the swarm's sentinel**, so `--cap-per-agent`
    ended the whole run instead of one seat — the opposite of what the flag
    documents, and live from the moment the cap first armed. `done` treats
    `reason: agent_cap` as one seat leaving, and the harness stop passes the
    same. The 15-second cap timer now checks the per-agent cap too, so a seat
    inside a long shell call or a `wait` is steered when it passes its own
    ceiling rather than at the next turn end.
  - **A post's `to` field could forge board frontmatter.** A newline in it
    wrote further keys, and the last key won, so a peer's post could read as
    `from: system`. Values are flattened to one line, the first key wins, and
    a post's id comes from its filename rather than from the text.
  - **A forged tool inherited the pane's whole environment**, provider API
    keys included. It now gets PATH, proxy, locale and the run's own `SWARM_`
    context; the console's mutation token is denied by name, and the console
    no longer hands that token to the `swarm.sh` it spawns.
  - **A manifest's `sha256` could be empty or a stub**, which made the
    bytes-match check vacuous; it must be a 64-hex digest, a tool seeded by
    `--tools-from` is sealed into file history at kickoff so its hash is the
    harness's, a directory named after a reserved tool cannot load, and a
    rewritten tool no longer counts as a peer's forge.
  - **Allowlisting a host opened every port on it.** `127.0.0.1` for a local
    model admitted a CONNECT to SSH, to this console, to anything listening.
    An entry with no port is 443 alone; local endpoints carry `host:port`.
  - **The console's API answered any origin** (`access-control-allow-origin: *`
    on every route and the event stream), so a page the operator had open
    could read a run's board, trace, goal and spend. The header is gone, the
    token is a bearer header rather than a query parameter, and an artifact
    page is served under a CSP that cannot fetch.
  - **The reaper killed working agents**: a 300-second silence is normal for a
    `vol` or `fls` over an image, and `swarm.sh status` reaped as a side
    effect of looking. The threshold is 960 seconds, above the catalog's own
    step, a pane Herdr reports as `working` is never reaped, and `status`
    does not reap at all.
  - **Forged-tool output was capped after the child finished**, so a runaway
    script could fill memory first; it is capped as it is read.
  - **`done` could skip the late-correction check** by naming an output file
    that does not exist, or one outside the sandbox.
  - Claims follow the real path rather than a symlink alias; `names.json` is
    harness-owned; the bash watch fingerprints the token cap and the metered
    flag, so a shell cannot lift a local run's only brake; `--env
    SWARM_FSGUARD` is refused whether or not `--inputs` was passed; the
    inputs size and file caps follow the links `cp -RL` will copy; a leftover
    netguard sidecar or idle watchdog from an earlier run is stopped at
    kickoff; the goal library skips a symlink; the overview labels a harness
    stop from the sentinel's own frontmatter instead of inferring it from
    spend.
  - **The evidence catalog** keeps a filesystem whose start sector is 0,
    names its output after the path under `inputs/` rather than the basename
    (two images with the same name no longer overwrite each other), and runs
    Volatility only on files that look like memory.
  - **The tool library**: `icat` and `grep` tools parse JSON instead of
    calling `eval`, extract and catalog tools fail loudly when the image or
    the catalog is missing rather than printing nothing, AES Crypt writes
    plaintext only after both HMACs verify, and the BitLocker parser reads
    the FVE metadata from the volume header offsets.
  - `--toolbox crypto` recognises `pyAesCrypt` as the AES Crypt tool, and
    `SWARM.md` lists a seeded library tool as case-specific.

- **The console's artifact route followed a symlink out of the sandbox.**
  `GET /api/swarms/:id/work/<path>` checked the path lexically and then served
  whatever it pointed at, so a symlink an agent's shell planted under `work/`
  was readable by anyone on the LAN, no token needed. The route resolves the
  file and serves it only when it really lives under `work/`; a test plants
  the link.
- **A forged tool's manifest could name an entry outside its directory.** The
  runner refused that already; the console's read route did not, so a
  manifest a shell rewrote with `entry: ../../..` disclosed the file it
  pointed at. Both go through one check now, an entry is a plain file name,
  and a symlink out of the tool's directory is refused to read and to run.
- **`names.json` was not a harness-owned path.** An agent could claim it and
  rewrite what its peers called themselves through the guarded `write` tool.
  It is in the protected list now.
- **`swarm.sh say` posted without the lock-table mutex**, so an examiner's
  post and an agent's could take the same id. It takes the same mutex as the
  protocol and the reaper.
- Console: an undefined colour token left error notes uncoloured; the
  ledger's names went stale when only the names changed; two running swarms
  were never ordered against each other; a spend past the cap rounded to a
  whole multiple ("2×" at 150 %); the team panel keyed its fragments wrongly;
  and the kickoff form refuses a wall clock above 240 minutes and more than
  twenty extra hosts before the server has to.
- **The per-agent cap never fired.** `--cap-per-agent` was written into
  `budget.json` at kickoff and dropped by the first fold of session usage,
  because the record was rebuilt without the field; the cap then read as zero
  for the rest of the run. Nine forensic runs reported "0 cap steers" while one
  seat finished $1.26 over its cap. The field survives the rebuild now, and a
  test seeds a cap, folds usage, re-reads from disk and asserts the cap fires.
- The published run costs were wrong in both directions, and the case
  documents now carry the invoice rather than the harness's estimate. The
  Azure run was configured with a DeepSeek rate four times below Azure's, so
  it cost $37.03 and not the $24.68 it reported. The eight runs on DeepSeek's
  own API were billed at DeepSeek's peak rate, which is what Pi's catalogue
  carries, while all of them ran outside the peak window, where DeepSeek
  charges half; their DeepSeek seats cost half of what the console showed.
  A `cost` block holds one number, so the reported figure is an upper bound
  whenever a provider's rate depends on the hour.
- `herdr agent start` could hit `agent_pane_busy` on a pane whose shell was
  still starting (more likely with the fsguard hook) and abort the kickoff;
  the launch now waits for the pane to be at a prompt, up to 30 s.
- A large input (a 25 GB disk image) was read whole to hash it; hashing
  streams now, the manifest records mtime and ctime so an unchanged input
  is never re-read, and the inputs copy is an APFS clone where the
  filesystem allows it.
- `swarm.sh start` failed to write the registry on jq 1.6 (Debian 12,
  Ubuntu 22.04), where `label` is a keyword and can be neither a bare key nor
  a variable name; the key is quoted and the variable renamed.

## [0.3.0] — 2026-09-17

The open-source release. Renamed from "Simple Swarm" to **Agent Swarm**.

### Added

- Run a swarm on a Pi **subscription** (OpenAI Codex, Anthropic) with no API
  key, through Pi's own credential store; `pi auth check` gates every model
  before a cent is spent.
- **Mixed-model teams**: `--models "provider/id=count,…"` puts several models
  in one swarm; each agent's model is on the board and in `team.json`.
- A whole swarm end to end with **no provider at all** (`tests/mock-provider.mjs`,
  scripted turns), used for the cap-breach and runaway proofs.
- **Post-sentinel termination**: once `done/SWARM_DONE` exists every agent's
  session is ended at its next tool call, in-flight call included.
- The done sentinel is created with an exclusive `wx` write, so two agents
  finishing at once cannot both claim to have written it.
- **Goal library** (`prompts/goals/`, `/api/goals`), the live contract route,
  and `await-done.sh --checks-json` so the console and the CLI certify a run
  the same way.
- The console redesigned as a warm editorial control room: vitals band, the
  board as a story, the finish line, leases with expiry, team spend, the
  harness panel with a grace clock, the activity strip.
- The console, complete: per-agent colours, thread
  pulse lanes, agent chips with calls, thread overlays with compute budget and
  members, post sizes, the agents page with activity spans, failure ticks,
  token splits and context windows, trace filter chips, a CALL / RESULT modal,
  `/` to find, readiness-aware kickoff.
- One netguard sidecar **port per swarm**, so concurrent swarms never share a
  proxy.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, CI,
  issue and PR templates, Dependabot.

### Changed

- The goal document owns the definition of done; a goal without one is refused.
- Harness-owned paths cannot be written by agents; leases have expiries; threads
  have members and purposes; file history is content-addressed.
- Shell writes are detected, snapshotted and announced on the board rather than
  silently allowed.
- Threads are listed main first, then by most recent post.
- The README is a guide again; the protocol, usage, verified runs and
  troubleshooting moved to `docs/`.

### Fixed

- bash 3.2 empty-array expansions in `swarm.sh` and `netguard.sh`.
- A `pi auth check` failure exit that killed the preflight before it could
  print its blocker.
- The check-then-write race on the sentinel.

## [0.2.0] — 2026-09-16

- Web app: JSON API, SSE change bus, `swarm.sh` actions, fixture seed, API
  tests; Vite + React + Tailwind client; artifacts preview; model picker
  parsing `pi --list-models`.
- Stall reaping, the netguard egress allowlist (unprivileged netns or a local
  proxy), a real Playwright tool driving headless Chromium.
- Pane grid to N=30 across Herdr tabs and workspaces.

## [0.1.0] — 2026-09-16

- V1 N=2 local swarm: file mailbox, exclusive locks, done sentinel, event log,
  live Pi budget, `swarm.sh` kickoff, LAN debugger, file history and restore.

[Unreleased]: https://github.com/halilozturkci/dfirswarm/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/halilozturkci/dfirswarm/releases/tag/v0.3.0
[0.2.0]: https://github.com/halilozturkci/dfirswarm/commit/d8e7e70
[0.1.0]: https://github.com/halilozturkci/dfirswarm/commit/04399a3
