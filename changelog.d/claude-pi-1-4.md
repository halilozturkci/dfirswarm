### Changed: Pi 1.4.0

`@earendil-works/pi-coding-agent` goes from 0.87.1 to 1.4.0, in `package.json` and in the base image (`images/base.Dockerfile`). What it changes here:

- Pi 1.0.3 renamed its Azure provider from `azure-openai-responses` to `azure` (the `AZURE_OPENAI_*` variables are unchanged; the API it speaks is still `azure-openai-responses`). The kickoff's key and host lookups, the console's, the tests and `docs/credentials-and-teams.md` now use `azure/<model>`; the API names stay. An operator whose `~/.pi/agent/auth.json` holds the old key renames it or runs `/login` again, as Pi's own note says.
- Pi 1.0.1 ships no shrinkwrap, so npm puts `pi-ai` beside `pi-coding-agent`, and Pi 1.4 keys its catalogue `<type>:<id>` with image and classifier models beside the chat ones. `scripts/provider-hosts.mjs` finds the catalogue in either place, and the model gateway counts chat models only (it had declined to front `openai` and `openrouter`).
- Pi 1.2.0 fires `before_agent_start` also for runs an extension starts, so the self-compaction hand-off's run now carries the swarm's system prompt like any other, without the inputs guard the pane measured for its first run.
- Pi 1.4 keeps a "Sign in with ChatGPT" login under `openai` (beside `openai-codex`), with a token of about an hour refreshed at `auth.openai.com`: the host allow-list opens that host for an `openai` OAuth login, and the record calls it a consumer plan.

### Fixed: a Linux image's root inside LVM is catalogued (linux-forensics)

dissect.target 3.25, the one in the linux image, prints the target it read before a plain value: `<Target /path/disk.E01> linux`. The `linux-target` recipe read that line as a name it did not recognise, said it could not tell, and the kickoff's census never planned it, so a Linux root inside LVM was not catalogued (the base pack's `disk-volumes` reads the partitions and names the LVM physical volume as a layer The Sleuth Kit does not read). Its detect step now takes off the prefix when it names this image exactly; any other text before the value still makes it no name.

### Fixed: `job_run` writes a tool's output given under `work/<id>/` to the job's `$OUT`

A pack tool run directly and rerun as a job had its output path in the agent's own directories mapped under `{OUT}`; the same tool given to `job_run` did not, and the worker, which writes only its `$OUT`, refused or could not write it. The first microVM case run's three `linux_triage` jobs, each with `out_dir` `work/<id>/triage` as its manifest asks, were refused before anything ran. `job_run` now maps the arguments the same way (what those places already hold stays as given, since it is read) and says where each went (`written_to`).

### Changed: the Linux tools that read files refuse a disk image with the routes that read one (linux-forensics)

`cron_dump`, `shell_history`, `utmp_parse`, `auth_log` and `journal_export` read an extracted root or a file. Given a disk image (by its first bytes, or by its name and a boot sector's signature) they said "no such directory" or read it as text, and the agents fell back to raw `fls` and `icat`. They now refuse it and name the routes: the catalogue's `linux-target` files, `linux_triage` as a job, or the files extracted first in a job with `target-fs`, which the pack now declares. `triage/system-profile` says the same: the catalogue first, then `linux_triage`, and `target-fs -q <image> cp <dir> -o "$OUT/root<dir>"` for the tools that read files.

### Changed: a skill id asked with its pack in front loads that pack's note

`skill("linux/accounts/users")` answered "no such skill" with a suggestion. A leading segment that is a pack id of the run, or the start of one, is now taken off when exactly one such pack carries the rest, and the answer says the id to use.

### Fixed: a ChatGPT sign-in no longer stops a microVM kickoff

The seats' subscription tokens are minted for the wall clock and an hour, and a "Sign in with ChatGPT" token under `openai` lives about an hour, so the kickoff stopped with "pi could not produce a openai subscription token valid for the run" unless `SWARM_TOKEN_MIN_VALIDITY` was set. A subscription that cannot be minted for the run's floor but can for 50 minutes now brings the floor down to 50 minutes, renewed on the host at half that (within the ten minutes between the watchdog's checks), and the kickoff says so; the error, where it still comes, names the floor and the variable.

### Fixed: `check_inputs` runs as a job (computer-forensics-base)

A job sees the run's directories, not the run's `inputs.json`, and a share is a directory: the first microVM case run's `check_inputs` job answered "inputs.json not found". A job that sees all of `inputs/` (its `inputs` left out, or `["all"]`) now gets a copy of the run's `inputs.json` in its control directory, named by `SWARM_INPUTS_MANIFEST` and listed among what it could reach, up to 16 MiB; never a link, so what the job writes there is not the run's baseline. `check_inputs` reads that copy in a job, and says why when there is none.

### Changed: work over a whole source leaves the agents a worker

The kickoff's recipes, a recipe an agent asks for with `catalog_request` (a super-timeline) and the derived catalogue's work now hold at most every worker the agents' longer jobs take but one (one, with the default two workers). In the second microVM case run the kickoff's `linux-target` and an asked-for `disk-timeline` held both workers, and the agents' jobs waited up to 505 s (p90 291 s, against 14 s the run before); the super-timeline then held one of the two for 94 minutes.

### Changed: the route to a Linux file by path is where agents look (linux-forensics)

The second microVM case run's agents reached files inside LVM with `fls` and `icat` at the logical volume's offset and never met `target-fs`: the note that named it (`triage/system-profile`) was not loaded. `filesystem/storage-lvm-luks`, which they did load, now says how to read a logical volume's files: what the catalogue parsed first, The Sleuth Kit by inode at a linear volume's offset (which keeps the record's identity), and `target-fs` by path for anything else. `linux-target`'s receipt (`coverage.json`), which the agents read first, names the same route in `files_by_path`.
