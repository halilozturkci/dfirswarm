# Usage

Every command, flag, environment variable and API route, and how to write a goal. The README's quick start is the short version of this.


### `scripts/swarm.sh`

```
scripts/swarm.sh start --model <provider/id> --cap-usd <n> --n <N>
    [--models "<provider/id>=<k>[@USD],..."]
    [--compact-at SPEC] [--compact-warn-at SPEC] [--compact-notice-at SPEC]
    [--compact-model P/ID] [--inbox-page-chars N]
    [--goal-file FILE | --goal "<markdown>"]
    [--sandbox DIR] [--allow-synced-folder] [--custody-timeout SEC]
    [--label NAME] [--wall-clock MIN] [--stop cap-pause|cap-stop|operator]
    [--until-solved [--stall-minutes N]] [--hard-kill] [--playwright]
    [--cap-per-agent USD] [--cap-per-agent-tokens N] [--cap-tokens N] [--idle-nudge-sec N]
    [--allow-tool-forging] [--allow-install] [--no-pypi] [--tools-from DIR]
    [--no-read DIR]... [--accept-signer-exposure]
    [--inputs DIR]... [--inputs-enforce auto|on|off] [--inputs-max-mb N] [--inputs-max-files N]
    [--catalog] [--toolbox <sets>|auto|off] [--toolbox-required] [--quarantine]
    [--allow-host HOST]... [--provider-host P=HOST]... [--case-id ID] [--examiner NAME] [--operator ID]
    [--probe-violation] [--no-netguard] [--open-net] [--net-allow] [--local-only] [--no-start]
    [--network closed|dynamic|open] [--policy standard|live_adversary|internal|ctf]
    [--lookups none|reference|evidence_linked|any] [--contact passive|active] [--disclosure CLASSES]
    [--more-evidence no|ask|yes] [--material-use CLASS=USE,...] [--legal TEXT] [--provider-retention TEXT]
    [--key-from-env] [--env KEY=VALUE]... [--customer-case] [--key-owner [PROVIDER=]OWNER]...
    [--token-alert N[,M...]] [--derived-limit N]
    [--notify TARGET]... [--ledger-from RUN] [--no-verify-copy] [--allow-root] [--model-gateway] [--check]
scripts/swarm.sh image-for [--pack ID]... [--tools-from DIR] [--playwright] [--no-jobs] [--brains-with-packs]
scripts/swarm.sh list
scripts/swarm.sh status <id>
scripts/swarm.sh stop <id> [--no-custody] [--custody-timeout SEC]
scripts/swarm.sh extend <id> [--minutes N] [--tokens N] [--usd N]
scripts/swarm.sh pause <id> [--why TEXT]
scripts/swarm.sh unpause <id>
scripts/swarm.sh resume <id> [--question TEXT]... [--questions FILE] [--why TEXT] [--as ID] [--skip-refused-questions]
    [--minutes N] [--tokens N] [--usd N] [--env KEY=VALUE]... [--no-start] [-- START OPTIONS]
scripts/swarm.sh requests <id> list [--open] [--json] | show R-n [--json]
scripts/swarm.sh requests <id> ack|answer|decline|withdraw|authorise|collecting|unavailable R-n [TEXT | --why TEXT] [--as ID]
scripts/swarm.sh evidence <id> add PATH --why TEXT [--for R-n] [--question Q-n]... [--sha256 HEX] [--as ID] | list [--json]
scripts/swarm.sh material <id> add PATH --why TEXT [--class operator_supplied|case_material] [--sensitive] [--as ID] | list [--json]
scripts/swarm.sh tool-supply <id> add PATH --why TEXT --source TEXT [--built TEXT] [--sha256 HEX]... [--for R-n|L-n]... [--as ID] | list [--json]
scripts/swarm.sh symbols fetch --accept-terms --accepted-by NAME [--from DIR] [--name TEXT]... [--packs DIR] [--store DIR] | list [--json]
scripts/swarm.sh summary <id>
scripts/swarm.sh context <id> [--json]
scripts/swarm.sh package <id> [--sign [--key FILE]] [--redact [--redact-leaks list]] [--with-outputs]
scripts/swarm.sh verify <package dir|zip> [--allowed-signers FILE] [--ca FILE [--ca-intermediate FILE]] [--tsa-ca FILE]
scripts/swarm.sh custody-verify <id> [--allowed-signers FILE --identity NAME] [--tsa-ca FILE] [--scratch DIR] [--json]
scripts/swarm.sh examiner enroll --name NAME --organisation ORG --competence TEXT [--role examiner|reviewer]
    (--generate-key [--no-passphrase] | --key FILE [--no-passphrase] | --fido [--fido-verify-required] [--fido-resident]
     | --pkcs11-module PATH (--pkcs11-id HEX | --pkcs11-uri URI) [--pkcs11-chain FILE]) [--id ID] [--principal P] [--tsa-url URL --tsa-ca FILE]
scripts/swarm.sh examiner list | show ID | machine
scripts/swarm.sh machine [rotate]
scripts/swarm.sh review <id> (--adopt N [--note T] | --qualify N --note T | --reject N --note T | --inconclusive N --note T
    | --accept N [--note T] | --amend N --note T
    | --technical-review --reviewer ID|NAME --outcome agreed|issues-resolved|disagreement --checked TEXT [--entries 4,10 | --all-answers]
      [--disagreement TEXT]... [--reviewed-at ISO] [--competence TEXT]
    | --countersign SEQ --reviewer ID | --import FILE [--allowed-signers FILE | --ca FILE]
    | --sign [--pdf] [--amend-reason TEXT] [--report PATH] [--no-timestamp] [--yes] | --show) [--examiner ID]
scripts/swarm.sh review <package-dir> --technical-review --reviewer ID ... [--out FILE]
scripts/swarm.sh releases <id> [--draft [--reason TEXT] | --verify [--allowed-signers FILE] [--ca FILE [--ca-intermediate FILE]] [--tsa-ca FILE] | --print [N]
    | --mirror cmd:COMMAND|dir:PATH|print [--version N] | --ots [--upgrade] | --transparency COMMAND | --json]
scripts/swarm.sh timestamp <id> [--version N] [--tsa-url URL] [--tsa-ca FILE]
scripts/swarm.sh rerun <id> <job> [--normalise timestamps@1] [--network] [--json]
scripts/swarm.sh certify <package dir|zip> [--allowed-signers FILE] [--tsa-ca FILE] [--out FILE]
scripts/swarm.sh export <id> --format csv|timesketch [--out FILE]
scripts/swarm.sh hold <id> [--reason TEXT]
scripts/swarm.sh release <id>
scripts/swarm.sh purge <id> [--yes]
scripts/swarm.sh tools <id> [--save DIR | --candidates [--out DIR] [--min-lines N] [--library DIR]...]
scripts/swarm.sh say <id> "<message>"
scripts/swarm.sh ui [--port N] [--host H] [--no-build] [--inputs-root DIR]... [--allow-inputs-root-from-ui]
scripts/swarm.sh reap [id] [--stall-sec N] [--stop]
scripts/swarm.sh netcheck
scripts/swarm.sh help [command]
```

`swarm.sh --help` prints the commands and the options a run usually needs.
`swarm.sh help start` (or `start --help`) prints every `start` option with its
default; a test holds that page to the parser, so an option that exists is on
it. A wrong command line prints the mistake and where to read, not the manual.

#### `start`

| Flag | Required | Default | Effect |
| --- | --- | --- | --- |
| `--model provider/id` | yes, unless `--no-start` | — | Passed to `pi --model`. The prefix picks the provider key variable and the netguard allow host. The registry keeps the ids asked for and the date (`model_identity`: `requested`, `recorded_at`, and `floating` for an id that names no dated model); the kickoff warns of an id with `latest` in it (`-latest`), which the provider can serve as another model from one run to the next. When a provider says a model other than the one asked for answered a seat (Pi's `responseModel`, which the Messages and Chat Completions APIs carry and the Responses APIs, Codex's included, do not), the seat's harness puts a `model_reported` line on the trace: an alias resolved to one of its dated ids is `resolved`; any other model is a substitution, said on the board (`MODEL SUBSTITUTION`) and, in a VM run, to the notify hook (`model_substitution`). A substitution is the operator's to decide on; a run meant to be compared or repeated stops on it. |
| `--cap-usd N` | yes, unless nothing on the team bills | — | Swarm-wide spend cap written to `budget.json`. At `spent_usd >= cap_usd` the first agent over gets a steer to `done cannot_complete`. A team whose every model is unmetered (a local server, or a `models.json` provider with no `cost` block) reports an exact $0 whatever happens, so this cap cannot stop it; such a team needs `--cap-tokens` instead and may leave this out. So does a team on a subscription (an OAuth login in Pi's store, such as `openai-codex`): Pi's dollars for it are an estimate from a price list, not a charge, and not comparable across models (a GPT-6-Luna seat with ten million tokens read $0.13, a Daybreak Blue seat $14), so they brake nothing there. Under `--isolation microvm` the spend is what each seat reports about itself (a report may only grow), not something the host measures; the brake the host holds by itself is the wall clock (and each VM's `maxDuration`). |
| `--n N` | yes | — | 1–30 agents. Warns above 10. The harness assigns no roles and adds no artifacts of its own — if you want a critic, say so in the goal. |
| `--goal-file FILE` | no | `prompts/goals/hello.md` | The goal document. Must contain `## Definition of done`; its `## Checks` lines are what `await-done.sh` runs. Stored in the registry and shown in the UI. An investigation from the library (`library/<category>/<slug>.md`) launches as it is: the metadata block at its top is stripped, and the contract starts at `## Goal`. |
| `--goal "markdown"` | no | — | The same document inline. Same rule: no definition of done, no swarm. |
| `--key-from-env` | no | off | Read the provider key from the shell and pass it to each pane instead of letting Pi use its own store. For hosts with no persistent home; the key is briefly visible in `ps`. A subscription login needs neither a key nor this flag, and a local server has no key to forward: the kickoff refuses the combination rather than scanning the shell for someone else's. |
| `--models` | no | — | A mixed team: `provider/id=count`, comma-separated, e.g. `openai-codex/gpt-6-astra=3,deepseek/deepseek-v4-pro=2`. N is the sum of the counts. Every model is credential-checked and every provider's hosts reach the netguard allowlist. Mutually exclusive with `--model`. An entry may end in `@cap`, a USD ceiling on the combined spend of every agent running that model — `openai/gpt-5.4-mini=2@6,openai/gpt-5.4-nano=2@4` — for a team where the cost is in the model rather than the seat, which one `--cap-per-agent` number cannot fit. Over it, each agent on that model is steered to finish and stopped the way the per-agent cap does it, and the other models' agents go on. A per-model cap must fit under `--cap-usd`. Written to `budget.json` and the registry as `cap_per_model_usd`. See [docs/credentials-and-teams.md](credentials-and-teams.md). |
| `--env KEY=VALUE` | no | — | Extra environment for every agent pane; repeatable. `PI_CODING_AGENT_DIR` must be absolute. Under `--isolation microvm` a name that looks like a credential (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*PASSWD*`, `*CREDENTIAL*`; the match is case-sensitive, upper case only) is refused: it would enter every VM and its snapshot in clear; Pi's store and a pack's secrets are where a key lives, and the VM gets a placeholder. |
| `--customer-case` | no | off | A customer's case: API keys only ([ADR 0003](adr/0003-the-provider-key-comes-from-pis-own-store.md), "Whose credential, under which terms"). Refused before anything is written: a seat on any subscription (OAuth) login in Pi's store, `openai-codex/*` whatever the store says (a ChatGPT login by design, whose consumer terms carry no processor commitments), `--allow-oauth-in-vm`, `--policy ctf`, and a provider whose key has no owner named (`--key-owner`). The record (`customer_case`, `credentials`) and custody (`models.credentials`, a line of the verdict) keep whose key each seat used. |
| `--key-owner [PROVIDER=]OWNER` | under `--customer-case`, for each provider | — | Whose API key a provider uses: the customer's own, or your business account's with the customer told. `OWNER` alone names it for every provider; repeatable. Recorded in any run, per seat: the registry's `credentials` (seat, model, provider, `credential`: `api_key` or `oauth` in Pi's store, `env` with the `variable` Pi would read (its name, never its value), `local`, or `other` for `models.json`; `owner`) and the custody anchor, which custody prints. A subscription seat is recorded with `plan: "consumer plan; not for customer data"` (ChatGPT/Codex; another provider's as `"subscription login; not for customer data"`), and its kickoff `Key:` line says the same. **Every run**: an `anthropic/*` seat on a Claude subscription login (an `oauth` entry in Pi's store, or `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_OAUTH_TOKEN` where the store holds no key: Pi takes those before `ANTHROPIC_API_KEY`, and a bearer token is not an API key) is refused, `--allow-oauth-in-vm` or not: Anthropic does not permit Free, Pro or Max credentials in a third-party client such as Pi. Log Pi in to Anthropic with an API key (`/logout anthropic`, then `/login anthropic` with the key). Codex's subscription stays usable for a test or CTF run. |
| `--sandbox DIR` | no | `runs/<id>` | Isolated cwd for this run. |
| `--allow-synced-folder` | no | refused | Let a copy of the evidence (`inputs/` and `.inputs-pristine/`), or the VMs' kept disks, go into a folder a sync client uploads (under `~/Library/CloudStorage`, iCloud Drive, Dropbox, OneDrive, Google Drive). Without it the kickoff refuses, before anything is written. A regular file of yours named `.dfirswarm-allow-synced` at the top of the synced folder, or in any folder between it and the destination, allows that destination the same way; each synced destination needs its own, and the flag covers all. The registry says which allowed it (`synced_folder_allowed_by`: `flag`, `marker` or null). A run directory in such a folder is warned about in any case, for what the agents derive there. |
| `--brains-with-packs` | no | off | Boot the agents' own VMs from the image that holds the run's packs. By default, in a microVM run with jobs and packs, the agents boot the base image (a shell, Python and the tool library) and the packs' programs are in the job images: each pack's own profile (`images/recipe.py profile-for`), and the one holding every pack as the default. A command that names none runs in the smallest job image whose own record (`image.json`: `on_path`, every program on its PATH, and `binaries`) holds every program it runs, and in the default whenever that is not sure (a heredoc, a quoted script, an import, a script of the agents'); `job_started` says which image and why. A job names one with `job_run profile=<name>`; a pack tool or a recipe runs in its pack's (a recipe may name one in `recipe.json` as `profile`). Each image's program list is read at kickoff into `images/<profile>/tools.md` (and `image.json`), read-only, and SWARM.md's "Job images" lists them. An image this host does not hold is pulled; one that cannot be had is left out and its packs' jobs run in the default. The toolbox check and the kickoff's catalogue plan run in the default job image. `--playwright` keeps the packs out of the agents' image question: its browser is in the agents' VMs. |
| `--inputs-hashes FILE` | no | — | The acquisition hashes an imager recorded for the evidence (md5sum, sha1sum or sha256sum lines, or BSD `SHA256 (name) = digest`; the algorithm is the digest's length). Each is held to the digest the kickoff computes, and the kickoff is refused on a mismatch or a name that is none of the inputs; the list goes into `inputs.json` (anchored with it) and custody compares it again. Without it, custody's "unchanged" means unchanged since the kickoff hashed the evidence. |
| `--custody-sign-key FILE` | no | — | Sign each custody verdict with this ssh key (`ssh-keygen -Y`, namespace `dfirswarm-custody`): `custody.json.sig` beside it, its hash and the key's fingerprint in the anchor. Recorded in the registry as `custody_seal`. |
| `--custody-timestamp-url URL` | no | — | Have each verdict's sha256 timestamped by this RFC 3161 authority: `custody.json.tsr` beside it, the authority's time in the anchor. |
| `--custody-timestamp-ca FILE` | no | — | The authority's CA certificates (PEM). Each token's signature and certificate are checked against them with `openssl ts -verify` (openssl is required) and the result goes into the anchor beside the token (`verified`, the CA's path and sha256, openssl's words); `custody-verify` checks it again. Without it a token is held to the verdict's digest only, and the anchor, the report and `custody-verify` say "imprint only". Also `SWARM_CUSTODY_TSA_CA`. Recorded in `custody_seal.timestamp_ca`. |
| `--time-reference URL` | no | — | Record this https server's clock offset from the host's (its `Date` header, a second's precision) in the anchor at kickoff and in the verdict at custody. |
| `--anchor-mirror TARGET` | no | — | Copy each release's digest line somewhere this account does not keep: `cmd:COMMAND` (the line on its stdin; its output kept whole as the receipt, `mirror-<k>.json` beside the release), `dir:PATH` (a directory that exists: a file per release, never written over), or `print` (the line and a QR-ready string in `case-file.txt`, and printed). An object-locked bucket's mount or a records custodian's separately administered archive is the independent copy; a folder of the same account is not, and a signed git remote is a witness of when a line was pushed, not a write-once store. Recorded as `anchor_mirror`; `SWARM_ANCHOR_MIRROR` for a run without one. |
| `--custody-timeout SEC` | no | 14400 (`SWARM_CUSTODY_TIMEOUT`) | How long custody may take at the run's end, whoever takes it: the hub at a microVM run's finish, or `stop`. Recorded as `custody_timeout_sec`; `stop --custody-timeout` overrides it for that stop. |
| `--notify TARGET` | no | none | Who is told when something happens to the run; repeatable. `desktop:` (a desktop notification: `osascript` on macOS, `notify-send` elsewhere), `ntfy:<topic>` (a push through ntfy.sh, or `ntfy:https://host/topic` for a server of your own), `mailto:<address>` (this host's `mail` or `sendmail`), or a command of yours. The events: `finished`, `finish_failed`, `stop_incomplete`, `budget_cap`, `wall_clock`, `paused` (a `cap-pause` run held at a cap, or any run paused because the model provider refused every seat, with the time the provider named when it named one; the operator is told of a pause once per spell, whichever process wrote it; your own `swarm.sh pause` is not announced back to you), `extended` (a cap pause lifted by `extend`), `operator_request` (an operator request committed: a lead that needs you, an acquisition, a clarification, a network item, a stop proposed when nothing yields; fired by the hub, [ADR 0014](adr/0014-the-case-contract-says-what-comes-in-and-what-is-asked.md)), `token_alert` (a `--token-alert` mark crossed: the mark and the count), `model_substitution` (a provider said a model other than the one asked for answered a seat: the seat; from the hub, in a VM run), `evidence_changed`, `chain_broken`, `agent_dead`, `collector_unreachable`, `hub_down`. A command gets one JSON line on stdin (`{event, run, at, event_id, detail, details}`), where `detail` holds only identifiers (a request's `R-n`, its kind, a lead's or question's id, an urgency, a state), numbers and yes/no values, and every list as its count; the event's whole details stay in the run, in `traces/notify-events.jsonl` under `event_id` (`details` says where). A typed target gets the event and the run's id. Nothing a notification carries is case content: it leaves the host. `mailto:` takes one mailbox (`local@domain`, never beginning with `-`), given to `mail` or `sendmail` after `--`. Each target runs detached and has 30 seconds; a failure or a timeout goes to `traces/notify.log` and never stops the run. The targets are kept outside the run (`runs/notify/<id>.cmd` and `<id>.targets`, 0600, in a directory denied to a host run's panes wherever the guard can deny, read only when they are regular files of yours; an ntfy topic is its secret), never in the start options kept for a resume: `swarm.sh resume` gives the command and each target to the kickoff again from that store. The registry records only that there is one (`notify: true`), and the operator's record shows their length, not their text. |
| `--ledger-from RUN` | no | none | An earlier, finished run's ledger handed in as hypotheses to re-derive or refute: `prior/ledger.md`, read-only (on a VM run it is on the read-only floor), never copied into the new ledger. When the earlier run has an examiner review whose chain verifies, only the entries whose latest review accepted or amended them (and whose entry hash still matches) come in; otherwise every entry, each marked unreviewed. Refused for a run that is running, purged, or held for another case. Recorded as `ledger_from`. |
| `--no-verify-copy` | no | content check on | By default the evidence copy is checked against its source by content: each copied file's source is read again and its SHA-256 compared with the manifest's (progress every 2 GiB on large sets), and a mismatch is a BLOCKER. This keeps only the check by name, kind and size. Recorded in `inputs.json` as `source_checked`. |
| `--allow-root` | no | refused | Start a host run (`--isolation host`) as root. Without it that is a BLOCKER: root is not bound by the read-only modes a host run relies on. A microVM run started as root is warned about, not refused. Recorded as `allow_root`. |
| `--check` | no | off | Run every refusal and preflight of this start, the same code a start runs, and write nothing: no sandbox, no registry entry, no hook, no daemon, no VM, no pull, and no line on the operator's record. It prints what the start would print, and ends with `Check: the start would go ahead (…); nothing was written`. Exit 0 when the start would go ahead, 2 when it would be refused, whatever the refusal. An image that is not on the host is a WARN, since a start would pull it first. The console's New swarm form runs it with the form's options and keeps Start off while it says the start would be refused. |
| `--model-gateway` | no | off | microVM runs: every model call a VM makes goes through one process on the host that holds the provider key, meters the call from the provider's own answer and refuses a stopped seat's call, or a call past a cap or the wall clock once the harness's grace has passed. The VM holds a seat token, never a key. Providers it cannot front keep msb's placeholder path, and the kickoff names each (`Gateway:` lines). Refused with `--isolation host`. Recorded as `isolation.model_gateway`. See [model-gateway.md](model-gateway.md). |
| `--label NAME` | no | `swarm-<id>` | Herdr workspace label and UI label. |
| `--wall-clock MIN` | no | 8 (N<10), 15 (N≥10), 20 (N≥20) | Written to `SWARM.md` and `budget.json`. **Enforced**, the same way the spend cap is, under the run's stop policy (`--stop`): the agents are steered, and one grace period later the run pauses (`cap-pause`) or the harness writes the sentinel itself (`cap-stop`). The time a run spends paused does not count. |
| `--stop POLICY` | no | `cap-pause` | What reaching a cap or the wall clock does ([ADR 0013](adr/0013-a-negative-is-bounded-and-a-cap-pauses.md)). `cap-pause`: every agent is steered to post a checkpoint, and two minutes later the run pauses: no model call goes out (the extension's own brake, the model gateway, the hub's prompt gate and the watchdog each hold it), every seat stays where it is, the partial result is kept, and the notify command hears `paused`; `swarm.sh extend` goes on, `swarm.sh stop` ends it as `stopped`. The run never goes on by itself, and your silence approves nothing. `cap-stop`: the harness stops the run after the grace period, for an unattended run; it ends `stopped`, never `completed`. `operator`: `--until-solved` (no wall clock, caps advisory, only you end it). A goal can name it in its metadata block (`stop: cap-stop`); a goal or flag that says `--until-solved` and another policy is refused. Written to `budget.json` as `stop_policy`, and to the registry. A run from before it reads as `cap-stop`. |
| `--hard-kill` | no | off | After the cap steer, also call Pi `ctx.shutdown()` on that agent. |
| `--playwright` | no | off | Adds `playwright` and `browser_check` to the agents' `--tools`. |
| `--allow-tool-forging` | no | off | Agents may write tools with `make_tool` and share them: a script under `tools/<name>/` becomes a real tool for every agent on its next `inbox` / `wait`. Runs as a subprocess with the same limits as `bash`. Recorded as `tool_forging` in the registry. See [forged-tools.md](forged-tools.md). |
| `--no-self-compact` | no | on | Turn self-compaction off. On by default: each agent watches its own context against an effective ceiling the harness sets per model (272k for the GPT-5.4/5.5 family, 200k for grok-4.6, 300k for a million-token model, the declared window otherwise), receives a transient notice and warning as it climbs, and at the compact line every tool except `self_compact`, `budget` and `done` is refused until it hands off with `self_compact(note_to_self)`; the context is summarized with `prompts/compaction-summary.md` and the note comes back verbatim under the harness's own facts (live claims, unread posts, the ledger). Pi's own overflow compaction stays as the safety net and is recorded as such. Recorded as `self_compact` in the registry; a `context` row per turn and every `compact_*` event on the trace; `context_ceiling`, `context_level`, `compactions`, `compaction_usd` and `handoffs` per agent in `budget.json`. `--self-compact` says on explicitly. See [self-compaction-plan.md](self-compaction-plan.md). |
| `--compact-at SPEC` | no | `60%` | The compact line, as a token count (`150000`, `150k`, `0.5m`) or a percentage of the ceiling, optionally followed by per-model overrides, comma-separated: `60%,openai/gpt-5.4-mini=55%,grok-4.6=70%` (a key with a slash is a `provider/id`, one without matches the model id under any provider; the last match wins; a list with no seat value leaves the seats it does not name on the default). Never above what the window can hold once Pi's reserve and 32k of headroom are kept; an explicit value that does not fit is refused, a default that does not fit is clamped and noted on the trace (`compact_config`, which also records which per-model entry applied under `matched`). A line left unset is a default fitted to the lines you set, per seat and noted on the same row: it rises to a higher line set below it (the compact line no higher than the window holds) and drops below a lower line set above it in the defaults' 40 : 50 : 60 proportion, so `--compact-at 45%` alone runs at 30 / 37.5 / 45%. Two lines you set that are out of order are refused. The kickoff and the run's detail page mark an unset line `(default)` when another is set; `self_compact.set` in the registry says which lines were set. |
| `--compact-warn-at SPEC` | no | `50%` | The warning line: finish the current atomic step, write the note, hand off. Same shape as `--compact-at`. |
| `--compact-notice-at SPEC` | no | `40%` | The notice line: awareness only. Same shape. |
| `--compact-prompt-file FILE` | no | `prompts/compaction-summary.md` | Replace the system prompt of the summary call. Under `--isolation microvm` the file is copied into the run (`compact-prompt.md`), so nothing else in its directory reaches a VM. |
| `--compact-model P/ID` | no | each agent's own | Send every summary call to this model: a cheap summarizer for expensive seats. It is credential-checked and its provider's hosts join the netguard allowlist like a seat's model, and it never counts as a seat (no cap, no share of `--models`). Recorded as `self_compact.model` in the registry; `compact_config` says which model the seat will use (`summary_model`, `summary_model_source`) and `compact_done` which one wrote each summary; a model Pi's registry does not know falls back to the agent's own and the config row says so (`summary_model_problem`). The summary's cost is the summarizer's, counted in `compaction_usd`. Refused with `--no-self-compact`. |
| `--inbox-page-chars N` | no | `40000` | How much post text one `inbox` or `wait` delivery carries. Whole posts only: a post is never cut, a delivery stops before the post that would break the bound, what stayed behind is still unread and the next call (or `wait`, at once) delivers it; the result says `remaining` and why. `0` removes the bound. Recorded as `inbox_page_chars` in the registry. |
| `--inputs DIR` | no | — | Hand the swarm a read-only copy of `DIR` as `inputs/`: the tools refuse to write it, a shell write is detected and healed from a pristine copy, and where the host can (macOS `sandbox-exec`, Linux mount namespace) the panes run with it read-only at the kernel. Recorded as `inputs` in the registry. Repeatable: several sets each land at `inputs/<name>/` (the directory's name as given), and every other `--inputs` flag applies to all of them. See [inputs.md](inputs.md). |
| `--inputs-enforce M` | no | `auto` | `auto`: kernel guard when the host has one, otherwise a `WARN`; `on`: refuse to start without one (exit 3); `off`: detection and healing only. |
| `--inputs-max-mb N`, `--inputs-max-files N` | no | none | Refuse an inputs directory larger than N MB, or with more than N files, before anything is copied (several sets: together). Unset by default: evidence is as large as the case is. `SWARM_INPUTS_MAX_MB` and `SWARM_INPUTS_MAX_FILES` set the same limits from the environment. |
| `--catalog` | no | off | Before the agents start, run the standard first pass over the inputs once (`scripts/evidence-catalog.sh`): for a disk image the partition table, per partition a body file, a MAC timeline and a path list (a logical volume image with no partition table is catalogued from sector 0); for a memory image Volatility's info, pslist, psscan, cmdline, netscan, malfind and dlllist. What an input is and how it is catalogued are the packs' recipes (`recipes/<name>/` in a pack; computer-forensics-base ships disk volumes, Windows memory, archive members and AD1 logical images); the harness takes the census: every input gets a row in `catalog/coverage.tsv` — catalogued, in part, planned, a further segment of a set, not catalogued, or smaller than any recipe asks about — with why, and the index names those not catalogued, so an input this pass could not read is named rather than missing. In a microVM run with the job service (the default) the census only plans the recipes (`catalog/plan.json`); they run as jobs once the hub is up, while the agents work, each result a generation under `catalog/gen/` and each change a revision under `catalog/revisions/<n>/`, announced on the board. What a step wrote to stderr is kept whole beside its output (`<file>.stderr`). A recipe a pack declares a broad extraction (a parse of the whole source into a searchable form, where the rest of the catalogue inventories it: the mobile pack's iOS and Android parsers over a full file-system acquisition, the base pack's super timeline of a disk image) is asked about every input too; each that applies is listed in `catalog/plan.json`'s `preparations` and in the README, run by the kickoff where its pack marks it so and otherwise offered as a lead once the run is up, and its receipts are kept on the store journal ([ADR 0013](adr/0013-a-negative-is-bounded-and-a-cap-pauses.md), "A source's broad extraction before a negative on it"). Lands in `catalog/`, harness-owned and read-only, indexed in `catalog/README.md` and rendered into `SWARM.md`. Needs `--inputs`; implies `--quarantine` and `--toolbox dfir`. Under `--isolation microvm` it runs with the image's tools, not the host's. |
| `--allow-missing-symbols` | no | off | With `--catalog`: start although a recipe's detect says the image lacks what it needs to read an input — a memory image's kernel symbol table above all (the base pack's `memory-windows` recipe asks, offline, which kernel the image runs, and names it when the image holds no table for it; a probe that does not answer within 30 s, `SWARM_CATALOG_MEMORY_PROBE_TIMEOUT`, says the table's presence is unknown, the same way). Without it that is a BLOCKER, at the start and at `start --check` (which runs the census's detect in a throwaway VM of the census's image and keeps nothing): the program cannot read the image offline. The verdict names the image the census ran in, and says so when a pack's jobs run in another. With the flag the run goes on with what needs no kernel table, said as a WARN; either way the census writes `catalog/missing.json` and says it in the catalogue's README, and the generation's post says it to every seat. Any other kind of missing data is a WARN. |
| `--toolbox M` | no | `off` | `dfir`: check the forensic toolbox on this host (`scripts/toolbox.sh`: Sleuth Kit, Volatility 3, regipy, python-evtx, yara, exiftool, sqlite3, strings, python3) into `toolbox.json` and a Toolbox section of `SWARM.md`, with install commands for what is missing; `auto`: `dfir` when `--catalog` is set, plus the sets a `--goal-file`'s metadata block names in `toolbox:` (without the key, the sets its words suggest), and `crypto` when a VHD(X), VMDK, QCOW2 or encrypted container is under the inputs; `off`. `crypto` adds the volume readers (libbde, libvhdi, libluksde, libvshadow, dfvfs, qemu-img), `linux` the journal, XFS (xfsprogs) and LVM (libvslvm) readers. |
| `--toolbox-required` | no | off | A missing tool is a `BLOCKER` (exit 3) instead of a `WARN`. |
| `--quarantine` | no | off | `work/extracted/` and `work/quarantine/` cannot execute: no-exec at the kernel where the host can (`fsguard.sh --noexec`), and the harness strips execute bits from anything written there. Evidence pulled out of an image is for reading, never for running. |
| `--tools-from DIR` | no | — | Seed `tools/` from a library of tools forged in earlier runs: one directory per tool, each with its `manifest.json` and script. They are in every agent's list from the first turn, author and version kept, so a swarm does not rewrite what the last one wrote. `swarm.sh tools <id> --save DIR` puts a finished run's tools into such a library. |
| `--allow-install` | no | off | Agents may install the Python packages a case needs: `pypi.org` and `files.pythonhosted.org` join netguard's allowlist, `PYTHONUSERBASE` points at `work/.toolchain/` inside the sandbox, `PIP_BREAK_SYSTEM_PACKAGES=1` lets pip install there on a system that marks its Python as externally managed (PEP 668), which also means PEP 668 no longer stops a pip run without `--user`: the write guard is what keeps that out of the system, and the contract tells the agents the rule and asks them to record what they installed. There is still no root, nothing mounts, and Homebrew and the system package managers stay out — they write outside the sandbox. Under `--isolation microvm` each agent installs into its own VM's disk (`/opt/dfir/agent`), never a shared prefix, and a program a pack requires that the image lacks is a warning instead of a refusal. Under a case policy that permits no direct host (`--policy ctf`, `internal`, `live_adversary`) it is refused without `--no-pypi`: the index would be reached with no grant, no check and no capture. Recorded as `allow_install` in the registry. See [safety.md](safety.md) and [credentials-and-teams.md](credentials-and-teams.md#what-a-run-may-install). |
| `--allow-pack-secrets` | no | off | Hand a pack's stored secrets (`pack.sh install` keeps them in `~/.dfirswarm/secrets/<pack>.env`, never in the pack) to that pack's own tools on the host. A pane can read whatever its extension can, so the agents can read them too; without the flag a pack that requires a secret is refused on the host. Under `--isolation microvm` it is needed too: the value never enters the VM (msb swaps its placeholder in only on the way to the hosts the pack names), but the placeholder is in the whole VM's environment, so any process there, an agent's shell included, can use the operator's account against those hosts. A secret bound to a suffix is refused (msb would send the value to any host under it); `--local-only` withholds every pack secret and opens none of its hosts. Recorded as `pack_secrets`, with what happened to each secret by name. |
| `--no-pypi` | no | off | With `--allow-install`: `pypi.org` and `files.pythonhosted.org` stay off netguard's allowlist. pip is still pointed into `work/.toolchain/` and what comes through is still inventoried, but the network refuses the index, and the contract tells the agents that instead of inviting them to try; on one published run the invitation was what an agent walked around. Recorded as `install_hosts: false`. |
| `--no-read DIR` | no | none | A directory the panes may not read, denied at the kernel; repeatable. Reads are open by design, so this is narrow on purpose: a previous run's findings on the same evidence, above all, so a re-run cannot read the back of the book. Recorded as `no_read` and `no_read_applied` (whether the host could apply it). Without it a host run's panes are already denied every earlier run's sandbox in the registry and the examiners' reviews (`runs/reviews/`), where the guard can mask a directory (seatbelt, a mount namespace; not Landlock alone, which would freeze `runs/` for them): recorded as `earlier_runs_hidden`. |
| `--accept-signer-exposure` | no | off | Host runs. Start although no kernel guard holds the panes (`--no-write-guard`, or a host without one) and a signing key of this install exists: the machine key (current or retired), an enrolled examiner's key file, the custody key, or an ssh-agent that holds an examiner's key. Without it that run is refused, in `--check` too. With it the run records `signer_keys_hidden: false` and what was exposed (`signer_isolation`), and the kickoff says to rotate them afterwards (`swarm.sh machine rotate`; an examiner's new key is a new enrolment). With a guard nothing needs accepting: the panes are denied each home's `machine/` and `examiners/` (made 0700 first), `SWARM_SIGNERS_HOME`, each examiner's key file as its record names it (never read), the custody key, and the ssh-agent (`SSH_AUTH_SOCK` dropped from the panes and its socket denied; launchd's on macOS by its directory); a guard that cannot deny one of them (Landlock alone and an agent's socket, a key inside the run, a signers' home holding what the panes need) refuses the run. Refused under `--isolation microvm`, where no VM mounts any of it (a signers' home inside something every VM mounts is refused there). `--env SSH_AUTH_SOCK=...` is refused. |
| `--cap-per-agent USD` | no | — | A cap per seat on top of `--cap-usd`: an agent over its own cap is steered to post what it has and call `done(reason=agent_cap)`, and a grace period later its own harness stops it. The swarm goes on. Written to `budget.json` as `cap_per_agent_usd`. Only where the team's dollars are charged; on a subscription or local team it is said to brake nothing. |
| `--cap-per-agent-tokens N` | no | — | The same per seat in tokens: the per-agent brake of a team on a subscription or local models. Written to `budget.json` and the registry as `cap_per_agent_tokens`. |
| `--cap-tokens N` | required when nothing on the team bills | 100000000 for a metered team (not under `--stop operator`) | A swarm-wide cap in tokens: Pi's own totals (`input + output + cacheRead + cacheWrite`) summed over every turn of every agent. The brake for a team whose dollars are not charged: local models, which bill nothing, and a subscription, whose dollars are Pi's estimate. Required for such a team; a metered team without it gets 100,000,000 as a second brake, which the kickoff says is the default (a seven-agent case runs to tens of millions, so the default stops a runaway, not a case). Over it, the same steer and grace period as the USD cap. The context is re-sent every turn, so a small goal on two agents is a few million and a seven-agent case runs to tens of millions. Written to `budget.json` as `cap_tokens`, next to `metered`. See [credentials-and-teams.md](credentials-and-teams.md#local-models-ollama-lm-studio-vllm-llamacpp). |
| `--token-alert N[,M…]` | no | — | Token marks you are told of as the run crosses each (`200M,400M,1.6G`: whole numbers, or with `k`, `M` or `G`; repeatable, merged). Each once: a board post (`TOKEN ALERT`), a `token_alert` trace line, the notify hook's `token_alert` (the mark and the count), and the console's Budget tab, which shows every mark and which are crossed. Claimed on disk (`traces/token-alerts/<mark>`), so the hub of a VM run or the watchdog of a host run tells it once, across restarts and resumes. Advisory under every stop policy: nothing pauses or stops for it, and the operator decides. Made for `--stop operator`, where every cap is advisory and says nothing; the Breadcrumbs run spent 790 M tokens that way. Written to `budget.json` and the registry as `token_alerts`; set again while the run goes on with `swarm.sh cap <id> --token-alert` (a resume keeps the run's own). In a host run the idle watchdog is the only teller: while it is down nothing is told, and a mark crossed then is told when it is back (the watchdog is restarted by the kickoff's keeper). A VM run's hub tells them. |
| `--allow-host HOST` | no | — | Add a host to the netguard allowlist for this run (repeatable): the provider hosts plus, say, a symbol server. A bare host means port 443 and nothing else, so anything on another port is named as `host:port` — a bare `127.0.0.1` would open every port on the machine, the console's included. `*.suffix` or `.suffix` allows the names under a domain. Whether it also allows the domain itself (the apex) depends on the mode: netguard does not (`*.example.com` does not allow `example.com` on a host run), msb does (under `--isolation microvm` it does). A suffix lets an agent send data to any host under it, not only the one the case needs: `*.blob.core.windows.net` reaches anyone's storage account there. A suffix of one label (`*.com`) is refused under `--isolation microvm` and by the console; a host run's command line does not check it. Under `--isolation microvm` every entry is checked before anything is written, as the VM's policy will read it: an IPv6 address is `[addr]:port` with a port, a CIDR block (`10.0.0.0/8`, `10.0.0.0/8:8080`) is an address range, a loopback entry (`127.0.0.1:8080`, `[::1]:11434`, `localhost:1234`) is this machine's port reached through msb's host gateway, which the guest calls `host.microsandbox.internal:<port>` (a local model's base URL is rewritten to it; the guest's own `127.0.0.1` is the VM itself), and an entry with a scheme, a path or a wildcard anywhere but in front is refused with the reason. Volatility 3 fetches a Windows kernel's symbols over plain HTTP from Microsoft, which redirects to a numbered blob host: `--allow-host msdl.microsoft.com:80 --allow-host '*.blob.core.windows.net'`. The same syntax holds under `--isolation microvm`. Recorded as `allow_hosts` in the registry. |
| `--case-id ID`, `--examiner NAME` | no | — | Chain of custody: both go into the registry, the contract's title block and the run summary. |
| `--operator ID` | no | — | The run's operator: a person enrolled on this install before the run (`swarm.sh examiner enroll --id ID`, role `examiner` or `analyst`); refused otherwise, before anything is written. Recorded in the registry (`operator`: id, name, role, key fingerprint). On this run's acts (`question`, `resume --question`, `requests`), `--as operator` names them, a claim unless `--sign`. Without it, `--as operator` is whoever is enrolled under the id `operator`, and refused (as before) when nobody is. The Breadcrumbs run's first resume asked its question `--as operator` with nobody enrolled under it, and the register refused it. |
| `--idle-nudge-sec N` | no | 180 | The idle watchdog (`scripts/idle-nudge.sh`, started next to netguard): an agent with no tool call for N seconds and no marker is prompted through Herdr to continue its seat or call done, at most three times, each an `idle_nudge` event on the trace. An agent that has called only `wait` and `inbox` for 600 s (`SWARM_WAIT_IDLE_SEC`) is steered the same way, unless a job of its own is running. One whose last turn ended in a provider error is retried with backoff instead: three times under a cap policy, without end until solved. `0` turns the prompts off; the watchdog still runs the stop policy. |
| `--probe-violation` | no | off | Dev only. Starts one extra agent `<id>pv` (not in `team.json`) without `claim_file`, told to do both: a `write` (which the guard must block) and a shell write (which the harness must detect and announce). |
| `--provider-host P=HOST` | no | — | The host provider `P` is called on, when the harness cannot know it: a gateway, a region, an account (repeatable). The harness knows a provider's host from `models.json` (its `baseUrl`, which Pi takes over its own for a built-in provider too), from its own table, and otherwise from Pi's model list, which names the host of every provider Pi ships (Groq, Mistral, Fireworks, …). Under `--isolation microvm` a provider with no known host is refused before anything is written, with or without `--no-netguard`: its key is bound to its hosts and swapped in nowhere else. Providers that sign each request with their secret on the client (`amazon-bedrock`, `google-vertex`) are refused under microvm, since the secret itself would have to be in the VM. On the host a provider with no known host is a warning. |
| `--no-netguard` / `--open-net` | no | netguard on | Skip the netguard sidecar and PATH shim: open egress. Under `--isolation microvm` each VM may reach every public host, and its credentials still go only to their own hosts; recorded as `netguard_mode: "microvm-open"`, and the report's egress row says OPEN. It is the network mode `open`, and contradicts `--network closed` or `dynamic`. |
| `--network MODE` | no | `closed` | The run's network mode ([ADR 0012](adr/0012-a-dynamic-network-decided-by-rules-and-made-on-the-host.md)). `closed`: the models' hosts, the package index with `--allow-install`, `--allow-host`, and what the operator allows later with `lead note --allow-host` (a socket grant). `dynamic` (microVM runs): an agent asks for one bounded lookup with `net_request`; the hub decides it by rules under the case policy and records the decision; a fetch service on this host (`scripts/net-fetch.ts`, started with the hub and kept by its keeper) makes exactly the granted request and seals the answer as a capture (`store/net/<k>/<n>/`), recorded on the ledger as external material; the agents get `net_request`, `net_fetch` and `network`. Refused with `--isolation host`. `open`: every public host (`--no-netguard`), with the tools too. The goal's metadata block may say `network: MODE`. Recorded in `network/policy.json`, SWARM.md and the registry's `case_policy`. |
| `--policy PRESET` | no | `standard` | The case policy: what the examination permits to leave the run and to reach outside it, whatever the mode. `standard`: hashes and public indicators, to approved passive adapters; active contact (an evidence URL's HEAD) is the operator's. `live_adversary`: stricter; nothing the evidence names is ever contacted, no socket grant. `internal`: nothing leaves (with `--network open` or any lookup it is refused). `ctf`: a published case; no search, no write-up site, only reference or evidence-linked adapters, and every value sent must be found in the evidence the request cites; no socket grant (so no `--allow-host`). The goal's metadata block may say `policy: PRESET`, and `legal:`, `provider_retention:`, `more_evidence:`, `material_use:` as text; a flag overrides the goal's value and the kickoff says so. A combination that contradicts its preset is refused before anything is written, and so is a run whose direct egress does not fit it: under `ctf`, `internal` and `live_adversary` no host is reached without a grant, so `--allow-host`, the package index `--allow-install` would open (add `--no-pypi` to keep the install machinery without it) and a pack's secret hosts (`--allow-pack-secrets`) are each refused, naming where they came from. |
| `--lookups L`, `--contact C`, `--disclosure LIST` | no | the preset's | Override one field of the preset: what the hub grants by itself (`none`, `reference`, `evidence_linked`, `any`), whether what the evidence names may be contacted (`passive`, `active`), and which classes of case data may leave (`hash`, `public_indicator`, `coordinate`, `internal_name`, `personal`, `file_upload`, or `none`). |
| `--more-evidence M` | no | the preset's (`ask`; `ctf`: `no`) | Whether evidence may arrive while the run goes on ([ADR 0014](adr/0014-the-case-contract-says-what-comes-in-and-what-is-asked.md)). `no`: a closed collection or a published case; an agent's acquisition is answered at once, "no additional input under this case policy", a constraint of the case and never a finding that something is absent, and `evidence add` is refused; a not_determinable's coverage says so in `acquisition_none_why` (the policy is the reason no ask was opened), which the `no_acquisition_ask` warning suggests instead of an ask. `ask`: the operator authorises or declines each acquisition. `yes`: further collection is expected; an acquisition is authorised by the policy, and the operator collects it. Also `more_evidence:` in the goal's metadata block. `ctf` with `yes` is refused. |
| `--material-use SPEC` | no | the preset's | What each class of material from outside the original evidence may be used for: `CLASS=USE` pairs (`,` between them), the classes `acquired_evidence`, `case_material`, `operator_supplied`, `external_capture`, the uses `evidence` (a finding may rest on it as on the original evidence), `reference` (it may be cited; what rests on it is flagged) and `none` (kept on the record, never citable: a record citing it is refused). A class left out keeps the preset's use (`acquired_evidence=evidence`, the rest `reference`; `internal`: `external_capture=none`). A capture is never evidence of the events: `external_capture=evidence` is refused. Also `material_use:` in the goal's metadata block. |
| `--legal TEXT`, `--provider-retention TEXT` | no | none | The case's legal text (jurisdiction, warrant or engagement scope, "GDPR or similar laws") and what you know of how the model and lookup providers keep what they are sent: recorded in the policy, SWARM.md and the registry, never inferred. Also `legal:` and `provider_retention:` in the goal's metadata block; at most 2,000 characters each, nothing cut. |
| `--local-only` | no | off | Every model on the team must be served from this machine or this network — a `models.json` `baseUrl` on loopback, a private range, link-local or `.local`, or Pi's built-in `llama.cpp` provider — and the netguard allowlist becomes those endpoints and nothing else (`netguard --only`): the eight cloud hosts of the default list drop out. Panes also get `PI_OFFLINE=1`, so Pi makes no catalog-refresh calls at startup. Refused with a cloud model on the team, with a cloud `--compact-model`, and with `--no-netguard`. Recorded as `net: "local"` in the registry. |
| `--net-allow` | no | — | Alias of the default (kept for older scripts). |
| `--no-start` | no | — | Prepare the sandbox, `SWARM.md`, `team.json`, `budget.json` and the registry entry, but start no Herdr/Pi. Used by the web API test and the UI's "Prepare only". Under `--isolation microvm` it boots no VM of any kind: the host is not probed and the image is not pulled, `--toolbox` and `--catalog` are not run, neither in a VM nor on the host (the kickoff says so), and `vm-spec.json` in the sandbox records what each VM would have been given. The checks that need no VM still run: the providers' hosts, the `--allow-host` entries, the capacity. |
| `--isolation M` | no | `microvm` (`SWARM_ISOLATION`) | `host`: unisolated. Every agent is a Pi process on this machine, held by the host guards (the write guard, the tool guard, netguard) with no VM around it; a host guard's flag (`--no-write-guard`, `--no-seal-herdr`, `--inputs-enforce`, `--key-from-env`, `--probe-violation`) needs it named, and is refused under the default with that hint. `microvm` (the default): every agent runs Pi inside its own microVM (microsandbox; macOS on Apple silicon, Linux with KVM), created at kickoff and put away by `stop`. The run is mounted read-only in each VM except the agent's own `work/<id>/`, `work/extracted/<id>/` and `work/quarantine/<id>/` (no-exec), its own `tool-output/<id>/` and its own Pi session; a shared deliverable under `work/` is written through `publish_file`, claimed and recorded for the agent; `--allow-install` installs into the VM's own disk; `--inputs DIR` is used in place and mounted read-only (no copy, no pristine clone), and a link in it that leads out of it is refused at kickoff, since no VM could follow it; the board is written by one process on the host, `scripts/vm-hub.ts`, which each VM reaches over its own vsock port and which decides who is asking by the port; a VM reaches only its models' hosts, `--allow-host` and, with `--allow-install`, the package index (every public host under `--no-netguard`); no provider credential enters a VM (Pi on the host resolves it and msb swaps it in on the way out). The host guards (fsguard, netguard, the trace gate, the nudge broker) are not started: the VM is the guard. Refused before anything is written on a host that cannot boot a VM (except with `--no-start`, which boots nothing, so there is no probe), with what it lacks, how to fix it (the image's build commands, KVM) and `--isolation host` as the unisolated way on; the kickoff never falls back to host processes on its own. A registry record from before the default changed carries no isolation and is shown as a host run. See [ADR 0009](adr/0009-agents-live-in-microvms.md). |
| `--image REF` | no | from the packs | The VM image (`SWARM_VM_IMAGE`). Default: the smallest profile that holds the run's packs or covers every program they require and every Python package they import (`images/recipe.py profile-for`), by the digest a lock pins (`SWARM_IMAGES_LOCK`, else `images/images.lock.json`), else the local build `dfirswarm-<profile>:dev-<arch>` ([images/README.md](../images/README.md)). In a microVM run with jobs and packs that default is the job image that holds every pack, and the agents boot the base (see `--brains-with-packs`); an image named here is the one the agents and their jobs boot. The digest a VM booted is in `vm/<id>.json`. |
| `--vm-cpus N`, `--vm-memory MIB`, `--vm-disk MIB` | no | 2, 2048 (1024 on a host with less than 8 GiB), 8192 | Per agent VM. N VMs that would take more than 85% of this host's memory, or four times its cores, are refused before anything is written; past 60% or past its cores, warned about. The disk is where a VM's own installs and its `/tmp` live. With `--playwright` and no packs the image is the `web` profile (the base with Chromium); each VM's `TMPDIR` is its own `/tmp`. The host guards' flags (`--no-write-guard`, `--no-seal-herdr`, `--inputs-enforce`, `--key-from-env`) are refused under microvm, and so is a `--no-read` path the VMs are given (the harness, the packs, the evidence, the run). |
| `--workers N` | no | 2 (4 on a host with 64 GiB or more, 6 with 128 GiB or more) | Tool-job worker VMs that may run at once (1–16). From 3, one is kept for short jobs (an agent's `timeout_seconds` of 120 or less, stopped at that limit), so a quick look never waits behind long parses; the kickoff's recipes and the derived catalogue never take it. Each worker starts only while the host keeps 15% of its memory free beside it (several runs may share a host); until then its job waits, said on the journal (`job_waits_for_host`) and on its `job_started` line. Each job — an agent's `job_run` or `catalog_request`, the kickoff's recipes — runs in a throwaway VM of the run's image, made for it and removed after, seeing what its `inputs` declare (`input:<path>`, `input:<dir>/`, `job:<id>[/<path>]`, `member:<gen>#<n>`, `sha256:<hex>`, `work/<you>/<path>`, `tool-output/<you>/<path>`; `[]` for nothing) and nothing else, read-only, in a view the hub builds for that job outside every VM (an evidence set bound whole when the scope covers every file of it, a part of one cloned file by file, never hard-linked; a segment set whole, as the census recorded it; an agent's file copied and hashed at the job's start; a declaration that does not resolve refuses the job), or, with `inputs` left out or `["all"]`, what an agent sees (the evidence, `store/`, `catalog/`, `tools/`, `tool-output/`, the packs, all of `work/`), the record saying which, with the declared scope's manifest at `store/jobs/<id>/scope.<attempt>.json`; no network unless the job asks for the run's `--allow-host` list (plus PyPI with `--allow-install`), and only its own directory (`$OUT`) writable (it starts in the run's directory, read-only there, so a program that writes its log or temp files where it stands is given a path under `$OUT` or run after `cd "$OUT"`; a job that ends non-zero on such a write, a `Read-only file system` or a `Permission denied` outside `$OUT` in its stdout, its stderr or a stderr file it kept, says so in its reason, with the path, where the line is, and `$OUT`); what it wrote is sealed into `store/jobs/<id>/` (read-only, hashed, every file stored once under `store/blobs/`) and every step is a line of the hash-chained `store/journal.jsonl`, whose head is anchored beside the run (`<sandbox>.journal-anchor.json`). Counted with the seats against the host's capacity: unset, as many as fit beside the seats up to that default, and none fitting leaves the run without a job service (the kickoff says so); given, kept or refused. |
| `--worker-cpus N` / `--worker-memory MIB` | no | 2 / 2048 | Each worker VM's size. |
| `--no-jobs` | no | off | No job service: no tool jobs, and the kickoff's catalogue is built before the agents start, as in a host run. A host run (`--isolation host`) has none. |
| `--derived-limit N` | no | 50 (`SWARM_DERIVED_LIMIT`) | The derived catalogue's ceiling of generations a run, 1 to 999999; recorded as `isolation.jobs.derived_limit` and said at kickoff with where it came from. The ceiling is checked before each pass, so a pass in flight finishes past it (the Breadcrumbs run made 52 against 50): at the ceiling, what waits stays offered and named (`derived_bounded`) and `catalog_request` still catalogues any object. Refused with `--no-derived-catalog` or without a job service. |
| `--no-derived-catalog` | no | on | Turn off the derived catalogue. By default what jobs make is offered to the packs' recipes whose trigger is `derived`, by content (sha256: an object is answered once in a run, wherever it appears; a copy of an input is skipped): a file is offered when a recipe's `min_bytes` and, if it names any, its `suffixes` or `magic` say so, and only to those recipes. The work runs in the lowest lane — one worker, started only when no agent job waits — the largest objects first, 32 object–recipe pairs a pass, within 300 worker-seconds each 10 minutes; a run makes at most 50 derived generations (`--derived-limit N`) and 2 GiB of them (what the catalogue costs, not what it asks about). Nothing is dropped: what waits is named in the journal (`derived_offered`), a pass's answers are read whatever its status (`detect_answered`), a pair not answered is tried once more then named (`detect_unanswered`), and a limit is journalled (`derived_deferred`, `derived_bounded`, told to all). A complete derived generation is posted to all; a partial one to the agent whose job made the object, with the recipe's reasons, and it is linked to its readable form when one is catalogued (`generation_related`). Imports and the files of failed jobs are offered too; a recipe's or a detect pass's own outputs never are. |
| `--no-vm-snapshot` | no | disks kept | At stop, remove each VM without keeping its disk. By default each disk is kept beside the run (`<sandbox>.vm-snapshots/<id>.msb`) with msb's integrity record, and its sha256 is in `vm/<id>.json`. Below 4 GiB free there (`SWARM_SNAPSHOT_MIN_FREE_BYTES`) a VM is kept, stopped, neither snapshotted nor removed, and the stop says so: free space and stop again. |
| `--vm-snapshot-dir DIR` | no | beside the run | Keep the VMs' disks in `DIR` instead; `<sandbox>.vm-snapshots` becomes a link to it, so stop, custody, the package and reap find them where they always look. For a volume with room, or one outside a synced folder: a kickoff whose run is inside Dropbox, iCloud Drive or another `~/Library/CloudStorage` folder warns that what the agents derive, and each kept disk, will be uploaded. |
| `--allow-oauth-in-vm` | no | off | Let a subscription (OAuth) provider into the VMs. Refused otherwise under `--isolation microvm`: a subscription token is the operator's account at the provider, and the VM that holds its placeholder could use it beyond inference (an Anthropic token can create API keys; a Codex token is the ChatGPT account). An API key needs no flag, but it is not limited to inference either: its placeholder reaches every endpoint on the provider's host, so the VM can do there whatever that key may do (files, batches, fine-tuning, where the provider allows them). The refresh endpoint is never bound either way, since the guest never refreshes. Recorded as `isolation.oauth_allowed`. |
| `--inputs-copy` | no | off | Under `--isolation microvm`, copy `--inputs` into the run, read-only, instead of mounting the directory in place: a second layer for evidence the examiner's own account can write, and the way to bring in files the directory only links to. The manifest records `held: copy`. **Start a live run with it** (or with evidence nothing on the host can write): evidence this account can write (a file, or a directory whose names can change, on a volume mounted read-write) is refused in place, a BLOCKER under every stop policy and at `start --check`, naming both ways out: `--inputs-copy`, or `chmod -R a-w DIR` / a read-only mount first. It was a warning until the Breadcrumbs run, where a helper of the operator's own wrote a file into the live run's evidence folder and the seats spent an hour telling an added name from a changed object. A resume is held to the same check: a run started before it with writable evidence in place resumes once the evidence is made read-only (`chmod -R a-w`), since its kept options cannot gain `--inputs-copy` (only `resume <id> -- <every start option>` replaces them). The check reads the permission bits as they apply to this account (owner, group, other) and the set's mount flag; it reads no ACL (`ls -le` on macOS, `getfacl` on Linux) and no volume mounted inside the set, which `--inputs-copy` holds against too. In each VM the copy is held exactly like evidence in place: `inputs/` and `.inputs-pristine/` are each their own read-only, no-exec mount over the run's floor (on the floor's share alone, read-only but not no-exec, every seat's probe refused its VM), and a VM whose probe finds either writable or executable is refused. |

What `start` does, in order, for a host run (`--isolation host`): read and validate the goal document (no definition of done, no swarm) → allocate id → resolve the sandbox path and reset per-run files, including `work/` → render `SWARM.md` → write `team.json` + `budget.json` → copy `prompts/worker-system.md` to `<sandbox>/.pi/SYSTEM.md` (and write what holds for the whole run to the two files Pi appends to its own prompt sections, which every run of a seat keeps, the runs a hand-off starts included: `<sandbox>/.pi/APPEND_SYSTEM.md` for the run (the packs' skill index, the self-compaction mechanics, the read-only inputs rule, the forging rule; empty when none applies, and then not passed, so the prompt does not start with blank lines) and `<sandbox>/.pi/seat-<id>.md` for each seat (its id and the stop rule)) → registry `prepared` → check `herdr`, `pi`, `jq` → check the credential store → start netguard sidecar + shim → `herdr workspace create --cwd <sandbox>` → pane grid (`√N` columns, max 5; new tab at `SWARM_PANES_PER_TAB`, default 30; new workspace if tab create fails) → `herdr agent start <id> --kind pi --pane <p> -- --approve --no-skills --name <id> --append-system-prompt <sandbox>/.pi/APPEND_SYSTEM.md --append-system-prompt <sandbox>/.pi/seat-<id>.md --session-dir <sandbox>/.pi-sessions/<id> -e extensions/agent-swarm.ts --tools read,bash,edit,write,post,inbox,wait,claim_file,release_file,claims,list_team,budget,file_history,file_restore,file_diff,thread_open,thread_join,inputs,name,record,ledger,attest,dispute,done --model <model>` for each agent (with `--allow-tool-forging` the list travels in `SWARM_TOOLS` instead, so `make_tool`, `tools` and every forged tool can join it) → `herdr agent prompt <id> "Join swarm <id>. …"` → write `layout.json` → registry `running`.

In a microVM run (the default) the order differs: before anything is written the host is probed and the image pulled when it is missing (`scripts/vm.ts probe`, `pull`); `--toolbox` and then `--catalog` run in a throwaway VM of the run's image rather than on the host (in the catalog's VM only `catalog/` is writable; the rest of the run is read-only there, the evidence read-only and no-exec, and it has no network but the run's `--allow-host` entries, which is how Volatility reaches a symbol server, or every public host under `--no-netguard`; `scripts/vm.ts catalog`), the collector and then the hub start, the VMs are created in parallel and each one's own probe must say the floor is read-only, its holes writable, the evidence read-only, the hub reachable and Pi running (`vm/<id>.json`), or the kickoff stops; then the pane grid, and in each pane `msb exec -t dfs-<run>-<id> -- /.msb/scripts/dfirswarm-pi <the same Pi arguments>`, which bridges the hub link and starts Pi with the kickoff as its first message. The idle watchdog asks the hub, not Herdr, who is working, and prompts through it.

What `--no-skills` keeps out of a seat's prompt, and what it does not. Every place the kickoff starts a seat's Pi passes it, and Pi's own skill directories stay out: `~/.pi/agent/skills`, `~/.agents/skills`, a project's `.pi/skills` and the `skills` setting (Pi 0.87.1, `dist/core/resource-loader.js`; tested through the real CLI in `tests/skills-e2e.test.ts`). Still in, because the flag does not reach them (an operator's own `~/.pi/agent/APPEND_SYSTEM.md` is not among them: the seats are started with `--append-system-prompt` for the kickoff's two files, which replaces Pi's discovery of that file): a skill path an operator's own extension adds through `resources_discover` (Pi re-reads skills for an extension's paths and skips `noSkills`); the operator's and the ancestor directories' `AGENTS.md` (context files); the operator's other global extensions, which load in every host seat. `--no-extensions` is not an option for the kickoff to add: Herdr's own integration (`~/.pi/agent/extensions/herdr-agent-state.ts`) is a global extension, and without it Herdr loses the agent's state. A microVM seat does not mount the operator's home (it has the VM's own), so the directories above should not exist there; **UNKNOWN**: not checked against a booted VM.

Per-pane environment (a host run; a microVM run's pane gets only a quiet shell, and its VM's environment is built by `scripts/vm.ts` from the spec): `AGENT_ID`, `SWARM_ID`, `SWARM_HARD_KILL`, `PATH=<sandbox>/bin:$PATH`, `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY=http://127.0.0.1:<port>` (the swarm's own sidecar port, recorded in `<sandbox>/netguard.port`), `NODE_USE_ENV_PROXY=1`, empty `NO_PROXY`, and `BROWSER_CHECK_EXECUTABLE` if Google Chrome is found at `/usr/local/bin` or `/usr/bin`. No provider key, unless `--key-from-env` was passed.

#### `list`, `status`, `stop`

- `list` prints `ID STATE LABEL HELD WS N MODEL SANDBOX` from `runs/registry.json`; `HELD` is how the agents were held (`host` or `microvm`). Run ids are `s` and six hex digits; a VM run does not draw an id another registry's VMs on this machine carry.
- `status <id>` prints the registry record, then `watch.sh --once`, which for a microVM run lists each agent's state from the run's own hub (working, idle, done, gone; linked or not). Looking at a swarm does not reap anyone.
- A kickoff that does not reach its end once the run is in the registry — a BLOCKER, a pane that did not open, `^C` — puts away what it started (its VMs, its daemons, its Herdr workspaces) and records the run as `failed`, which the console shows as such. The registry is written under a lock shared with a VM run's hub. A sandbox a running run still uses, or one whose VMs are still up, is refused as `--sandbox`. For the wall clock and half an hour more the host is asked not to sleep, since a sleep pauses the agents while the wall clock runs: `caffeinate -i -s` on macOS, `systemd-inhibit --what=sleep:idle` on Linux (which polkit refuses to a user with no login session, such as one reached through `sudo -u`; the kickoff then warns instead of claiming it). Neither holds against a closed laptop lid, and on macOS `-s` holds only on mains power: keep the lid open and the machine plugged in for a run. A microVM run's harness (extensions, scripts, prompts) is a copy taken at kickoff and mounted where the checkout is, so editing or updating the checkout mid-run does not reach its agents; the kickoff prints which commit it froze and where each agent's relaunch script is. The hub of a VM run, the VM finish it starts and the custody it takes run from a second copy taken at the same time. The keeper, the stop the hub runs itself, the idle watchdog and the model gateway run from that copy as well. The operator's own commands (`swarm.sh`, an operator's `stop` and its custody, `await-done.sh`) and every host run run from the checkout, so an update mid-run reaches them, and a host-run pane that is relaunched loads the new code.
- `stop <id>` says which step it is in, and interrupted it says where it was: running it again finishes the job, since every step is safe to repeat. Before closing any Herdr workspace it holds the hub's jobs (`.stop`). If a VM or its hub remains up, the command records `stop_incomplete` and exits 3 before stopping the daemons, gathering spilled traces, writing the stopped outcome, taking custody, sealing a release or detaching evidence. The collector and evidence stay available to the remaining writers; a later successful stop performs those steps. A missing or stale `hub.pid` is checked against the run's process command line; a failed process lookup defers finalisation. A fatal error sealing the remaining staging also defers finalisation and leaves that staging available for a retry. It closes every Herdr workspace recorded for the swarm, kills the netguard sidecar (`<sandbox>/netguard.pid`) and the idle watchdog (`<sandbox>/idle-nudge.pid`), each only when the process the pid file names is that daemon for that run (after a reboot a pid can name anything), and sets state `done` when `done/SWARM_DONE` exists, `stopped` otherwise; when a VM of the run is still up after it, the state is `stop_incomplete`, the stop says `NOT STOPPED` and exits 3, and running it again (or `reap <id>`) finishes the job. It does **not** write `SWARM_DONE` and does not delete the sandbox. A microVM run's VMs are stopped first, each disk kept as a snapshot unless the run said `--no-vm-snapshot`, then the hub. From the moment the stop begins (it writes `.stop` in the hub's directory first) the hub's job service starts no worker and accepts no job; what waits in its queue is cancelled on the record when the hub goes, and a stop interrupted after that point leaves the service holding until the next stop. A hub that is putting the VMs away itself is let finish first (`SWARM_STOP_HUB_WAIT_SEC`, default 1800). The stop then asks the hub to go and waits for it (`SWARM_STOP_HUB_EXIT_SEC`, default 180, whole seconds; anything else is the default), so its job service cancels what waits, removes each worker it runs and seals that job's staging; only then are the run's VMs counted. A hub still up after that keeps its pid file and its directory, the run is `stop_incomplete`, and nothing is sealed beside it: the next stop finds the hub, waits for it and seals after it. A job's worker still listed once the hub has gone is removed by a second finish, and the list is asked again for up to `SWARM_STOP_JOB_VM_WAIT_SEC` (default 60, whole seconds) before anything is called left up. A job whose worker msb could not confirm gone when the hub stopped is never read while it may be up: the job service asks again (three times, two seconds apart), and one still unconfirmed is named on the journal (`job_unsealed`, its staging directory and why); with the hub gone the stop seals it once msb says its worker is gone (`vm.ts seal-left`, which refuses while a hub of the run is up, found by its pid file or by its command line: `job_fenced` with `by: "stop"`, then its commit, its partial output and logs kept as any job's) or says which staging directory it left and why, and custody names each one left with that why. On the Breadcrumbs run a worker started while the seats were put away was counted while the hub was removing it: the stop said `stop_incomplete`, and that job's staging was left unsealed. Once the run's daemons are down the stop chains the harness's own trace lines the collector could not take (`traces/system-spill.jsonl`, `traces/hub-spill.jsonl`: an operator's command after the collector stopped, the hub's last words, this stop's own line when the collector had gone before it) with the collector's own code (`trace-collector.mjs --gather`): each written unverified and marked `gathered` with its spill and its own sha256, the spilled lines kept whole in `traces/<name>.gathered.jsonl` (each once; a package carries them as `trace/spill-<name>.gathered.jsonl`), a line that is not an event, or one that names a seat (a seat's word, never the harness's), left in the spill, where custody counts it; custody counts the gathered lines and holds a gathered operator line to the operator's audit by the time the command ran. Run again, nothing is chained twice. msb keeps a live VM's configuration, its secrets' values included, in its own database on the host (`~/.microsandbox/db`); once VMs are removed the stop rewrites that database without their leftover bytes, which needs `sqlite3` on the host, and warns when it could not. Every successful stop then takes custody on the host (`scripts/custody.ts` → `custody.json`; `--no-custody` skips it, `--custody-timeout SEC` bounds it, else `SWARM_CUSTODY_TIMEOUT`, else the run's own `--custody-timeout`, else 14400): the evidence re-hashed in full, which reads every evidence file once more (a custody that runs out of time says which files it did not re-read), with sha1 and md5 compared too when the manifest has them, every session file's sha256, every kept output the trace names checked against its hash, every kept VM disk checked against its record; the one-line verdict is printed and goes into the report. Custody first sets the previous verdict aside (`custody.<its time>.json`, or `custody.previous-<stamp>.json`), with the index of `work/` it sealed (`artifacts.<its time>.json`, so the hash the anchor names for it stays checkable; a package carries both under `custody-history/`), and writes each of its files fresh and renamed into place, never through a link; one ended by its deadline, a signal or an error writes what it found and names what it never reached (`not_reached`), so `custody.json` is this custody's verdict or none. Its sha256 goes into the anchor outside the run, and the report, the summary and the console say whether the `custody.json` they read matches it. Every part of the verdict has a status in `checks` — passed, failed, incomplete, not applicable or unavailable, with why and how much it covered — so a part that raised or was not reached never reads as nothing wrong; the summary ends with them. The verdict seals what it read (`seal`: the trace's lines, bytes and last line's hash, the ledger's and the attestations' heads, the store journal's and the gateway log's), so a later check knows which lines came after it (the hub's own `custody` and `hub_clear_up` lines and the operator's `stop` are the run's closing lines). It holds the operator's audit (`runs/operator-audit.jsonl`) to its own chain and each operator line on the trace to a line of it, compares the acquisition hashes given at kickoff, verifies each job's logs against the hashes its commit sealed and each catalogue generation against its journal line and its job's sealed output, counts the findings that rest on a failed job's kept output, the standing contradictions, limitations and sensitive entries, records how long each part took and the evidence read rate, and the models the agents were given (and the ids the gateway saw answer, when there was one). It says "evidence unchanged since the run began", and "matches the acquisition hashes given" only when they were. Custody exits 0 when every check passed or did not apply, 4 when it finished and one did not (the hub records that as a verdict with adverse checks, not a failure), 3 when it was incomplete. The index it writes of `work/` (`artifacts.json`, every file with its sha256) is the sealed one: its sha256 is in the verdict (`artifacts.index_sha256`) and the anchor (`artifacts_sha256`), `custody-verify` holds every work file to it, and a package carries it as `artifacts.sealed.json`. With the registry's `custody_seal` (or `--sign-key`, `--timestamp-url`, `--timestamp-ca`, `--time-reference` on `scripts/custody.ts`), the verdict is signed and timestamped, the token held to the authority's CA when one is named, and a reference clock's offset recorded. The anchors are files of the operator's own account: they hold the agents to account; the signature and the trusted timestamp hold the verdict itself. Once custody is taken the stop seals the report's first release, the machine's draft (`release/v0/`, see `releases` below): once per verdict, never holding the stop up, and said when it could not be written.
- The hub stops a microVM run's VMs itself once the sentinel has stood for the grace period (or every agent is done). It keeps the wall clock on its own clock; the caps it applies to the spend each seat reports about itself, which the host does not measure, except under `--model-gateway`, where a fronted seat's spend is the gateway's measure (`metered_by: "model-gateway"` in `budget.json`) and a seat's own report can only raise it. When it has put the VMs away it records the run as `finished`, or `finish_failed` when a VM could not be put away (the console shows the latter as its own phase), takes custody and seals the machine's draft release (the stop it runs after finds it and writes nothing). What is left of the run (the collector, the Herdr workspace, the keep-awake, an attached evidence image, the hub itself) is cleared by a `stop` the hub runs itself once it is done (`stop <id> --after-hub`: no custody, it was just taken, and the run keeps the state the hub gave it); an operator's `stop` after that finds no VM left to stop and says so, and one while the hub is still putting the VMs away waits for it. A keeper (`scripts/hub-supervise.sh`) brings a hub that died back with its saved tokens and stop clock, for the length of the run, and the hub refuses to run twice for one run; the idle watchdog restarts one only when the keeper is gone. The keeper also brings back the run's trace collector, which in a microVM run is the trace's only door, and gives up after twenty crashes in a row (`SWARM_HUB_MAX_RESTARTS`), saying so in `traces/vm-hub.log`. The hub and the VM finish it starts run from a copy of the harness frozen at kickoff, like the VMs, with its own copy of msb.
- Each seat's socket on the hub serves only that seat's VM: the kickoff makes a token per seat (32 hex characters), gives it to that VM as `SWARM_SEAT_TOKEN` and to the hub, and every connection must open with it or is refused and named on the trace (`hub_call` with `fn: "seat_auth"`). The tokens rest in the hub directory (`seat-tokens.json` and the hub's saved input, both 0600), in each VM's environment, and in msb's database while the VM lives; they are never in the trace, the registry, a VM record or a package, and they go with the hub directory. A seat's file history on the hub is bounded (1 GiB by default, `SWARM_HISTORY_QUOTA_MB`): past it a revision is recorded by its hash only, and the seat is told once that `file_restore` and `file_diff` cannot use it.
- The hubs live in `~/.dfirswarm/hubs` (`SWARM_HUBS_DIR` moves it; under `DFIRSWARM_HOME` when that is set): one directory per run, in a parent that must be the user's own, not a link, and is kept 0700. A Unix socket path may be 103 bytes, and the kickoff refuses a run whose longest agent socket would be longer, naming the path; set `SWARM_HUBS_DIR` to a shorter directory of your own.
- After a reboot or a crash, run `swarm.sh stop <id>`: a run recorded as `running` with none of its processes alive (no hub, collector, watchdog or VM) is said to have ended that way, with the trace's last time, and the stop then puts it away as usual, the hub's unsent lines (`hub-spill.jsonl`) copied into `traces/`. Nothing restarts a run by itself.
- A host run has a stop from outside the panes too: past a cap or the wall clock the idle watchdog claims the stop clock and says so on the board when no pane has, and past the grace period writes the sentinel as the harness.

#### `summary`, `package`

- `cap <id> [--usd N] [--tokens N] [--per-agent-usd N] [--per-agent-tokens N] [--wall-clock MIN]` changes a running swarm's caps. The change is made under the lock every fold of usage takes, kept in `budget.json` as `cap_changes` (with the caps it left, so the shell watch does not report it as an agent's write), put on the trace as the operator's, merged into the run record and said on the board; a swarm-wide stop the run is no longer over is withdrawn, and a seat's own cap steer lifts by itself on its next check. The run keeps its brake (a dollar cap above zero where dollars are charged, a token cap where they are not), and a finished run is not brought back. `--token-alert N[,M…]` (or `none`) sets the run's token marks again, alone or beside a cap: advisory, kept in `budget.json` as `token_alerts` with the change in `token_alert_changes`, said on the board and in the run record; a mark the run has crossed already is told once, at the next round.
- `say <id> "<message>"` posts to a running swarm's board as the examiner: what an operator notices, or a tool that has just appeared on the host. Agents see it on their next `inbox` or `wait`.
- `tools <id>` lists the tools a run forged, with author, version and runtime; `tools <id> --save DIR` copies them into a library for `--tools-from`. `tools <id> --candidates` ranks the code the agents wrote into command jobs as candidates for the library ([below](#the-report-the-outputs-and-the-code-left-behind)).
- `summary <id>` prints a Markdown run summary from the sandbox's files (`scripts/summary.ts`): outcome and markers, the team with what each agent called itself and its spend, by agent and by model, activity counts from the trace (tool calls, implicit claims, violations, forge hints, nudges, per-agent cap events, forged tools, the commands typed most), the ledger, the work files, and the chain of custody (case id, examiner, input hashes, the inputs checks, the toolbox, the catalog).
- `context <id>` prints the context history of every agent from the trace (`scripts/context-audit.ts`; `--json` for the same as data): per agent the model, the ceiling and the three lines it ran under, the turns, the peak, the lines it crossed, the holds, the hand-offs and Pi's own fallbacks with what each summary cost and which model wrote it, the largest climb in one turn, how many tool calls had more output than the model received (whole under `tool-output/`) and how many `inbox`/`wait` deliveries held posts back; then one sentence per thing the record says about the lines (a provider refusal, a hold at the compact line, a seat that handed off early, a run that never reached a line). A run with no `context` rows says it is not measured rather than guessing. The same record the console's Context chart draws.
- `metrics <id> [--json]` prints the run's process metrics from its own registers (`scripts/metrics.ts`), and `metrics --compare <id-A> <id-B> [--json]` sets two runs of one goal side by side, question by question. Read only. Each metric's definition is under [Metrics](#metrics-swarmsh-metrics-scriptsmetricsts).
- `report <id>` writes `<sandbox>/package/report.html`: one self-contained document — cover (which says an AI agent swarm prepared it and that its findings are the agents' conclusions until an examiner reviews them), summary of findings, scope and evidence with a sha256 per file (and sha1 and md5 when the kickoff took them, with how the copy was checked against its source: by content, with the counts, or by names, kinds and sizes under `--no-verify-copy`), the timeline, indicators and findings as numbered exhibits taken from the ledger's own `seq`, the method, the artifacts with their hashes, the limitations (the tools the agents forged, not independently validated, among them), the chain of custody (whether `custody.json` matches the verdict anchored outside the run, operator actions on the trace, and any removed VM whose secrets msb's database may still hold), a reproducibility row from the run's `provenance` and `host_clock`, the examiner's review (each exhibit's standing, the counts, whether the review's chain verifies and whether the sign-off covers the ledger's current head), coverage and grounding (a "Named by" column, the evidence no command named, exhibits not grounded in the trace), corrections and absences marked, rows for disk encryption, a legal hold or a purge, a notify hook (never its command), a synced folder allowed by flag or marker, an earlier run's ledger handed in as hypotheses and a root start, the source of the spend figure (with `--model-gateway`, which providers were metered on the host), the files handed over with the report, and the swarm's own `work/report.md` reproduced verbatim. Its first section is one screen of every question, and its second follows each question from who asked it to what it cost; Appendix F holds the whole question and lead registers ([below](#the-report-the-outputs-and-the-code-left-behind)). It fetches no stylesheet, script, font or image, so it reads the same on a machine with no network. `--pdf` prints it through Chrome, Chromium or Edge if one is installed (`SWARM_CHROME` names another); the browser numbers the pages, because `@page` margin boxes are unimplemented there and a number this document computed itself would be wrong in every other engine. `--lint` warns when a numbered section cites nothing checkable — a code span, an exhibit number, an inode, a record id or a registry key — and never fails. `--out PATH` writes somewhere else.
- `package <id>` writes `<sandbox>/package/` (and says first, as a WARN, when a job's staging is left unsealed or the harness's trace lines are outside the chain: `stop <id>` again seals and chains them): `report.html`, `summary.md`, `artifacts.json` (every file under `work/` with its sha256, including the extracted material the package deliberately leaves behind), everything the run wrote under `work/` whatever its extension, the run's `tools/` with their manifests, the ledger (`ledger.md`, `ledger.jsonl`), `inputs.json`, `toolbox.json`, `team.json`, `budget.json`, `layout.json`, `netguard.allow`, `SWARM.md`, the catalog index, the trace, one file per board thread, and `MANIFEST.txt` with a sha256 per file, `court-set.json` and this run's lines of `runs/operator-audit.jsonl`; with `--model-gateway`, the gateway's log. `--sign` signs the manifest (see "After a run" below). One walk of `work/` produces the report, the summary and `artifacts.json` together, so the hashes on the report's artifact table are the hashes in `artifacts.json`. What you hand over, with the hashes to prove it is what the swarm produced. `work/extracted/` and `work/quarantine/` stay in the sandbox — they came out of the evidence and may be live — and the command says how many files it left behind. `--redact` takes out what a sensitive ledger entry says and the files it cites before the manifest is made. A sensitive entry's words are every text field of it, whole when six characters or more (four with a digit in them, a PIN), and each identifier-like run inside one (a key, a token, an address, a path, an account). A word under eight characters (a PIN) counts wherever it stands, a letter touching it included (`PIN4821`), except inside a longer run that makes it something else: its digits running on into a bigger number (`12.482145Z`), a run of sixteen hex characters or more with digits of its own (a sha256, a keyed id), or a run of twenty base64 or base64url characters or more with letters and digits of its own and few separators (an encoded blob; a path is not one). The redaction and the scan below hold to that one rule, in text, bytes and file names. A redacted line of the trace, the ledger, its attestations and disputes, the store journal or the review keeps its own sha256 (a ledger entry its seq, kind, prev and hash; an attestation or a dispute of a sensitive entry its act, target, prev and hash; a journal line its seq and prev), so every chain still walks; a JSON file is redacted field by field and keeps its shape; other text files have the words replaced; a PDF a release printed is withheld; a release's signed record, a signature and a token are left as they are. `REDACTIONS.txt` lists each change, and `REDACTIONS.json` what each replaced. Sensitive content the package withholds or matches is named by a **keyed id** (`hidden-<hex>`, an HMAC under a per-package key), never by an unsalted sha256, so a low-entropy value (a PIN, a dictionary word) cannot be brute-forced from the record; the key and each id's real digest, path and word are written to a **private sidecar** (`<dir>.private.json`, mode 0600) beside the package, outside the hand-over, which the owner keeps to match the original. Then every packaged file is scanned — including the generated records and the filenames — for each sensitive entry's words, normalised (case, path separators, JSON escapes) in text and as UTF-8 and UTF-16 bytes in any file, for each sensitive output's digest, and for a filename that holds a sensitive word: a hit refuses the package, naming the file and a keyed commitment, never the word; `--redact-leaks list` hands it over with the hits listed in `REDACTIONS.json`, and `verify` says them. A short word is judged where its context (64 characters each side) is whole: the windows overlap so that every occurrence has one where it is. The scan reads each file once per form, in 8 MiB windows, whatever the number of words and digests it looks for (`scripts/multi-match.ts`): it used to search for each on its own, and a 4.2 GB package with some 2,700 sensitive words, 1,600 sensitive digests and a 1.37 GB job log was still being scanned after two hours; it now takes under a minute and a half. A sensitive output (a job run with `secret_output`, or one made from such an output) is withheld whole under `--redact` wherever its bytes sit in the package, not only its canonical store path, with its job's stdout and stderr: each file is replaced by a line naming its keyed id and why, listed under "Withheld whole" in `REDACTIONS.txt` and in `REDACTIONS.json` (`withheld`, `sensitive_outputs`); an entry citing a sensitive output is redacted as a sensitive one whether or not it was recorded so; and the scan looks for the whole text of each small sensitive output as well (at most 256 bytes, one line, shaped like a secret rather than a status word), which the redaction takes out where it stands. A package made without `--redact` takes nothing out: when the run has sensitive entries or outputs it writes `HYGIENE.json`, naming them (with the same keyed ids and sidecar), how many sensitive files it carries and what the same scan found, and says to hand it over with `--redact`. `--with-outputs` includes the jobs' sealed outputs, which a record-only package names by their hashes; `PACKAGE-KIND.txt` says which it is. A package carries the ledger's attestations, disputes (`ledger-disputes.jsonl`) and store sweeps (`ledger-sweeps.jsonl`), the finish register (`finish.jsonl`), the network's two chains (`network/grants.jsonl`, `network/fetches.jsonl`) and the model gateway's log (`trace/model-gateway.jsonl`), each a declared component `verify` walks against the verdict's seal, every release of the report as it was sealed (`release/`, never rendered again), and the verdict's signature and timestamp token; `artifacts.sealed.json`, the index of `work/` custody wrote at stop byte for byte (the package's `artifacts.json` is generated when it is packaged); `review.jsonl`, the examiner's review; and `COMPONENTS.json`, which lists each part a recipient holds the record to (the verdict, its anchor, signature and token, the sealed index, the trace and its anchor, the ledger, its attestations, the journal and its anchor, the review) as present or absent with why. All three are under `MANIFEST.txt`.

#### After a run: `examiner`, `machine`, `review`, `releases`, `timestamp`, `rerun`, `package --sign`, `verify`, `certify`, `export`, `hold`, `release`, `purge`

Each of these but `certify` (which only reads) goes on the operator's record (`runs/operator-audit.jsonl`: who, from which host, the command, chained line to line). On a live run, `review`, `export`, `hold` and `release` also go on the trace as `operator_action`. `swarm.sh help <command>` prints each one's page.

- `examiner enroll --name NAME --organisation ORG --competence TEXT [--role examiner|reviewer|analyst|observer] (KEY) [--id ID] [--principal P] [--tsa-url URL --tsa-ca FILE]` enrols a person on this install, outside every run (`$DFIRSWARM_HOME/examiners/<id>.json`, 0600, in a 0700 directory; `SWARM_SIGNERS_HOME` keeps the signers apart from the packs): a name, the organisation they sign for, a competence statement, and a role. An examiner (`--role examiner`, the default) adopts a report and signs its release; a technical reviewer (`--role reviewer`) signs their own review of it, never a release; an analyst (`--role analyst`) adds questions to a running case and an observer (`--role observer`) proposes them, and neither signs a release (every enrolled person may sign their own acts on the question register: `swarm.sh question … --sign`). One person who is both enrols twice, under two ids, and is refused on one run in both roles. The key is one of three kinds (KEY): an ssh key made here (`--generate-key`: ed25519, the passphrase asked twice on the terminal with echo off, at least 8 characters) or given (`--key FILE`, which must be encrypted: `ssh-keygen -y -P ""` must fail on it; its passphrase is asked to prove it signs; a `.pub` names a key held in ssh-agent, for the command line only); `--no-passphrase` takes a key without one, a documented trade the console refuses. A FIDO key (`--fido`): an ed25519-sk key made on the authenticator plugged into this computer, by an `ssh-keygen` with FIDO support (below), with `--fido-verify-required` (every signature needs the PIN as well as a touch) and `--fido-resident`; the key-handle file stays in the examiners' directory. An e-signature certificate (`--pkcs11-module PATH` with `--pkcs11-id HEX` or `--pkcs11-uri URI`): an X.509 certificate on a token, read without the PIN; the record keeps its PEM, its sha256 fingerprint (`X509-SHA256:…`), CN, issuer, validity, key usage and whether it carries a qualified-certificate statement, and refuses one without digitalSignature and nonRepudiation or out of its validity; `--pkcs11-chain FILE` names the issuing CA's certificates, which then travel inside every signature so a verifier needs only the root. An ssh key is checked by signing a challenge and verifying it; a FIDO key made just now and a certificate are not (a touch and the PIN are what signing asks for). Enrolment prints the fingerprint and, for an ssh or FIDO key, the line for the organisation's signer register (an ssh allowed-signers file: namespaces `dfirswarm-release,dfirswarm-package` for an examiner, `dfirswarm-review` for a reviewer): the register, checked with the person, is what ties the key to them; a certificate's issuer does that for an e-signature. `--tsa-url` and `--tsa-ca` are the RFC 3161 authority the examiner's releases are timestamped by. `examiner list` (id, name, organisation, fingerprint, role, kind), `examiner show ID` (the register line, and whether the console signs with the key) and `examiner machine` read them. No private key is ever printed or copied, and a certificate's subject is shown by its CN alone: a qualified certificate's subject can carry a national identity number.
- `machine` shows the install's machine key (as `examiner machine`); `machine rotate` retires it and makes the next one. The machine key seals the draft release at stop, unattended, so it has no passphrase: rotate it when a pane may have read it (a host run started with `--accept-signer-exposure` records that it could). The old key, its public half and its record are moved to `machine/retired/<id>/` (0700, the key 0600) with `retired.json` (when, by whom, its fingerprint), never deleted: every draft it sealed carries its public key and is still checked against it, and a retired key still counts as a signing key for the host-run refusal above. The new key is made at once, where and as a seal would make it, and both fingerprints are printed; the next draft is sealed with the new one. Half a key (the key or its record without the other) is refused and nothing is moved. `machineSigner` puts the machine directory back to 0700 and the key and its record to 0600 each time the key is used.
- `review <id>` is the examiner's review. `--adopt N`, `--qualify N --note T` (adopt with a stated qualification), `--reject N --note T` (for an answer: withdraw it) and `--inconclusive N --note T` are the examiner's disposition of a conclusion, an `answer` entry (ledger version 4) or any entry, by seq and hash. An answer whose support is defective (what the ledger gate names: support that names no entry or another hash, superseded without its correction cited, disputed or resting on a failed job's output without `qualifies`, an answer resting on one that no longer stands; no support at all; the tokens the hub found in no cited entry) cannot be adopted or qualified: an unsupported conclusion is not waived, it is withdrawn or rendered inconclusive, and repairing its support is further examination: the run resumed (`resume`, below), or a new run. A superseded answer is refused: its correction is what stands. `--technical-review --reviewer ID|NAME --outcome agreed|issues-resolved|disagreement --checked TEXT [--entries 4,10 | --all-answers] [--disagreement TEXT]... [--reviewed-at ISO]` records a second person who checked the methods: who, on what competence, what was checked (entries by seq and hash, or every answer), the outcome (a disagreement says each one and how it stands), when, and what it was over (report.md's sha256, the ledger's head, custody's sha256, the head of the dispositions); two-stage signing, below, says who writes and signs it. These, and the sign-off, are an enrolled examiner's: `--examiner ID`, or the one enrolled when there is one; `--accept N`, `--amend N --note T` and `--reject N` of a finding may still name someone who is not enrolled, and the line says so by carrying no id. What the kickoff recorded as the run's `examiner` is never taken for the examiner: the report shows it as who ran the run. `--sign`, once the run has ended, is the adoption, in two halves: prepare, then seal. It is refused while a defective answer has no withdrawal or inconclusive disposition, with no report at `work/report.md` (`--report PATH` names another under the run), when the run is not as custody sealed it, when a technical reviewer is the examiner, or when the run requires a signed technical review there is not; otherwise it renders the report's final bytes once (no DRAFT mark, a fixed time, printed with `--pdf`) into `release/.pending-<nonce>/` (0700, files 0600) and prints what will be signed: the report's and the release's sha256 with the path to read it at, the gate's counts and the rejections standing, the technical reviews, and the key (with "touch your key" for a FIDO key). It asks on the terminal for the examiner's confirmation of "I have read the report and the answers I adopt", then for the key's passphrase or PIN with echo off, and seals exactly the prepared bytes: `release.json` records how it was signed (`signing`: `via: cli`, the consent confirmed, the statement, the sha256 shown, when it was prepared and confirmed, the key's kind and fingerprint, the `ssh-keygen` or `openssl` that signed) and is signed with the key's kind (`release.json.sig`, or `release.json.p7s` and `report.pdf.p7s` for an e-signature); the signature is timestamped when the examiner's enrolment names an authority (`--no-timestamp` skips it), and the review's sign-off line names the release. A seal is refused when the prepared bytes, the review, custody, the report or the releases moved since, or after fifteen minutes; a wrong secret leaves the prepared release for another try (three at the terminal). `--yes` skips only the confirmation: the release then records the consent as `presented`, not confirmed. With no terminal and no `--yes` the sign-off is refused. A run with no release yet gets the machine's draft first. After an adoption, another is an amendment and says why (`--amend-reason TEXT`); it examines nothing again. An answer the examiner made no disposition on is the agents' conclusion, not adopted, and the release lists it so. `--show` prints what has been reviewed (each disposition, whether the examiner is enrolled, the technical reviews, the release the sign-off names), and exits 4 when the ledger's head or the report's hash has moved since the sign-off (1 when the review's chain is broken). The review lives beside the registry, where no agent reaches (`runs/reviews/<id>.jsonl`, 0600): each line is chained to the one before, appended and never rewritten, and a review whose chain is broken takes no more lines. The report, the summary and the console show each entry's review; `adoptionState()` (scripts/review.ts) gives the report body each answer's disposition, its defects and what it shows (adopted, qualified, withdrawn, inconclusive, or the agents' conclusion, not adopted). A sign-off from before releases is a chained record, not a key's signature, and is said so.
- `releases <id>` shows the report's releases: each version, a machine's draft or an examiner's adoption, who sealed it with which key, why it was made, the bytes it binds, and what is beside it (a token, a mirror's receipt, a print). A release is `release/v<N>/`: `release.json` (the record), `release.json.sig` (its ssh signature, namespace `dfirswarm-release`: the machine's, an ssh key's or a FIDO key's) or `release.json.p7s` (a CAdES-BES CMS made on an e-signature token, with `report.pdf.p7s` beside a PDF), `report.html` (the report's bytes, rendered for that release at its own time with no other wall clock in them), `report.pdf` when printed for it. v0 is the machine's draft when custody is taken at stop, sealed by this install's machine key (made once, outside every run, with no passphrase, labelled as the machine's): it binds the swarm's report as custody sealed it, the rendering with the DRAFT mark, the custody verdict and its anchor, the index of `work/` custody sealed, the head and length of the ledger, its attestations and disputes, the store journal, the trace and the review, the harness commit at kickoff and now, the renderer's and the run contract's sha256, and the models; it is adopted by no one. v1 is an enrolled examiner's adoption (`review --sign`): the examiner's key, each disposition, the answers not adopted, the defective ones and how each was resolved, the technical reviews, the final bytes. Each later version names the one before it by its sha256 and says why it was made; nothing in a release is written over, and every release's line goes into the anchor beside the run. Each release says its evidence cutoff: the evidence as custody sealed it; further examination reopens it, as the run resumed (`resume`: a later release binds the continuation, and this one stays valid for what it bound, a prefix of the same chains) or as a new run. `--draft [--reason TEXT]` writes the machine's draft for a run that has a verdict and none (or another, with a reason); it is refused when the run is not as custody sealed it. `--verify [--allowed-signers FILE] [--ca FILE [--ca-intermediate FILE]] [--tsa-ca FILE]` walks the chain: each record, its place (prev), its signature (the machine's seal only against the machine key it names, said as "machine seal, self-checked" and never "verified"; an examiner's ssh or FIDO signature against the organisation's register when given: verified, a key the register does not list, or a key it lists for another principal, which fails; without one, sound under the key the record names; an e-signature with `openssl cms -verify`, its certificate held to the fingerprint the record names, and its chain against the trust anchors in `--ca FILE` with the intermediates in the CMS or in `--ca-intermediate FILE`, naming each anchor's sha256; without a CA, "signature valid; certificate chain not checked"), how it was signed (from the console or the command line, the consent confirmed or presented, over the report.html shown), the technical reviews it binds as signed (still signed, over the state it binds), the host it ran on when its agents could reach the signers' keys, the bytes it binds (the HTML, the PDF, the swarm's report, a print), the verdict and the index it names (the current ones or ones custody kept aside), the ledger, its attestations and disputes as they are, the trace, the journal and the review as prefixes whose chain still holds (lines may follow a release; the ones it bound may not change), its line in the anchor, its token; exit 0 when it all holds and every adoption's key is one the register allows (an e-signature's chain one the CA verifies), 3 when it holds and nothing was given to check an adopting examiner's key against, 4 when something does not. A run no examiner has adopted says "RELEASES HOLD: the machine's seal, self-checked". `--print [N]` prints release vN's HTML to PDF beside it (`print-<k>.pdf`, `print-<k>.json`): made after the release was sealed, it is not in it, and the next release binds the record. `--mirror cmd:COMMAND|dir:PATH|print [--version N]` copies a release's digest line to an independent copy (the run's `--anchor-mirror` does it at every release). `--ots [--upgrade]` stamps the signature with the OpenTimestamps client when it is installed (`release.json.sig.ots`, pending until a Bitcoin block commits it; `--upgrade` completes it later) and says "unavailable" when it is not. `--transparency COMMAND` hands the digest line to a transparency log's client on stdin, with the release's files in its environment (`DFS_RELEASE_JSON`, `DFS_RELEASE_SIG`, `DFS_RELEASE_SHA256`), and keeps what it prints whole as the receipt (`transparency-<k>.json`).
- `timestamp <id> [--version N] [--tsa-url URL] [--tsa-ca FILE]` obtains an RFC 3161 token over the latest release's signature now (another version with `--version`): an air-gapped lab's later step. The authority is `--tsa-url`, else the adopting examiner's enrolment, else the run's custody set-up. `timestamp.json` beside the token says when it was obtained and that the release's proof of existence dates from the token's time, not the release's own; `--tsa-ca` checks the authority's signature (exit 0 verified, 3 imprint only, 4 does not verify). One token per release: a second is refused.
- `rerun <id> <job> [--normalise timestamps@1] [--network] [--json]` runs a sealed job again, once the run has ended: its recorded spec through the job service's own worker path, in the image it ran in, held to the image digest the journal recorded (another digest here is refused, never substituted), the tool's or recipe's sha256 and the run's packs' manifests. The outputs go to `<sandbox>.reruns/<job>/<n>/` (with `rerun.json`), never into the store, and each is compared by its bytes with the sealed manifest: the same, different (both hashes), not made, added; stdout and stderr too. A byte mismatch is a mismatch (exit 4). `--normalise NAME@VERSION`, only when asked, says which differing files are equal once a named, versioned normalisation is applied to both, apart from the verdict and never as a reproduction; `timestamps@1` replaces ISO 8601 and RFC 2822 date-times in text files, and its exact definition is in the record. The rerun has no network unless `--network` gives it the job's own. An import (a copy of a live file) and a job whose image digest was not recorded are refused. What a rerun does not reproduce is said: the bytes the job read (not measured), what it fetched, the reasoning that asked for it.
- `certify <package dir|zip> [--allowed-signers FILE] [--tsa-ca FILE] [--out FILE]` writes a certification template of the kind FRE 902(13) and 902(14) contemplate: what the package says of itself (the manifest's sha256, who signed it, the custody verdict, every release of the report and who sealed each, the redactions), `verify` run on it with its output and exit verbatim, the statements for the certifier to confirm or strike, what the checks do not establish, and blank fields for the qualified person who completes and signs it. It is not legal advice, and says so. A report's PDF carries no signature of its own (no PAdES): its release binds the PDF's sha256, and the release's detached ssh signature is the examiner's; a certifier signs the template the same way (`ssh-keygen -Y sign -n dfirswarm-certification`).
- `package <id> --sign [--key FILE]` signs the package's `MANIFEST.txt` with an ssh key (`ssh-keygen -Y sign`, namespace `dfirswarm-package`; default key `~/.ssh/id_ed25519`, then `~/.ssh/id_ecdsa`; no key is a BLOCKER). It writes `signer.pub` and `SIGNER.txt` (who signed: user and host, the examiner, the key's fingerprint, the time) before the manifest, so both are listed in the manifest the signature covers, then `MANIFEST.txt.sig`, and prints the allowed-signers line a recipient needs. The package also carries `court-set.json` (every file handed over, with its size and sha256, or why it is absent) and this run's lines of the operator's record.
- `verify <package dir|zip> [--allowed-signers FILE]` re-hashes every file against `MANIFEST.txt` (none missing, none changed, none added) and checks the signature. Exit 0: the files hold and the signer is one the file allows; 3: the files hold and the signature is sound, the signer not checked (no `--allowed-signers`); 4: the files hold and the package is unsigned; 1: something does not hold; 2: usage. A signature proves the manifest was signed by that key and not changed since; who holds the key is for the allowed-signers file to say. It refuses a listed path outside the package or reached through a link, and says whether `SIGNER.txt` is under the signature (a package from before 2026-09-27 has it beside the manifest, unsigned). Then (`scripts/package-tools.ts verify`): every part in `COMPONENTS.json` is there or declared absent, and one the verdict sealed (a trace, a ledger, a journal, the index of `work/`) or the anchor names (a signature, a token) cannot be declared absent; a package from before 2026-09-27 has no list, and a core part missing from it fails. It re-walks the chains the package carries (the trace; the ledger, every entry a redaction left readable recomputed from its core; its attestations; the store journal, where only examiner notes may follow the sealed line; the examiner's review, and what its sign-off is over) against the custody verdict's seal, the verdict against its anchor, `artifacts.sealed.json` against the sha256 the verdict and the anchor name, and every packaged `work/` file against it: changed, missing or not in the sealed index is a failure, a file left in the sandbox (`LEFT-BEHIND.txt`) or redacted (`REDACTIONS.txt`) from the sealed bytes is said as such. An anchored file a redaction changed is accepted when `REDACTIONS.txt` names the anchored sha256 as its sha256 before; a redaction's lineage and leak scan (`REDACTIONS.json`) are said, and a change it does not record fails. The act chains (attestations, disputes) are walked with a redacted line's hash taken as it stands and every other line's recomputed. Then the report's releases (`release/`), as `releases --verify` walks them, a release's HTML redacted from its bound bytes and a withheld PDF said as such; `--allowed-signers` is the register an adopting examiner's key is held to (an adoption whose key it does not list makes a signed package exit 3), `--tsa-ca` the authority's CA for release tokens.
- `export <id> --format csv|timesketch [--out FILE]` writes the ledger as CSV (every field, the entry hash, superseded by, the examiner's review, grounding) or as a CSV Timesketch imports (message, datetime in UTC, timestamp_desc). Default `<sandbox>/exports/ledger.csv` or `ledger.timesketch.csv`. A text cell a spreadsheet would run as a formula (starting with `=`, `+`, `-`, `@`, a tab or a carriage return) gets a leading apostrophe; that is the only change made to any value.
- `hold <id> [--reason TEXT]` puts a run on hold: it is kept from `purge`, from a new run in its sandbox and from the VM reaper. `release <id>` lifts it; the record keeps both. (A report's releases are `releases <id>`, above.)
- `custody-verify <id> [--allowed-signers FILE --identity NAME] [--tsa-ca FILE] [--scratch DIR] [--json]` takes the run's custody again writing nothing in the run (`scripts/custody.ts <sandbox> --verify`) and holds it to the verdict it sealed: every check's status now against then (the evidence check holds each link the evidence is read through, `inputs/` or each `inputs/<set>`, to the source the kickoff recorded: one that leads elsewhere, even to identical bytes, fails); the sealed prefix of the trace (the line the verdict named must be the same bytes), the lines written after the seal and whether they are only the run's closing lines; each chain's sealed length and head (the ledger, its attestations and disputes, the store journal, where the examiner's notes after the run are named and allowed, the gateway log), each drift named with both; every file under `work/` against the index custody sealed (`artifacts.json`, held to the sha256 the verdict and the anchor name), each changed, removed or added file named; the verdict against its anchor; its signature (against an allowed-signers file when given, otherwise only that it is a valid signature); and the timestamp token: its digest, and its signature and certificate with `openssl ts -verify` against `--tsa-ca FILE` (else `SWARM_CUSTODY_TSA_CA`, else the run's `--custody-timestamp-ca`). Without a CA it says "imprint only, signature not verified", and a token the anchor recorded as not verifying fails. A verdict from before a part was sealed says "not sealed by this verdict" for it rather than failing. A kept disk msb checks is loaded under `--scratch DIR` (the host's temporary directory by default), never beside the run's snapshots, and the command says what it touched outside the run and what it found and left (a disk an ended custody left loaded). Exit 0 when the run is as its verdict sealed it, 4 when it is not or a check does not pass.
- `purge <id> --yes` deletes a finished run's sandbox, this run's kept VM disks (with `--vm-snapshot-dir`, only this run's files in that directory) and its hub directory. Without `--yes` it lists what it would delete. It refuses a run that is running, being prepared, finishing or `stop_incomplete`, a held run, a run whose VMs are still up, and a sandbox path it does not recognise. The registry keeps the run as `purged`, and the operator's record gets the destruction record: what was deleted with its size, what was not, and the hashes of the inputs manifest, the custody verdict and the package manifest. The anchors outside the run and the examiner's review stay: they hold hashes and verdicts, not material.

Three read-only helpers:

- `image-for [--pack ID]... [--tools-from DIR] [--playwright] [--no-jobs] [--brains-with-packs]` prints the image a kickoff with these packs would boot its agents on, by the kickoff's own rule (with packs and tool jobs, the base, and the packs' programs in job images; with `--playwright`, `--no-jobs` or `--brains-with-packs`, the image that holds every pack), as one JSON line: `ref`, `digest` (null when neither the images lock nor msb has it), `profile`, `arch`, `packs`, `pinned_by` (the lock that pins it, or null for a local build's name), `reason` and `jobs` (each job image's `profile`, `ref` and the `packs` it serves; empty when the agents boot the packs' image). It starts, pulls and writes nothing; a pack that does not resolve or a lock that pins by tag exits 2. The console's New swarm form shows its answer.

- `node --experimental-strip-types scripts/coverage.ts <sandbox> [--json]` lists the evidence files no command on the trace named, and, for each ledger entry, whether a call before it named its source (grounding). It matches paths in every call's arguments and knows no tool. A file a command named was not necessarily examined, and a file under a directory a command named is counted apart. The report and the summary carry the same figures, and the idle watchdog posts the unnamed inputs at a quarter, a half and three quarters of the wall clock, assigning them to nobody.
- `node --experimental-strip-types scripts/score.ts <sandbox> --answers FILE.json` checks a run against an answers file of your own (`[{id, question, accept: [...], reject?: [...]}]`, a `/regex/` or plain text). It prints found, not found or contradicted for each question, and writes nothing anywhere.

#### Signing: the keys, the console, two stages

**The hardware and the programs.** An ssh key needs only `ssh-keygen`. A FIDO key needs an `ssh-keygen` with FIDO support: on macOS, Homebrew's (`brew install openssh libfido2`; it need not be linked, and macOS's own `/usr/bin/ssh-keygen` has none); on Linux, the distribution's normally has it built in. The product takes `DFIRSWARM_SSH_KEYGEN` when it is set, else looks at Homebrew's openssh and the one on `PATH` and picks the first whose `ssh-sk-helper` has the built-in support (read from the files, never by talking to the key), else takes the one on `PATH` when `SSH_SK_PROVIDER` names a middleware library; each release records which one signed. An e-signature certificate needs the token's PKCS#11 module (a SafeNet eToken's is `/usr/local/lib/libeTPkcs11.dylib`), OpenSC's `pkcs11-tool` to read the certificate, OpenSSL 3 and libp11's provider (`brew install opensc libp11 openssl@3`); `DFIRSWARM_OPENSSL`, `DFIRSWARM_OSSL_MODULES` and `DFIRSWARM_PKCS11_TOOL` name them when they are elsewhere. The token's own chatter (slot tables, key labels, subjects) is captured and never shown: a failure is reported by its kind (the PIN refused, no token, no key under that id).

**The secret.** A passphrase or a PIN is read on the terminal with echo off, or taken from the console, and reaches the signing program only down a pipe on its fd 3: `ssh-keygen` asks through `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`, answered by `scripts/askpass-fd3.sh`, and OpenSSL's provider reads `pin-source=file:/dev/fd/3`. It is never in an argument, the environment, a file, a job record or a log. A new key's passphrase is fed to `ssh-keygen` on its stdin, in a session with no terminal (with one, `ssh-keygen` reads the terminal and ignores stdin).

**From the console.** The Release tab of a stopped run shows its releases and, to adopt it, a list of the enrolled examiners (a key without a passphrase or held in ssh-agent is not offered), the prepared report in a frame with no scripts beside the sha256 of exactly the bytes the browser holds, the gate's counts and the key, a box to tick, "I have read the report and the answers I adopt", and then a dialog that asks for what the key wants: the passphrase; a touch of the FIDO key (plugged into the computer the console runs on) and its PIN when it was made verify-required; the e-signature PIN. The release records `via: console`. The console signs only with its token (a console started with `SWARM_UI_TOKEN=""` does not sign), only when it listens on loopback, for requests whose Host is a loopback name and whose Origin is its own, and never while a host-mode run is live on this install. Five wrong secrets for one person lock that person out of console signing for fifteen minutes, and the operator's record says so; every console signing act is on that record, without its secret. The Examiners page enrols a person (an ssh key made with the passphrase typed twice, a FIDO key with a touch, a token's certificate), and the Technical review tab is the reviewer's.

**Two stages: the examiner and a technical reviewer.** The review comes before the release. The examiner records the dispositions; a technical reviewer enrolled with `--role reviewer` reads the run and records their own review, `swarm.sh review <id> --technical-review --reviewer ID --outcome … --checked …` (or the Technical review tab), which shows the state it will be over, asks for confirmation and the reviewer's own secret, and writes the record and a `countersign` line after it together: the countersign carries `over_seq`, `over_sha256` (the record line's own hash), the signature over the record's bytes (SSHSIG in the `dfirswarm-review` namespace, or a CMS for a certificate) and the key. A record the examiner writes, naming a reviewer who is not enrolled (`--reviewer NAME --competence TEXT`), says "recorded by the examiner; not signed by the reviewer"; a reviewer can countersign a record naming them later (`--countersign SEQ --reviewer ID`), and a countersign made after a release names that release, which the next amendment binds. A reviewer with the examiner's id, name or key is refused: the register, not the keys, shows that two people signed. When the reviewer disagrees, the examiner withdraws the answer or renders it inconclusive, prepares again, and the reviewer signs again; the earlier record stays in the chain, "signed over an earlier state, not current". `--require-technical-review` at kickoff (stored in the run's record) or `SWARM_REQUIRE_TECHNICAL_REVIEW=1` makes the seal refuse unless a technical review is signed by its reviewer, over the run as it stands, with an outcome other than a disagreement. A reviewer on another machine works from the run's package: `swarm.sh review <package-dir> --technical-review --reviewer ID …` writes `review-import.jsonl`, made over the package's review, report, ledger and custody; the examiner runs `swarm.sh review <id> --import FILE --allowed-signers REGISTER` (or `--ca FILE` for a certificate, or with the reviewer enrolled here), which checks the hashes, the signature, the register and the review's head, refuses a file made over a head that is no longer the run's, and appends the two lines as they were made. The release binds every technical review; the report and verify say each in one of five ways: signed by the reviewer; recorded by the examiner, not signed by the reviewer; no technical review; countersigned after release vN; signed over an earlier state, not current.

**The hardware tests** are in `tests/hw/` (a FIDO key, the e-signature token, the console's seal path with a real key), run only with `DFIRSWARM_HW_TESTS=1` at a terminal; their README says how.

#### `ui`

`ui [--port N] [--host H] [--no-build] [--inputs-root DIR]... [--allow-inputs-root-from-ui]`. `--inputs-root` names where the evidence sets live (or `SWARM_INPUTS_ROOT`, `:`-separated); `--allow-inputs-root-from-ui` lets the token holder add one from the kickoff form, off by default (see docs/inputs.md). Defaults `SWARM_UI_PORT=43173`, `SWARM_UI_HOST=127.0.0.1` (this machine only; `--host 0.0.0.0` opens reads to the LAN — they need no token and show case data), runs dir `SWARM_RUNS_DIR` (default `runs/`). Builds `ui/dist` when missing and `node_modules/vite` exists; `--no-build` skips that. Then `exec node --experimental-strip-types scripts/ui-server.ts`.

#### `reap`

`reap [id] [--stall-sec N] [--stop]`. First puts away microVMs this registry recorded whose run is not running or being prepared (by label; a VM another registry recorded is never touched; with `id`, only that run's): a run of this registry keeps each disk as a snapshot, as a stop would. A run left `prepared` for more than two hours is a kickoff that died, and its VMs count as orphans; so does a throwaway VM (the catalog's, the toolbox check's, netcheck's) that is no longer running, whatever run it was made for. A `^C` during one of those steps puts its VM away on the way out; one the signal did not reach runs until its own time limit (four hours for the catalog, thirty minutes for the toolbox check) and is collected by the next `reap` after that. Without `id`, every `running` swarm in the registry. Default stall `REAP_TIMEOUT` or 960 s (above the catalog's 900 s step, so a long `vol`/`fls` is not a stall). A pane Herdr (or, in a microVM run, the agent's extension through the hub) reports as `working` is never reaped. `--stop` also closes the reaped agent's pane, and puts a microVM agent's VM away with its disk kept. Delegates to `scripts/reap.sh`.

#### `netcheck`

Checks the egress a run would have, in a microVM unless `--isolation host` (or `SWARM_ISOLATION=host`) says otherwise.

`netcheck [--image REF] [--model P/ID]... [--allow-host H]... [--provider-host P=HOST]...` asks msb, in a throwaway VM built with the policy a run's VM would get (`scripts/vm.ts netcheck`): every allowed host name must answer (any HTTP status), `example.com` must not resolve, and with two host names a stand-in secret bound to the first is swapped in there and stopped on its way to the second. Suffixes, addresses and the host gateway are listed, not probed. Without `--model` or `--allow-host` it checks `api.deepseek.com` and `api.anthropic.com`.

`netcheck --isolation host` runs `netguard.sh --only api.deepseek.com` around two curls: `https://api.deepseek.com/` must not return a proxy 403 or fail to connect (origin 401/404 is fine); `https://example.com/` must be 403 or unreachable. Prints the last 20 netguard log lines. Exit non-zero on failure.

msb records one refusal: a placeholder on its way to a host its secret is not bound to, as a `secret violation` line in the VM's `runtime.log` (the VMs run with `block-and-log`). Custody reads those lines from the logs `stop` keeps and names each one in its verdict. A request to a host outside the policy leaves no record in msb: the name does not resolve and an address has no route, which the agent sees in its own tool output.

Which connections msb decrypts. A VM with no secret bound (a keyless local model and no pack secret) has none intercepted. Once one secret is bound, msb terminates TLS on port 443 and on every port a secret's host is reached on, for every connection except those to a host name or suffix on the VM's allowlist that is not a secret's host and does not cover one. So these are intercepted: a secret's own hosts (that is where the placeholder is swapped); an allowed suffix that covers a secret's host; an `--allow-host` entry given as an address or a CIDR block on one of those ports (msb's bypass takes names only); and under `--no-netguard` every public host on those ports. The allowed host names that receive no secret keep their own TLS end to end: msb never reads what is sent there, and a placeholder can reach them, the value it stands for cannot. A client with its own trust store, not the guest's (Chromium's NSS store, Java's keystore), fails on an intercepted connection.

The memory and `full` images carry the Volatility Foundation's Windows symbol pack (a bundle of 2019: `images/README.md`), so a kernel it covers needs no network. For a newer kernel, Volatility's symbol downloads are not cached across runs under microvm: each VM fetches what it needs through `msdl.microsoft.com:80` and `*.blob.core.windows.net` again. A shared cache would be a writable directory common to every VM, which is what the per-seat layout exists to avoid.

Three decisions about a VM's network, said so nobody assumes otherwise:

- **No apt mirror rule.** `--allow-install` opens the Python package index only: pip reaches `pypi.org` and `files.pythonhosted.org`. Root in a VM can install system packages into its own disk only if the Debian mirror the image's sources name is allowed with `--allow-host` (for the base image's plain-HTTP sources that would be `deb.debian.org:80`; not measured).
- **DNS.** msb's DNS rebinding protection is left at the SDK's default (on), and its strict mode is not enabled: a host-name rule admits the addresses that name resolves to, and msb does not require the connection's own TLS server name or HTTP `Host` to be that name. A local model reached by a host name that resolves to a private address may be refused by the rebinding protection (UNKNOWN, not measured); name it by address.
- **No TLS-inspecting corporate proxy.** A network that reaches the internet only through a proxy that decrypts TLS is not supported in VM mode: the VMs do not trust the host's certificate store (msb's `trustHostCAs` is off), and no upstream proxy is configured for them.

#### The dynamic network: `net`

`swarm.sh net <run> list` prints the run's case policy, what waits on the
operator (one item per host and lead, with the reasons it was refused and the
command that answers it), every grant with its state and what is left of it,
every request with its decision and machine-readable reasons, every capture,
every use the fetch service refused, and contamination. `net <run> grant
NR-<n> --why TEXT` grants a refused request: the same rules run with the
overridable reasons waived and recorded (a login, an upload, a credential, a
sensitive value, an internal case stay refused). `net <run> deny NI-<m>|NR-<n>
--why TEXT` declines an item or a request: the avenue closes, the lead does
not. `net <run> revoke N-<k> --why TEXT` ends a grant: its next use is
refused, a transfer under way stops. `net <run> grant --socket HOST[:PORT]
[--lead L-<n>] --why TEXT` makes a socket grant (tier 2) for the run's jobs run
with `network=allowlist`: host and port only, no method or path control, no
content capture; refused under `ctf`, `internal` and `live_adversary`. Every
act is on the trace and the operator's record, and posted to the board to
whoever asked. The console's **Network** tab shows the same and runs the same
commands. A host-managed adapter key (VirusTotal: `DFIRSWARM_VT_API_KEY` in the
shell that starts the run) is read by the fetch service alone and given to no
VM; `network view=adapters` tells the agents whether it is configured.

#### The case contract: `requests`, `evidence`, `material`

The case policy is fixed at kickoff ([ADR 0014](adr/0014-the-case-contract-says-what-comes-in-and-what-is-asked.md)):
written to `network/policy.json` before the custody anchor, which holds its
sha256, and carried in SWARM.md and the registry's `case_policy`. Custody
seals it by its sha256 and names a rewrite (`CASE POLICY REWRITTEN`, the
`case policy` check failed); a release binds it (`release.json` `case_policy`).
A resume keeps the policy its kickoff recorded and prints a `NOTE` for each
field its options would have changed. At kickoff the services the goal names
(a URL, a host, an adapter's whole id such as `rdap_domain` or its service's
name, alone or inside a tool's name such as `virustotal_hash`, a denied
service by its own name: the name of a host that is the service's own, such as
`google.*`, never a subdomain's label) are held
to the policy and the adapter catalogue and printed as `WARN` lines: a
closed network, a lookup the policy does not allow, an adapter whose key is
not configured, a host no adapter reaches or the hard denials refuse. Nothing
is refused for it.

Everything the run asks of a person is an operator request with a durable id
(`R-n`): a lead closed `needs_operator`, an acquisition (evidence the run does
not have), a clarification an agent asked of a question, a network item, and a
stop the harness proposes when nothing yields. The record that makes it (the
lead's close, the question's `clarify_ask`, the grants chain's `item`) is its
commit; the request is derived from it and written once to
`requests/requests.jsonl`, a chain custody seals, and rendered to
`operator-requests.jsonl` (one line per request as it stands) and
`requests/requests.md`. Its lifecycle is `pending` → `notified` (your
`--notify` targets were handed its id) → `acknowledged` → `answered`,
`declined` or `withdrawn`. The hub reconciles and notifies after every act
that may open one and on every round, so a crash between the commit and the
notification loses nothing; the watchdog is the fallback (every round in a
host run, every five minutes with a hub). A delivery is claimed on the chain
before it is sent, so the hub and the fallback never both send one; a failed
one is tried again after a backoff (a minute, doubling, at most an hour). A
request imported from a run before the chain is notified unless that run's
watchdog had notified it.

- `requests <id> list [--open] [--json]` lists them, open first, with how each
  is answered; `show R-n [--json]` prints one whole with its history.
- `requests <id> ack R-n [--why W]` acknowledges one; `answer R-n TEXT` answers
  it where it is answered (a lead's: its note, and the lead reopens; a
  clarification's: its reply; a stop proposal's: on the request);
  `decline R-n --why W` and `withdraw R-n --why W` close it. While the run's
  hub runs, each act goes to it (it writes the chain), as a question's do;
  the act is said on the board from its event on the chain, once, and a post
  that fails is made at the next round. The outcome is on your record
  (`requests_outcome` in `runs/operator-audit.jsonl`).
- An acquisition carries what it asks for (`source`, `where`, `questions`,
  `expected_value`, `urgency`: normal, urgent or volatile, `owner`,
  `authority_needed`) and its stage: `requested` → `authorised` | `declined` →
  `collecting` → `received` → `validated` | `unavailable`.
  `requests <id> authorise|collecting|unavailable R-n [--why W]` moves it
  (`unavailable` needs its reason); `evidence add --for R-n` makes it
  `received` and `validated`. Under `--more-evidence no` it is declined at once
  with "no additional input under this case policy"; under `yes` it is
  authorised by the policy.
- `evidence <id> add PATH --why W [--for R-n] [--question Q-n]... [--sha256 HEX]
  [--as ID]` adds evidence acquired after the kickoff, a file or a directory
  outside the run: each file is copied into a staging directory of its own
  outside the run and held to the sha256 its source had (and to `--sha256`, an acquisition
  hash of the one file), then sealed in the store as `import:ev-<n>` (the store's
  import path: read-only, in a manifest, the bytes kept once), written on the
  store journal as an `evidence_added` line with its inventory revision and
  every file's sha256, and recorded on the ledger as external material
  (`acquired_evidence`, with its provenance). It answers `R-n`, reopens the
  closed leads under the request's questions (and `--question`'s) and the
  request's own lead, makes the answers to those questions recorded before it
  stale until they are recorded again, lifts an acceptance made before it,
  makes stale every standing `bounded_negative`, `not_determinable` and
  `partial` answer whose coverage was recorded before it, whatever question
  it was added for (the reply and the board post name each; the finish line
  holds each, `evidence_stale`, until the new evidence is examined for it,
  another seat reviews that, and the examination says how the evidence
  bears on the answer: a coverage record naming the import among its
  objects, attested by another seat, or an entry resting on the import,
  attested likewise, cited by the answer recorded again, with the entry
  that examined the import carrying a delta (its refs name the import's
  files; a `rel` to the answer of kind supports, contradicts, adds_part,
  irrelevant or inconclusive), among that reviewed coverage record's
  results, or cited by the answer and attested by another seat; a review
  made before the evidence came does not count for it;
  an established answer is not staled; `question accept` after the
  evidence came excuses it, and its reply names what the finish line still
  holds), then, once it is committed and never inside it, searches the new
  files for every standing coverage record's `looked_for` strings (the
  reverse sweep: the reply's `reverse_sweep` says where it runs and for how
  many records and strings; it runs in the hub's background, or, when the
  addition was made here with no hub, as a detached step,
  `scripts/reverse-sweep.ts`; a pass at a time within its own budget,
  `SWARM_REVERSE_SWEEP_MAX_SEC`, 120, and `SWARM_REVERSE_SWEEP_MAX_BYTES`,
  2 GiB, what a pass leaves named and searched by the next; each pass's
  board post names its hits by question when it completes, the stale
  answers say theirs, and on an answer it does not stale a hit its answer
  does not reach is warned of, `late_evidence_hits`; a hit never holds by
  itself; `evidence list` continues a sweep left undone), and, when the
  run's catalogue is on, runs a detect pass over each file (at
  once when the hub runs, else at its next round). While the hub runs the act
  is handed to it: it is the store journal's writer. **Every seat's VM mounts
  the run's directory read-only and live, so an addition is readable there at
  once, at `store/imports/ev-<n>/out/`** (as it is to a host run's panes), and
  in jobs (`job_run` with `inputs: ["import:ev-<n>/<file>"]`); a finding cites
  it as `import:ev-<n>/<file>` however it was read, and its class and
  provenance are its ledger entry's, never the path. What follows from an
  addition is recorded once each, after its commit; a process that dies
  between is caught up by the hub's next round (or `evidence <id> list` with no
  hub), and the finish line waits for it. Refused under
  `--more-evidence no`, for a path inside the run, and when a copy does not
  hash as its source. `evidence <id> list [--json]` lists what was added.
- `material <id> add PATH --why W [--class operator_supplied|case_material]
  [--sensitive] [--as ID]` supplies material the same way (`import:mat-<n>`),
  recorded as external with `{supplied_by, at, from, sha256, permitted_use}`;
  `--sensitive` marks what its record says sensitive (no name, label or
  question may carry it). `question add --attach FILE` supplies a file given on
  this host the same way, and an attachment that is already an object of the
  run is recorded as supplied material. `check-answers` names every answer that
  rests on external material with its classes, the report marks it (§5) and
  lists the evidence and material added (§3), and `release.json` binds them
  (`external`, `acquisitions`). A record citing material whose class the policy
  says `none` for is refused.
- `symbols fetch --accept-terms --accepted-by NAME [--from DIR]` puts the
  files the packs list for the operator to acquire (the PDBs of the curated
  Windows kernels, `packs/memory-forensics/requires/symbols.windows.json`) into
  the host's symbol store, `$DFIRSWARM_HOME/symbols/blobs/sha256/<sha256>`, each
  held to its pinned sha256 and size, refused inside a synced folder. The files
  are Microsoft's under its symbol-server terms; the fetch is the operator's
  acceptance of them, refused without `--accept-terms` and `--accepted-by NAME`
  (nothing stands in for the name), and the acceptance (who, the terms, when,
  the sha256, and how: `attended` when a terminal was on both ends, the
  account, the host, the command) is written into the store's `manifest.json`,
  every earlier one kept and each journaled. A build takes an unattended
  acceptance only with `--allow-unattended-acceptance`. The packs read are this
  checkout's (`--packs DIR` for an installed pro or third-party pack). `--from DIR` takes copies you hold (every file of a pinned
  size is hashed; nothing is downloaded); without it each is downloaded over
  HTTPS on every hop, redirected at most twice and only to the hosts its list
  names, no more bytes than pinned, within a time limit. `symbols list` says
  which are held and accepted. `images/recipe.py build` takes them from the
  store, with their acceptance, and refuses a curated build without either
  (`images/README.md`, "Symbol tables"); the image records the acceptance
  beside the table it made. Each fetch is on the operator's record.
- `tool-supply <id> add PATH --why W --source TEXT [--built TEXT] [--sha256 HEX]...
  [--for R-n|L-n]... [--as ID]` hands a running (or stopped) run a program no
  image holds: a file, or a directory when the program loads libraries. It is
  material, sealed the same way as `import:mat-<n>` and recorded as external of
  class `operator_supplied`, never as evidence, with what an operator knows of a
  tool and the harness cannot: `--source`, where it came from (a package and its
  version, a URL, who built it; required), `--built`, how it was built or made
  fit for the run (leave it out for a program used as published), and
  `--sha256`, hashes you checked, each of which must be one of the supplied
  files' sha256 and is held to it (a hash of anything else, a source archive or
  a signed index, goes in the words). `--for` names the requests (`R-n`) and
  leads (`L-n`) it is supplied for, each of which must exist; a request's own
  lead is named beside it. The words are your statement and are recorded as
  such, whole (at most 4000 characters each: a longer one is refused, never
  cut); the ledger's entry carries them in its chained core
  (`provenance.tool`: `source`, `built`, `checked`, `for`), and
  `material.json` keeps them. The case policy's rules for material are kept:
  every preset (`standard`, `live_adversary`, `internal`, `ctf`) admits it
  (`more_evidence: no` refuses evidence, not material), and a policy that says
  `operator_supplied=none` for material refuses it before anything is sealed,
  since nothing recorded on its output could be kept; what rests on it, a job's
  output included, is flagged with its class like any material. **A directory is
  sealed whole**, every file under it, and every seat reads all of it: the
  reply lists the files, and a directory with a hidden file or directory in it
  (`.env`, `.git`, `.netrc`) is refused (give the files themselves; a hidden
  file named as the path is your choice). A path that holds the run (its
  parent, the runs directory) is refused.
  The board post tells the seats where it came from as you state it, what the
  harness checked, that they test it on input whose answer they know before
  relying on it, and **how to run it**: a sealed file has no execute bit, and
  nothing in a worker executes from `store/`, `work/extracted/`,
  `work/quarantine/`, `inputs/` or its own `$OUT`, so a job declares it as an
  input (`job_run` with `inputs: ["import:mat-<n>/<file>"]`) and copies it, and
  every library it loads, into an executable temporary directory inside the job
  (for example one made with `mktemp -d` under `/tmp`) before running it from
  there. In a base-image VM (msb 0.7.2, as root) a copy made that way under
  `/tmp` executed: `/tmp` is on the VM's overlay root, not a separate no-exec
  mount; a worker VM, which also mounts the run, was not tested. This is for a
  program you supply, never for evidence: evidence is read, not run (a job that
  runs code recovered from it is flagged), and a job that tried to run a program
  from `inputs/`, `work/extracted/` or `work/quarantine/` is told so, and sent
  to `tool-supply` or a reimplementation. A job that tried to run a program in
  place says so in its reason (`exit 126`, and the places nothing runs from), and
  the shell's other reasons for 126 (a file built for another machine, a missing
  interpreter, a directory) are quoted, not met with a copy. Supplying does not
  close the request or the lead: answer them (`requests <id> answer R-n TEXT`,
  `lead <id> note L-n TEXT`). `tool-supply <id> list [--json]` lists the tools
  supplied with their source, build, hashes and requests; `material list` shows
  them as material. If the run's hub was started by an older harness it takes
  the act as plain material (no provenance, `--for` not recorded, no
  instructions to the seats); this command holds the policy's rule, the
  statements, the hidden files and the `--sha256` hashes itself before handing
  it over, and the reply warns that the rest was not recorded.

The report's §8 carries "Evidence gaps and acquisition requests", generated
from the records: every acquisition with its stage and outcome, and each gap
told apart as never collected, unavailable, inaccessible, unexamined or
inconclusive, with its questions, what it bounds and what would close it. A
gap is never a finding that something is absent. The console's **Requests**
tab lists every request, open ones first, with the acts above, and the
header's badge counts the open ones.

#### The lead register and until-solved runs

`swarm.sh lead <run> list` prints every lead, the ones an agent closed
`needs_operator` first with the request and the command that answers it;
`lead <run> note L-n "TEXT" [--allow-host HOST]` answers one (recorded on the
lead, the lead reopened, posted to the board as the examiner, and in a microVM
run the host allowed for the run's jobs, as a socket grant it names: host and
port only, refused where the case policy permits none); `lead <run> reopen L-n` reopens a
closed lead. Each is on the trace and the operator's record. The console's
Leads tab does the same.

`swarm.sh start --until-solved [--stall-minutes N]` (the same as `--stop
operator`) runs until every question in scope has a disposition under the bar
([ADR 0013](adr/0013-a-negative-is-bounded-and-a-cap-pauses.md)): established;
partial; a bounded negative or not determinable, each on a coverage record
another seat reviewed; a premise shown not to hold; out of scope; accepted by
the operator; or withdrawn. That is the rule for every run, whatever its stop
policy; this one adds no stricter answer requirement: a question the evidence
cannot answer is answered `not_determinable` on its reviewed coverage record,
and the run ends examination-limited. What it takes away is the caps and the
clock: no wall clock, every cap advisory, no abandon, and a regroup
post when nothing moves for N minutes (15): first a nudge to the holder of a
lead a job still runs under, with what the job is doing, then everyone a window
later. Only `swarm.sh stop` ends it. A goal can
ask for it in its metadata block (`until_solved: true`, `stall_minutes: N`).
In a microVM run on a subscription (OAuth) provider, each VM's token is minted
at its start, valid for at least 12 hours (`SWARM_TOKEN_MIN_VALIDITY`
overrides it), and renewed on the host at half that validity: the watchdog
runs `scripts/vm.ts renew-secrets --spec <hub dir>/vm-spec.json --state <hub
dir>/secret-renewal.json` every ten minutes, which mints fresh tokens from
Pi's store and rotates each seat VM's secret in place with msb's live secret
update (the guest keeps its placeholder; a VM whose rotation would not be live
is left as it is and said on the trace, `secrets_renewed`).

How the seats share the work and end it ([ADR 0015](adr/0015-one-seat-finishes-and-work-is-offered.md)):
one seat coordinates the finish (normally the one that published the report
last); every other seat's `done` is answered "not yours", and the agents'
headers say whether the registers make the finish ready. `leads/finish.jsonl`
records the coordinator, the report's reviews, the late items it resolved and
the check result per state revision. The coordinator drafts the report, then
prepares the finish (`finish prepare`): it takes the finish as a done would,
runs no check, and answers readiness and every result, veto or objection late
against the report, with the lease's generation and the report's digest. It
resolves them all in one call (`finish resolve` with `items`, each folded with
where the report says it now or not_material with why, the generation, the
digest and a key naming the batch), invites the report's review (`finish
ack`), and calls done. A stale generation or digest, or an item that is not
late, refuses the whole batch and records nothing; a batch sent again under its
key is answered with what was recorded. What was late stays late through a
second prepare, a republished report and a takeover; after a resume, the first
prepare opens the new segment and keeps what was still late by name. Work nobody holds is offered to one idle
seat at a time, for a minute from when the offer reaches it; a lead held with
nothing done on it for ten minutes while its holder works on another lead is parked
and offered too. First choices are staggered at the start of a run (20 s a
seat, 90 s in all; `SWARM_FIRST_CHOICE_STAGGER_SEC=0` at kickoff turns it off,
`SWARM_FIRST_CHOICE_BOUND_SEC` sets the bound). The timings are pilot
settings: `SWARM_OFFER_SEC` (60), `SWARM_OFFER_MAX_SEC` (300),
`SWARM_REVIEW_HOLD_SEC` (600, how long a review's offer stays the seat's once
it took it with `offer accept`), `SWARM_LEAD_PARK_SEC` (600) and `SWARM_JOB_STALL_SEC` (600, for a running
job's "suspected stall", which is shown, never acted on). The console's Jobs
tab names a job that needed a program its image does not hold, with the
profile, for the images' upkeep. The Leads tab, and `swarm.sh lead <run> list`,
show the finish (ready by the registers or what holds it, who coordinates it,
the boundary and the last prepare, the last check and what is late against the
report), the parked leads, and on
each lead its standing offer, a closure waiting for its closer's confirmation,
a second route with its reason and its product contract.

A source's broad extraction ([ADR 0013](adr/0013-a-negative-is-bounded-and-a-cap-pauses.md),
"A source's broad extraction before a negative on it") is on the record as
receipts on the store journal (`type: preparation`): planned, attempted,
produced, partial, failed or declined, each with the source's digest, the
recipe and its version, the output manifest and what the extraction does not
hold. One its pack runs by itself runs at the kickoff; every other is a lead
of its own, "Broad extraction: <recipe> over <source>", opened by the harness,
serving no question and not material, offered to an idle seat, which runs it
or closes it deferred or infeasible with why (the preparation's decline). A
negative that says the event did not happen, or whose coverage is complete
over a source, waits while that source's extraction is planned or attempted:
`finish status`, readiness and the answers check name it (`preparation_pending`)
with the job to wait for or the lead to run or decline. The extraction's
outcome releases it, whatever that is, and so does `swarm.sh question <run>
accept Q-n`. Any other negative on a source whose extraction has not
produced carries the warning `preparation_missing`, which holds nothing, and a
negative's review offer opens with the state of each source it rests on.
The receipts are lines of `store/journal.jsonl`, and `swarm.sh replay <run>`
shows each source's state and what it holds or warns.

#### The stop policy: `extend`, `pause`, `unpause`, `stop`, `resume`

`done` finishes a run, under every stop policy, only when every question in
scope has a disposition under the bar ([ADR 0013](adr/0013-a-negative-is-bounded-and-a-cap-pauses.md)):
established; partial; a bounded negative or not determinable, each on a
coverage record another seat reviewed; a premise shown not to hold; out of
scope; accepted by the operator; or withdrawn. A limitation that only names a
question is none, and neither is a best candidate (an answer that claims
established, every review of which holds it a best candidate only) or a quick
negative nobody attested: the finish line refuses `done` on them and says the
way to a disposition. Partial is a disposition whatever its reviews' strength. A question that must be established (the goal's `## Must establish`
section or `must_establish:` list, or `question add|amend --must-establish`;
see Questions below) takes only an answer that answers it (established, a
premise shown not to hold, or a bounded negative under the stronger bar),
your acceptance of its limits, or its withdrawal: partial, not determinable
and the rest do not end the run on it. Under `cap-pause` and `cap-stop` the
agents may still abandon the run (two seats' `abandon`, ending it
`abandoned`, never completed), so the requirement binds them fully only
under `--stop operator`. The stop policy decides who else ends the run: a cap pauses or
stops it and you stop it, whatever the questions' state.

A run ends one of six ways (`runOutcome`, `stop-policy.ts outcome`):
`completed` (every question established, or settled by a bounded negative that
says the event did not happen under the stronger bar), `examination_limited`
(a question not determinable, partial, out of scope, a bounded negative short of
that, accepted by the operator, or resting on limitations or deferrals),
`paused` (held at a
cap, at the model provider's limit, or by you), `stopped` (`swarm.sh stop`, or `cap-stop` at a cap; never
`completed`), `abandoned`, or `verification_unavailable`. The summary, the
report and the console say which.

- `extend <id> [--minutes N] [--tokens N] [--usd N]` adds to a going or paused
  run's caps (`--tokens` only where it has a token cap, `--usd` only where
  dollars are charged). A paused run whose caps then leave room goes on: the
  pause is lifted (kept in `budget.json` as `pauses`), the wall clock starts
  again where it stopped, and the watchdog wakes every seat once, where it was
  (through the hub in a microVM run). An extension that leaves the run over a
  cap is refused and changes nothing. On the board, the trace and the
  operator's record, and to the notify command (`extended`) when it lifts a
  pause. `cap <id>` changes caps too and lifts a pause
  the same way. A pause that is not a cap's (the provider's limit, your own
  hold) stays under an extension: `unpause` lifts it.
- A seat whose last turn ended in a provider error is prompted again by the
  watchdog, with backoff (each wait twice the last, up to half an hour): in
  an until-solved run for as long as it goes, under `cap-pause` and
  `cap-stop` three times per run of errors, within the wall clock. The seat
  tells the board once per spell of failed turns; the trace has every one.
- When the model provider refuses every live seat at once (a subscription's
  usage limit), the watchdog pauses the run, under every stop policy
  (`paused.reason: provider_limit`): when every live seat's last turn since
  the last lift ended in a provider error, and each of them is limited, told
  to wait 30 minutes or more or refused again after a retry. One seat's
  error never pauses the run, nor one seat's long wait beside the others'
  passing errors. While it holds, no seat is prompted, no model call goes
  out and the wall clock does not run. The harness tries again at the end
  the provider named, plus a minute (seats on one provider: the longest end
  any of them was told; on several: the earliest, when each was told one),
  or every 30 minutes when none is known; it wakes every seat, and pauses
  the run again if every seat is refused again, without charging the try to
  the wall clock. You are told once per spell (the notify command's
  `paused`, with `reason: provider_limit` and `until`), and the board once.
  A long wait holds every VM: to free the machine, `stop` the run now
  (custody seals it) and `resume` it after the limit lifts (the resume wakes
  the seats itself); `unpause`, or Unpause beside the pause in the console,
  tries again at once.
- `pause <id> [--why TEXT]` holds a going run under any stop policy: each seat
  finishes its step and goes idle, no model call goes out, nobody is prompted,
  and the wall clock stands (`paused.reason: operator`). `unpause <id>` lifts a
  pause whose cause is gone and the watchdog wakes every seat: your hold and a
  pause for the provider's limit always; a pause at a cap only when the caps
  now leave room, and otherwise it is refused with nothing changed (`extend`
  gives room). Both are on the board, the trace (`run_paused`,
  `run_unpaused`) and the operator's record.
- `stop <id>` on a run with no sentinel writes `done/STOPPED` (`{outcome:
  "stopped", by, at, why}`) before custody seals it: a stopped run is never
  read as completed.
- When nothing has yielded (no new finding, question disposition or coverage
  record) for 30 minutes (`SWARM_YIELD_MINUTES`), the watchdog proposes a stop
  (`SWARM_YIELD_JOBS=N` adds a count: N committed jobs with nothing yielded
  propose too; off by default, since on the recorded runs a burst of 20 jobs
  without a yield was ordinary work that yielded within minutes): an operator request of
  kind `decision` (`D-n`, with its `R-n`), with what is still open,
  on the trace (`stop_proposed`) and to the notify command. Nothing stops unless
  you act; another proposal comes only after a further window with nothing
  yielded. It is never an agent's vote.
- `resume <id> [--question TEXT]... [--questions FILE] [--why TEXT] [--as ID] [--skip-refused-questions]
  [--minutes N] [--tokens N] [--usd N] [--env KEY=VALUE]... [--no-start] [-- START OPTIONS]`
  continues a run that ended, the same run in the same sandbox on the same
  chains. It is refused for a running run (that is `extend`), a purged one, and
  a prepared run that never started. First the budget: the wall clock counts on
  from where the run stopped, the caps grow by what you give, and a resume that
  would still be over a cap is refused before anything moves. Then what marked
  the end (the sentinel, `done/STOPPED`, `ALL_AGENTS_DEAD`, the seats' done
  files and abandon votes) moves whole to `done/history/<k>/`, the first
  segment's VM records to `vm/earlier-<k>/` and its kept disks to `earlier-<k>/`
  beside the snapshots; each seat's last hand-off note or compaction summary is
  written whole to `inbox/<seat>/resume.md`, where its resume kickoff sends it
  first; and the resume is recorded in `budget.json` (`resumes`), the registry,
  the operator's record, the trace and the custody anchor beside the run (with
  each chain's length and head). The questions given are asked as analyst
  questions (`--why` defaults to "asked when the run was resumed"). Each is
  checked before anything moves, as its admission would check it: one the
  register would refuse (an `--as` nobody is enrolled under on this install,
  a question it holds already word for word, words it refuses) refuses the
  resume with nothing changed, naming the question and why;
  `--skip-refused-questions` resumes without it and says so. Without `--as`
  a question is this OS account's, with the operator's authority; `--as
  operator` is the run's operator when it was started with `--operator ID`. The run
  restarts with the options it was started with, which the kickoff keeps outside
  the run (`runs/resume/<id>.argv.json`, 0600, removed by `purge`; `runs/resume`
  and `runs/notify` are denied to a host run's panes wherever the guard can
  deny, as the reviews are). The notify command is taken from `runs/notify/`,
  never kept with the options; an `--env` value is kept only where no pane can
  read it, and elsewhere the resume refuses until it is given again
  (`--env KEY=VALUE`). A run from before that gives its options after `--`, and
  another number of seats is refused. Evidence on an image (`--inputs-image`)
  that the stop detached is attached again, read-only, and held to the
  manifest by every file's name and size before anything moves; the resume is
  anchored beside the run first of all, and one that cannot be is refused with
  nothing changed.
  `--no-start` prepares it only; a later `resume <id>` starts it as prepared.
  The next stop seals the continuation anew: a new custody verdict (the earlier
  one kept beside it) and a new draft release. `custody-verify` holds every
  earlier verdict the anchor names to the run as a prefix of its chains and
  prints each (`Earlier seal: … before a resume: holds as a prefix: …`);
  `releases --verify` verifies the chains each release binds with their own
  verifiers, and accepts a release whose ledger, attestations or disputes are a
  prefix of the run's only when the anchor records, after it, a resume at a
  boundary the verified chains hold. The report each release binds is kept at
  `release/bound/<sha256>` when the run is resumed, so an earlier release still
  verifies after the continuation writes its own report. A
  signed v1 stays untouched and valid for what it bound; the continuation's
  answers are adopted through a later version (`review --sign --amend-reason`).
  The console's run page has "Continue this run" (and Extend, and a paused
  run's notice, which names its reason and, at the provider's limit, the end
  the provider named, with Unpause beside it for a pause that is not a
  cap's) for the same commands. Its elapsed time leaves every pause out.

#### Questions: `swarm.sh question` and directives

A run's questions are in its question register (`questions/questions.jsonl`,
rendered in `questions/questions.md`; [ADR 0011](adr/0011-questions-are-a-register-with-their-askers.md)).
The kickoff seeds it from the goal: each question the answers check names
becomes `Q-<n>` (`Q-3` is the ledger's `question:3`), and each objective of an
`## Objectives` section becomes `O-<n>`. A goal may put its objectives in its
metadata block instead (`objectives:` followed by `- O-1: text` lines); the
kickoff writes them into the goal's `## Objectives` section. A goal with
objectives and no questions is open-ended: its first agents propose the
questions with `question_open`. Its premises, what the case takes as given
(whose device it is, who the subject is), go in a `## Premises` section or
the metadata block's `premises:` list (`- text [scope: questions 1, 2;
entities E; times 2024-01-01..2024-06-30]`, the scope optional): each becomes
`P-<n>`, a given ([ADR 0011](adr/0011-questions-are-a-register-with-their-askers.md), "Premises").
A goal with a case brief (a heading naming a brief, a scenario, a background
or a situation, a `--sections-in` brief, or words naming one) and no premises
is warned about at the kickoff and by `start --check`: its answers would hold
the brief's givens open as parts to prove. Designate what the brief states as
given (never what a question asks or tests) in the metadata block, or on the
run with `question <run> premise add`. The shipped goals under
`prompts/goals/` and the calibration generator's designate theirs. What a
question takes as happened goes in a `## Presumptions` section or the
metadata block's `presumes:` list (`- 7: the drive was wiped`, the question
as the goal numbers it): its answer tests that premise first, against "the
question's premise is not supported", and a review names that test
([ADR 0011](adr/0011-questions-are-a-register-with-their-askers.md), "What a
question presumes"). The calibration generator marks every question that
asks which, when or how of an event, whatever its truth. The questions that
must be established go in a `## Must establish` section or the metadata
block's `must_establish:` list (`[1, 3]`, or a line each, `- 1: why`, the
question as the goal numbers it): for each, partial, not determinable, a
bounded negative short of the stronger bar and out of scope do not end the
run, under any stop policy ([ADR 0013](adr/0013-a-negative-is-bounded-and-a-cap-pauses.md),
"A question that must be established"). The kickoff says which questions are
required (`Required:`), and warns of a name the goal does not number, which
requires nothing, and of a `must_establish:` key that names nothing;
`start --check` warns of the same before the run exists (a goal that numbers
its questions in a `--sections-in` brief under `inputs/` is read from the one
`--inputs` set; one it cannot read is not judged). The report's summary says
which questions were required, by whom and why, and which requirement was
released, by whom, when and why (a `must be established` chip beside each
one's status, and a line under the table). Its
items may be indented or not, and a list beside the goal's own section is
merged into it. A flag-only challenge is the case for it: its one question
is answered by the flag, never by a partial answer.

- `question <run> add --text T --why W [--objective O-n | --objective new --objective-text T] [--parent Q-n] [--materiality material|background] [--priority urgent --reason R] [--expects existence|value|narrative|timeline|list] [--completeness] [--presumes P] [--must-establish] [--hint REF [--hint-value V]]... [--attach REF]... [--suggest SEAT] [--deadline ISO] [--neutral T] [--submission TOKEN]`
  asks the running swarm a question. `--must-establish` (yours or an examiner's; refused on a background question) says only an answer that answers it ends the run on it: partial, not determinable, a bounded negative short of the stronger bar and out of scope do not, and every seat's header names it until it is established. `--presumes` says what it takes as happened ("the drive was wiped"): its answer tests that premise first, an established review of an established answer without that test is recorded best_candidate, and a partial answer without it is warned (`premise_untested`), never held; the console's question form has the same field. `--completeness` says it asks for a complete set (every file, all connections, a complete list); a question whose words say so ("every", "all", "each", "complete list") is marked so without it, and `amend --no-completeness` takes the mark off. Its established or partial answer rests on a coverage record naming the areas searched (allocated, deleted, unallocated, slack, secondary), or the finish line holds it. It is written to the chain first and acknowledged after (the last line printed is the JSON of the act: `q`, `rev`, `scope`, the event's `seq` and `hash`, and what was delivered); then posted from `analyst:<you>`, offered to the suggested seat for its first minute (`SWARM_QUESTION_OFFER_SEC`) or to the most suited idle seat, and ranked first in every agent's header. A hint says where to look (a ref such as `input:<path>`, or a path in the run); `--hint-value` after it records what the hint says as an open hypothesis in the ledger. `--submission` makes a retry the same question.
- `question <run> list [--json]` and `show Q-n [--json]`: every question, the triage queue and the clarifications waiting first; one question whole, with every revision, its offers, its leads, its answer and each signed act checked.
- `question <run> amend Q-n --expect-rev N [--text T] [--why W] [--neutral T] [--completeness | --no-completeness] [--presumes P] [--must-establish | --no-must-establish] ...`: `--presumes` alone changes what the question takes as happened and makes no new revision; otherwise a new verbatim revision, refused unless N is the revision now; the standing answer, which names the revision it answers (`question_rev`), is stale until it is recorded again for the new one. `--must-establish` requires an existing question to be established (a goal's too: after a run ended on a partial answer, require it, then `resume`); `--no-must-establish --why W` releases the requirement, and the register keeps who released it and why beside who required it. Neither makes a new revision. Your acceptance (`accept`, below) also disposes a question that must be established, for that revision and the answer that stood: the release for that answer, on the record.
- `question <run> priority Q-n urgent|normal [--reason R]`, `withdraw Q-n --why W`, `clarify-reply Q-n C-n TEXT`, `scope Q-n|L-n in_scope|excluded --why W`, `accept Q-n --as bounded|not_determinable --why W --expect-rev N`, `verify [--allowed-signers FILE] [--ca FILE]`. An acceptance takes a question's limits as they stand for that revision; it is refused while a lead under the question is still open (a route not yet closed) or its answer is a negative no other seat has reviewed, and any acceptance makes the run's outcome `examination_limited`. It excuses a partial store sweep, and evidence added before it (`evidence_stale`), never evidence added after it or the rest of the negative bar; its reply (`still_held`, and a line from `swarm.sh`) names what the finish line still holds on the question.
- `question <run> premise add --text T [--locator L] [--class given|supplied_assertion|proposition_under_test] [--entity E]... [--time FROM..TO]... [--for-question Q-n]... [--why W]`: a premise the case takes, its words verbatim, where they stand, and what it is about (entities, time ranges, the questions it applies to; each optional, none meaning everything). A given unless `--class` says otherwise: a given is not proved again and is never an open part; a supplied assertion (a client's or a witness's statement) is assumed as asserted, and the report says so; a proposition under test is examined like any claim. `premise revise P-n --expect-rev N --why W [--text T] [--locator L] [scope flags | --no-scope]` makes a new revision (answers citing the earlier one are warned, never rewritten); `premise admit P-n --as given|supplied_assertion --why W` admits an agent's proposal (`premise_propose`: a proposition under test until then); `premise withdraw P-n --why W`; `premise list [--json]` and `premise show P-n [--json]` read them, with the answers that cite each. Two standing answers that assume and contradict one premise revision over scopes that overlap hold the run (`premise_inconsistent`) until they are reconciled on the record: one revised, the finding that rebuts the premise named (the premise then comes to you as a request of kind `premise`: revise it, withdraw it, or `requests <run> answer R-n "the premise stands, and why"`; nothing waits on your answer), a scope narrowed, or an answer made conditional ("assuming P-n"). Neither side is forced.
- `lead <run> direct (--question Q-n | --new-question T --new-why W) --title T --why W --product P --acceptance A`: a directive, an unheld lead under a question with the product it is to make and what makes that acceptable. A directive is not signed (`--sign` is refused; sign the question it serves). Under a person's question no lead has framed yet, the first agent to claim it states the proposition and its negation.

Every act takes `--as ID` (an enrolled person: a claim) and `--sign` (signed
with that person's enrolled key in the namespace `dfirswarm-question`; the
passphrase or PIN on the terminal or on the descriptor `--secret-fd N` names,
as release signing takes it). On `accept` and `premise admit`, `--as` names
what is accepted or admitted as, and a second `--as` the person. Without `--as` the act is this OS account's on
this host, not enrolled, with the operator's authority. Who may do what: the
operator and an examiner add in scope (`--objective new` expands the case),
admit or exclude, amend, re-prioritise, withdraw and accept any question, and
designate, revise, admit and withdraw premises (nobody else does); an
analyst (`examiner enroll --role analyst`) adds questions, in scope inside an
objective and proposed otherwise, and amends, re-prioritises and withdraws
their own; a reviewer's question is a proposed review query; an observer
(`--role observer`) proposes. Neither an analyst nor an observer signs a
release. Each act is on the trace and on the operator's record twice: the
attempt, and the outcome naming the event. The console's Questions tab runs
the same commands, with the person the console session chose as `--as`; an
amend or accept form keeps the revision it was opened on until you refresh it,
and a proposed question is a full card, so a clarification on it is answered
before it is admitted. It shows the premises with the same acts on them, and
each answer's parts (established, or open with what bounds it), the premises
it cites and a part a review says it leaves out. A question that must be
established carries a mark and says who required it (the goal, the examiner,
the operator), when and why, or who released the requirement and why; the add
form has the field (`--must-establish`, a material question only), and a card
in scope has the action that requires it or releases it with why
(`amend --must-establish | --no-must-establish`, no new revision).

While the run's hub is up (a microVM run that is going) it is the register's
one writer: `swarm.sh` hands each act, prepared and signed here, to the hub's
admin socket, which checks and commits it. With no hub (a host run, or a run
that is not going) the command admits the act itself under the registers'
lock. The acknowledgement says which (`admitted_by`). `verify` fails on a
signature that does not verify, on one whose key this install's enrolment or
the `--allowed-signers` file names for someone else (`wrong-principal`), and
on any act that says it is signed and carries no signature. A question
withdrawn from the goal is no longer required by the answers check or the
finish line; questions admitted or amended into new work after the run's
done are follow-ups, which `resume` takes up as the continuation's work.

#### The report, the outputs and the code left behind

[ADR 0016](adr/0016-the-report-follows-each-question-and-the-outputs-carry-their-sensitivity.md).

**The report follows each question.** The report's §1 is one screen: every
question (the goal's, the agents', the ones a person asked, and those
proposed, excluded or withdrawn), with its standing, who asked it, its answer
by number, its leads by disposition, the operator's acceptance and its
tokens. §2 then follows each question from who asked it to what it cost: the
origin (the goal; an agent and the entry that raised it; a person, with name,
role, and whether the act was claimed or signed), why, every verbatim revision
and the neutral wording, hints, attachments with their provenance,
clarifications, the proposition its first lead tested and its negation, its
leads (a negative counted, a duplicate footnoted), the coverage that names
it, the result with its contrary evidence, the acceptance, its evidence gaps
and its cost; grouped as the goal's, asked during the run, emergent,
proposed, excluded and withdrawn, each with why it matters, and then the
questions in scope no answer settles. A chain also says how strongly other
seats hold the answer (established, or a best candidate, with what capped
it) and where a person's question was offered, and each lead its offers and
what became of them, its hand-offs, its product contract, a confirmed
closure and its route review. §5 keeps each answer's steps. Appendix F
holds the whole register: every question and lead event — including an event
tied to no lead, an interpretation of a job's output, under its own heading —
each rendered whole as its fields' JSON so nothing is dropped, and every
disposition with who made it, what it cites and whether another agent
reviewed it; the negatives and duplicates the body counts are there in full;
and the finish register (the coordinator's lease, readiness, the checks, the
report's acks and their resolutions).

**Cost per question.** Each model call the model gateway recorded (input,
output and cache tokens) is given to the leads its seat held when the call
was made, split evenly among them, and each lead's share to the questions it
names, split evenly; a call made while the seat held no lead goes to what
it named (an attest or a dispute to the question of the entry it names, a
route review, a confirmation or a lead act to that lead, a record to the
questions it answers, a job's status to the job's lead; with the gateway,
what a call did is read from the trace rows that follow it), a finish call
or a write of the report to a line of its own, and a call that named
nothing to no question, on its own line by kind (waiting, compaction,
coordination, reading, other), so the figures add up to the run's total. A run without the gateway (a host run) spreads each seat's total over
its tool calls on the trace, an estimate the report calls one; a seat with a
budget the trace cannot place keeps its tokens in an explicit unattributed
bucket, so the total is still the whole budget. The per-question figures shown
are whole numbers apportioned by the largest-remainder method, so they sum to
the displayed total. It is an attribution by holding, not a measure of what a
question needed.

**A release binds the register.** `release.json` carries `questions`: the
length and head of `questions/questions.jsonl` as custody sealed them, the
questions those events opened by origin, every person who asked or acted on
one (enrolled, claimed or signed, with their questions), and the events
recorded after the verdict (`post_seal`), which the next release binds.
`releases <id> --verify` holds the chain to that head and recomputes the
rest. Custody holds the operator requests' chain to its seal too:
`custody-verify` names the operator's acts on requests after the stop as
following the sealed line, and a sealed line changed as a drift.

**Sensitive outputs.** `job_run(secret_output: true)` seals every output of
the job sensitive (its `job_committed` line and `job.json` say so, with why);
the harness never reads the bytes to decide. Derivation is read from the
snapshot a job's scope manifest recorded (each object's digest at the job's
start), so a job that executed against a sensitive output's bytes — by their
digest, wherever they sat: a work copy, a store blob, a catalogue link,
generation or alias, a directory scope — is sealed sensitive too, and it
carries through chains of jobs; a job declaring nothing whose command names the
sensitive job is derived. A generation of a sensitive output withholds its
coverage detail from the catalogue projection at the source. An entry citing a
sensitive output (`job:`, `sha256:`, `member:`) is recorded sensitive, and the
answer to `record` says so. The package side is above (`package --redact`);
`export --redact` treats an unmarked entry citing one as sensitive.

**A cancelled job's output.** An entry citing the kept output of a job that
was cancelled or stopped must say in `qualifies` how it treats what the job
wrote before it stopped; until a correction does, the answers check reports a
`partial_output` defect, which no limitation names away. A limitation, a
search recorded partial or failed, and a coverage record carry their own
disposition.

**The store sweep.** A coverage record names `looked_for`, the literal strings
a hit would contain were the answer in the evidence (or `looked_for_none_why`
when no literal form exists), and the hub then searches every output the run
holds for them: every sealed job output and job log, every import (evidence
added late included), every capture, every whole output kept under
`tool-output/`; not the input images. Case-insensitive for ASCII, in UTF-8 and
UTF-16LE, each file streamed whole, bytes and strings only. The result is a
line of `ledger/sweeps.jsonl` (chained, bound to the record's hash): clean,
hits (in objects neither the record's refs nor the outputs among its
result_refs name), or partial (what the budget did not reach, each named;
`SWARM_SWEEP_MAX_BYTES`, 16 GiB, and `SWARM_SWEEP_MAX_SEC`, 1800, set it). A
negative resting on the record waits for its sweep (`sweep_pending`); a hit
outside it holds the negative until the record is recorded again naming that
object, with what it showed, or the answer is revised (`sweep_hits`). What it
showed is an entry in the revised record's `result_refs`: a finding, an event
or a limitation whose refs name the object itself (not a directory holding
it), or one absence whose refs list several, written after the sweep that
found it. A hit object a record names with no such entry keeps holding
(`sweep_hits`, each object named, and the record's reply says so): naming a
hit is not examining it. A kept output and the import it was sealed as are
one object: naming either names both. A hit in an object made from the run's
own words is an echo, said on the line and holding nothing (ADR 0013,
"Echoes: authored, not derived"): a command that read only the run's
registers (a dump of the ledger), a summary the harness kept from a seat's
own words (a compaction), or a search whose own words name the string and
that read only the registers and named objects the sweep found the string
in. One made only from such named objects is said among the named hits. A
maker that read an input, anything else of the run, or paths that cannot be
told (a command naming none, a job that saw everything) leaves the hit
holding. A partial
sweep holds until the operator accepts the question's limits
(`sweep_partial`). A sweep lost with the process that began it is run again by
the finish gate and the answers check once its record is older than
`SWARM_SWEEP_ORPHAN_SEC` (120). The review offer, `ledger.md`, the report and
the metrics show each sweep.

**A downgrade.** A revision that moves an answer from established or partial
to not_determinable or bounded_negative carries `downgrade: {evidence:
[E-<seq> or objects], why}`, what undermines the earlier chain; without it the
revision is refused, and the refusal points to a dispute and a lower strength
or confidence instead. At least one entry of the evidence bears against the
chain (the answer and what it rests on): a finding or an event that
contradicts one of them (`rel` contradicts), a refuted hypothesis tied to one,
an entry it rests on under a dispute in force, or a correction of one. A
limitation or a coverage record does not. While a finding or an event the
earlier answer rested on for its question still stands (not corrected, not
disputed, contradicted by nothing), the revision is refused and the refusal
says to answer partial: a standing positive finding is never discarded to make
an answer not determinable. The report shows the earlier answer, the disputes
on it and the downgrade's evidence.

**Partial is a disposition.** "A best candidate" concerns only an answer that
claims established (its result established, or an answer from before results);
one that every review holds a best candidate only has no disposition, and it
holds readiness and the done under every stop policy. A partial answer, a
negative, out of scope and a premise shown not to hold are disposed by their
own bar whatever their reviews' strength. A review of a partial answer checks
the parts the answer claims: a part it declares open is held
`established: false` with `declared_open: "E-<seq>"`, the limitation it cites
or the coverage record it rests on for that part, and such a part does not cap
the review, nor does the answer's confidence.

**Tool candidates.** `tools <id> --candidates [--out DIR] [--min-lines N]
[--library DIR]...` takes the code out of every agent's command job (each
heredoc, each inline `-c`/`-e` script, the command itself, each script of the
agents' own under `work/` or `tool-output/` a job **ran as code** — an
interpreter invoked it, not merely named or copied it — read without following
a link and only when its bytes still match the snapshot the job read), keeps
those of N lines or more (20), counts the same text run by several jobs as one
candidate, and ranks them by lines times jobs. Output hygiene runs first: a
candidate from a sensitive job, or one whose text holds a sensitive value, is
withheld and named, its script never written. Each line says its job ids,
seats, image profiles, statuses and lines, how often it was reused, and the
library tools that may already cover it (the script names one, or its
manifest's `use` matches what the jobs declared; `--library` names the
libraries, the repository's `tool-library/` by default, beside the run's
`tools/`). Every non-withheld script is written whole to DIR (default
`<sandbox>.tool-candidates/`) with `candidates.json` and `README.txt`;
[tool-library/README.md](../tool-library/README.md#folding-a-candidate) says
how one is folded in.

**The library's hint.** A tool's manifest may say what it reads in `use`:
`extensions` (".evtx"), `magic` (`{offset, hex}`) and `names` (a file's own
name, `*` for any run). When an agent's command job declares its inputs, the
answer to `job_run` carries `library`: the run's tools that say they read
those files (by extension, first bytes or name; a manifest without `use` by
its description naming the extension as a word), each with what it matched.
A hint only: the job runs as asked, and a tool its command already runs is
not offered. It never holds the job: the inputs manifest is parsed once and
cached against its size and time, a bounded number of file heads is read, and
the hint gives what it has past a short deadline.

### `scripts/spawn.sh`

```
scripts/spawn.sh [--dry-run] [--no-start] [--sandbox DIR] [--n 1-30] [--model provider/id] [--label NAME]
```

`--dry-run` runs `tests/dry-run.test.ts`. Otherwise forwards to `swarm.sh start` with `--cap-usd ${SWARM_CAP_USD:-3}` and, when set, `--goal-file "$SWARM_GOAL_FILE"` or `--goal "$SWARM_GOAL"`; with neither, `swarm.sh` uses its default goal file. Env: `SWARM_N` (2), `SWARM_MODEL`, `SWARM_SANDBOX`, `SWARM_LABEL`, `SWARM_CAP_USD`, `SWARM_GOAL_FILE`, `SWARM_GOAL`.

### `scripts/watch.sh`

```
scripts/watch.sh [--once] [--sandbox DIR]
```

Sandbox from `--sandbox`, else `SWARM_SANDBOX`, else the repo `sandbox/`. Interval `WATCH_INTERVAL` (2 s). Uses `watch(1)` when present, otherwise a loop. Sections: `DONE`, `AGENT DONE`, `STALL / REAP` (`? <id>.dead`), `LOCKS`, `MAIN` (post count + last 40 filenames), `WORK` (`hello.txt`), `BUDGET`, `EVENTS` (last 16, humanised), `HERDR` (agent count by status + first 40 agents).

### `scripts/await-done.sh`

```
scripts/await-done.sh [--sandbox DIR] [--timeout SEC] [--interval SEC]
                      [--check-timeout SEC] [--quiet]
```

Defaults: `SWARM_SANDBOX` or `sandbox/`, `SWARM_TIMEOUT` 480 s, `WATCH_INTERVAL`
8 s, `SWARM_CHECK_TIMEOUT` 30 s. Each round runs `reap.sh --timeout
${REAP_TIMEOUT:-960} --quiet --stop` and `watch.sh --once`.

Exit 0 when `done/SWARM_DONE` exists **and** every check passes. The checks are
the backticked spans on bullet lines under `## Checks`, read from the goal as
the registry recorded it — not from `<sandbox>/SWARM.md`, which the agents can
reach. (If the sandbox has no registry entry — a hand-made directory, or a
custom `--sandbox` without the matching `SWARM_RUNS_DIR` — it falls back to
`SWARM.md` and says so on stderr.) Each check runs in the sandbox with stdin
closed and a time limit, so one that reads a FIFO an agent left behind cannot
hang the wait. `SWARM_HARNESS` names the harness in a check, for the checks it
ships:

- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,summary,narrative`
  reads the ledger's answers (`kind=answer`, ledger version 4): each named
  question (`question:1` …), the summary and the narrative has its standing
  answer, resting on a finding whose refs resolve, a complete search where
  the question asks whether something exists (`--existence 2,5` names those
  questions; for any other, a search that found nothing documents the search
  and the section is examination-limited) or a limitation; no answer has lost
  its support (an entry it rests on
  superseded or disputed since, transitively); a critic other than its
  author has attested or disputed each; and no contradiction stands that no
  answer weighs. Each defect is printed with its fix, and one that a
  limitation names lets the run end (the check still lists it).
  `--sections-in inputs/CASE.md` takes a brief's numbered questions. It does
  not ask how sure the swarm was, which would teach a swarm to say it is
  sure. With `--report work/report.md --sections 1,2,3` it checks a report
  instead, as goals did before version 4: each named section (`## 1.` …)
  cites (`#12`, `E-12`, `#10–#12`) at least one standing finding whose refs
  all resolve, or one search that found nothing (`kind=absence`, an answer
  only for a question `--existence` names; otherwise examination-limited),
  and names each section that does not, with why.

A failing check is not fatal: the swarm may still be working, so it keeps
polling until `--timeout`. Exit 1 on that timeout, or immediately when the
goal's checks cannot be read at all. A goal with no checks exits 0 on the
sentinel alone and says so.

### `scripts/reap.sh`

```
scripts/reap.sh [--sandbox DIR] [--timeout SECONDS] [--stop] [--dry-run] [--quiet]
```

Default timeout `REAP_TIMEOUT` 960 s. A pane Herdr reports as `working` is skipped. Exit 0 always (housekeeping), 2 on usage or missing `jq`/`team.json`. See [Observability › Reaping](observability.md#reaping-and-the--mark).

### `scripts/netguard.sh`

```
scripts/netguard.sh [--allow h1,h2] [--only LIST] [--allow-file F] [--port N]
                    [--mode auto|netns|proxy-only] [--log FILE] [--dry-run] -- CMD [ARGS...]
```

Default allowlist `api.openai.com,api.deepseek.com,api.x.ai,generativelanguage.googleapis.com` (+ `NETGUARD_ALLOW`). `swarm.sh start` adds the model's host (`anthropic/` → `api.anthropic.com`, `openrouter/` → `openrouter.ai`, others already listed). `--only` replaces the list. Port `NETGUARD_PORT` (3128; `swarm.sh` gives each swarm's sidecar the first free port at or above `SWARM_NETGUARD_PORT`, default 43178, so concurrent swarms never share a proxy). Mode `auto` picks `netns` when `unshare -rn` works and `lo` can be brought up, else `proxy-only` with a WARNING. `--dry-run` prints mode, allowlist, proxy and command. Exit 3 if the proxy fails to start or `--mode netns` was forced where unavailable.

### Calibration: `calibration/generate.py`, `scripts/calibrate.ts`

```
python3 calibration/generate.py --out DIR --truth-dir DIR [--seed SEED] [--cases LIST] [--force]
node --experimental-strip-types scripts/calibrate.ts <run-dir> --truth FILE [--out FILE] [--late auto|added|absent] [--json]
```

Synthetic cases whose answers are known, to measure how often a run says
"not found" about a fact the evidence holds (a deleted file, slack,
unallocated space, a rotated compressed log, two artefacts read together) and
how often it answers a question the evidence cannot answer (a near miss that
invites a guess, a false premise, evidence that was never collected). Three
cases: a USB drive image and a workstation's logs, a web server's logs, a
mailbox export and a browser history database. Each has a held-back evidence
item under `late/` that settles its missing question, for the operator to add
while the run goes on: `swarm.sh evidence <run> add <case>/late/<file> --why
TEXT [--for R-n]`, which the scorer tells by its digest on the store
journal's `evidence_added` line (`--late auto`). Python 3.8 and its standard library are all the
generator needs; the same seed gives the same bytes on any host (the history
database's page layout follows the host's SQLite version).

**The truth must stay outside the repository and outside every run.** The
generator writes it only to `--truth-dir`, and refuses a directory inside a
dfirswarm checkout, inside `--out`, or inside a run, before anything is
written. Without `--seed` a fresh seed is drawn and kept in the truth files
only. `calibrate.ts` refuses a truth file or an output inside the run it
scores or inside a checkout; its JSON goes beside the truth by default. It
reads the run's register (the ledger's answers, what they cite, the
attestations, the leads, the operator requests, and the question register and
the `result` and coverage fields where they exist), never a tool's output,
and reports the miss rate on present facts (the hard ones apart), false
negatives, the forced-answer rate, decoy adoption, unsupported negatives,
acquisition requests, the late item, the calibration of the stated
confidence, under-claiming (present questions answered partial with every
present fact found, each with its confidence) and, for each question that
expects `premise_not_supported`, whether its answer and its reviews carried a
premise test. Exit 0 when scored, 1 when a generated case's bytes do not hold
what its truth says, 2 on a usage error or a refusal. See
[calibration/README.md](../calibration/README.md).

### Metrics: `swarm.sh metrics`, `scripts/metrics.ts`

```
swarm.sh metrics <id> [--json]
swarm.sh metrics --compare <id-A> <id-B> [--json]
node --experimental-strip-types scripts/metrics.ts <run-dir> [--json]
node --experimental-strip-types scripts/metrics.ts --compare <run-dir-A> <run-dir-B> [--json]
```

How a run worked, read from its own registers, for cases with no ground truth
(the calibration cases above have one). Nothing is judged and nothing is
written: every figure is a count of named records, the JSON lists them (lead
ids, `E-n`, `Q-n`, `R-n`, job ids, seats, times, reason codes) so each can be
checked against the register it came from, and no free text a record carries
is copied into the table or the JSON: no answer's value, finding or command,
no dispute's why, no done's or stop's reason (the outcome is its class, who
and when). A register the run does not have is said to be absent, never read
as zero: each metric whose register is missing says "not recorded (no
<file>)", and its JSON object carries `recorded: false`; a run from before
offers has no offer events, one from before the reuse hints no `job_similar`
lines, one from before the finish register no readiness. Exit 0, 1 for an
unknown id, 2 on a usage error.

"The questions in scope" are, at the end of the run, the register's live
questions: in scope, not withdrawn, and not a follow-up admitted after the
run's done (`after_done`: a resume's work, not this run's; `Q.liveInScope`);
else the goal's, else the sections the ledger answers. A proposed or excluded
question is not in scope. The answer metrics count only questions in scope;
an answer still standing for a question since withdrawn, excluded or deferred
is listed apart as history (`negatives.out_of_scope`). A question is material
unless the register says background. "Standing" is at the end of the run: not
superseded by a later entry. A grant's status is read at the run's end, so a
finished run measures the same whenever it is read.

| Metric | What is counted, exactly |
| --- | --- |
| Quick negatives | Lead `close` events with disposition `negative` that the hub flagged `quick_negative` when it wrote them: the lead was held two minutes or less from its holder's take to the close, had at most one job, and that job's declared scope held at most one object (a job over everything is never quick). Each close counts, so a lead reopened and closed negative again counts twice; the flag is a review cue, not a defect. Out of every negative close. |
| Negative answers, reviewed | Standing answers of a question in scope that the finish gate holds as negatives (protocol.ts `negativeByResult`, the gate's own test): `bounded_negative`, `not_determinable`, and a `premise_not_supported` resting on a search alone (no standing finding it cites for its question shows the premise false). Reviewed: an `attest` carrying its review (detection, reproduction, another route), by a seat that wrote neither the answer nor a coverage record it cites, on the answer or on a standing coverage record it cites whose results still stand (protocol.ts `negativeReview`, the gate's own test). |
| Unreviewed negatives | The negative answers above that are not reviewed, split into material (these hold the finish) and background. Measured at the end, not at any moment during the run. |
| Store sweeps | Coverage records that name `looked_for`, by how their sweep (`ledger/sweeps.jsonl`) ended: clean, with hits in objects the record does not name (and how many hit objects, and how many echoes were named and hold nothing), partial, or pending (no line yet); the standing negatives in scope a sweep holds now (`sweep_pending`, `sweep_hits`, `sweep_partial`, with the coverage record); and the records with hits that a revision naming what the sweep found released (the revision's own sweep clean). |
| Confidence | Each standing answer of a question in scope, by the confidence its author stated and the one the run records (protocol.ts `recordedConfidence`): a high stands only on an established answer another seat attested established, naming the alternatives it weighed, why the evidence rules each out and the entries that show it; any other high is recorded medium. The answers recorded lower than stated are named, with the harness's reason. An answer recorded before the rule (no `confidence_rule` in its entry) keeps the confidence its author declared, and such highs are counted apart (`legacy`). |
| Under-claiming | The standing `partial` answers of questions in scope, those that carry parts, and each of those whose asked parts are all established: a part is asked unless a review of the answer marks it `not_asked`, a part a review names `missing` is asked and not established, and at least one part is asked (protocol.ts `answerPartsStanding`, the reading the report's plain line and the console show). Each is named with its counts (asked, established, open, open parts a review marks not asked). A partial answer without parts (one recorded before them) is named apart and counted neither way. What it measures is how often a complete answer is labelled partial on what the question does not ask; the answer itself stands as recorded. |
| Limited parts | Each part a standing answer in scope holds at the limit of the evidence (`status: limited`), with its bound (`limited_by`) and whether a seat that recorded neither the bound nor the answer reviewed the bound as a negative is reviewed (protocol.ts `limitedBoundReview`). A limited part keeps its answer partial; this line says where the swarm judged a gap to be beyond the evidence rather than open to more work (docs/adr/0013, "A part at the limit of the evidence"). |
| Rival areas | The established attests recorded best_candidate because a located value's input was not covered where a rival could live (`rival_area_uncovered`), counted from the attests' recorded caps; and, across standing coverage records that name their areas, how many say each area `not_applicable`. A rise in either count against a comparable run is the sign to read the records (docs/adr/0013, "A locator is not coverage"). |
| Coverage records | Standing `coverage` records, each counted once: stale when a result it names no longer stands (by code: `missing`, `rebound`, `superseded` with the entry that replaced it, `disputed` with the seats that dispute it, never their words), else by the hub's computed field: `complete`, `partial`, or not computed (a record from before the field). A stale record is never complete, whatever its field says. Complete means the jobs behind it were given, by digest, every object it names; it never means the objects were the relevant ones. Reviewed, as the finish gate counts it: an `attest` with its review on the record, by a seat that did not write it, while its results stand; or an `attest` with its review on a negative answer resting on the record that the gate holds reviewed (the review of the negative is the review of its search). Both are given apart. |
| Negatives on partial coverage | Negative answers none of whose standing coverage records is complete and current (each is shown as partial, not computed or stale), and, apart, those that cite no coverage record at all. |
| Offers | Lead offers (`offer` events) by what became of each while it stood (from the offer to the lead's next claim, release, close or reopen), one outcome each, the first that applies in this order: accepted (a `claim` or `confirm` that names the offer), declined (`offer_decline`), taken by another seat (that next claim was another seat's, lapsed or not), lapsed (`offer_lapse`), else no outcome. By reason too (wake, hand-off, parked, reopen, confirm). Question offers: made, accepted (`offer_accept`), declined, and not taken up. A run from before offers has none; its `wake` events are counted apart: taken by the woken seat (its first claim of the lead in that open spell), by another seat, or not taken. A woken seat's claim is not the same measure as an accepted offer: a wake reserved nothing. Review offers (a limiting route's review, a material negative's review, `reason: route_review | negative_review`) are counted apart (`reviews`): taken up by the review they asked for (recorded by the seat offered, even after its offer ran out), declined, withdrawn (`offer_withdraw`: reviewed by another route, or the answer superseded), lapsed, or with no outcome; and how many their seat took first (`offer_take`). |
| `done` calls | Every `done` line on the trace, and every `done_deferred` line (a seat's done that was not its finish: another seat coordinates it). Accepted: a done line with no refusal (and, of those, the one that wrote the sentinel); refused by the seat's checks, by why (the finish line not met, posts that landed after the report, the finish line unsettled, an abandon vote that did not end the run); refused by the hub (a `markDone` the hub refused: the seat saw a thrown error and wrote no done line; a refusal the hub counted and wrote once is that many calls); not the seat's finish. A done after the sentinel (a seat leaving) is an accepted call that wrote nothing. |
| Finish | The finish's own acts ([ADR 0015](adr/0015-one-seat-finishes-and-work-is-offered.md), "Preparing the finish"). The first done that was a finish (not another seat's, not a seat leaving on its cap, not an abandon vote) and how it was answered, and whether it was refused on what was late against the report: the refusal `finish prepare` exists to remove (the goal's checks run only after it, so whether they would have passed is not in the trace; replay reads that on the registers). Every done refused on late items. The finish tool's calls by act (prepare, resolve and how many of those carried items, status, ack), so a refusal renamed into more calls cannot pass for a gain; the register's resolutions, the batches they came in and its checks. From ready (the tail's) to the end: the minutes, every seat's tokens in that span (from the same per-call record as the cost; none without one) and the finish's calls in it, through the done that wrote the sentinel. |
| Warnings delivered | From the trace, each reply to a record, an attest, or a lead's close or confirmation that carried a warning, by act, and the warning codes they carried; from the lead register, each review of an answer offered and delivered to its seat (`offer_seen`), which leads with its source-first packet. Every finish status carries the warnings too (the finish's status calls). What the warning points and the packets cost, counted rather than assumed. |
| Tail | From when the run was ready to its end (the sentinel's time, or the operator's stop). Ready is, where the finish register records readiness, the last turn to ready before the end that was not undone before it (a done that passed while readiness had not turned ready records the ready state itself, and the tail says so: "recorded by the done"); otherwise the moment every question in scope had its first answer. Two more tails are given apart, because they are not the same: from every question's first answer (any result, supported or not), and from every question's final answer (the one standing at the end). None while a question in scope has no answer; the unanswered are named. |
| Acquisition | Operator requests of kind `acquisition`, by the stage each ended at (requested, authorised, collecting, received, validated, declined, unavailable), and those the case policy declined at once. A gap is a request that did not end validated (declined, unavailable, or still waiting), with the questions it named. Evidence added: the store journal's `evidence_added` lines, and how many answered a request. |
| Interpretations | The lead register's `interpret` events, each bound to the entry it names: valid while that entry stands, otherwise on a superseded or on a disputed entry, or on none the ledger holds (the job needs interpreting again). Lead jobs never interpreted at all, and those with no valid interpretation left, are named. |
| Reversals | A standing result that changed: an answer superseded by one of the same question with another `result` (a correction that keeps the result is counted apart, as a correction), and a lead closed negative that was reopened. The cause is new evidence when an `evidence_added` line came between the two (or the reopen's cause is `evidence_added`), and discoverable in the original evidence otherwise. A heuristic: evidence that came between is not proof it caused the change. Apart: each answer that claimed established and was recorded partial after an attest of it was capped (`partial_after_cap`, with the seats that capped it), what the review rule's caps cost ([ADR 0015](adr/0015-one-seat-finishes-and-work-is-offered.md), "A source-first review"). |
| Cost per question | Each call's tokens (input, output and cache, as `budget.json` counts them) and dollars, from the model gateway's log where the run has one, else the seats' Pi sessions, else each seat's total spread over its calls on the trace (`trace-estimate`), given to the leads its seat held when the call was made, in equal parts, and each lead's part to the questions it answers, in equal parts. A lead is held from its take to its release, close, reopen, hand-off or another seat's claim; a seat claiming what it holds keeps holding it. A call made while the seat held no lead is given to what it named (`named`: an attest or dispute to its entry's question, an act on a lead to that lead, a record to the questions it answers, a job's status to its lead); the finish's and the report's work made so is `finish_and_report`; calls that named nothing (`unheld`, with `by_kind`: waiting, compaction, coordination, reading, other), and parts of leads that answer no question, are counted apart; a call whose usage the provider did not report counts nothing. The same computation as the report's (`scripts/question-cost.ts`), shown with the same figures: the parts are kept exact until the end, then rounded to whole tokens and millionths of a dollar by the largest remainder (`roundParts`), so the questions, the unheld calls and the leads without a question add up to the run's totals. An apportionment, not a meter: a seat thinking about one lead while holding two is split evenly. |
| Duplicates | From the store journal: jobs whose `job_similar` line names another seat's similar job (not counting declared reproductions), and of those the exact repeats (the same command or the same tool and arguments over the same objects); `independent: true` jobs, and those of them that had similar work to compare with; `job_same_as` lines (files, bytes, and jobs every non-empty output of which is an earlier job's); typed recipe requests answered with an earlier job (`job_deduplicated`); and, from older runs, the retired shadow merge's `job_would_merge` lines. |
| Network | Requests and how the rules decided them (granted, denied, by each denial's code), operator items (and those still open), grants by status (granted, active, exhausted, expired, revoked), fetches, captures delivered (and complete), uses the fetch service refused, and contamination records. |

`--compare` reads two runs of the same goal after both ended, question by
question by section, each run over its own scope: its standing result and
the result's kind (it asserts: established or partial; a negative, as the
gate holds one; a premise a finding shows false; out of scope; or unknown, an
answer recorded before results, which is not guessed at), whether a negative
was reviewed, the coverage it cites (complete, partial, not computed, or
stale) and the operator's acceptance while it stands (`Q.acceptanceStands`;
one the question's amendment, new evidence or a replaced answer lifted is
shown as lapsed, and flagged). A question outside a run's scope is compared
as unanswered there, its old answer shown as history. The verdict is `agree`
(the same result), `class_differs` (the same kind in another class),
`disagree`, `unknown` (a side has no result class), or answered in one run
only. A negative the other run asserts is flagged, and so is a negative both
runs reached with no complete coverage that still stands: two runs of one
harness can share a blind spot, and their agreement is not confirmation.
When the two runs' questions in scope differ in number or text, it says so
and still compares by section. A partial answer whose every asked part is
established is marked on its side and flagged, and the summary gives each
run's under-claiming count (the metric above), side by side.

### Replay: `swarm.sh replay`, `scripts/replay.ts`

```
swarm.sh replay <id> [--checkout PATH] [--compare [A [B]]] [--stop-policy P[,P...]] [--deliveries] [--prepare-as STATE] [--reverse-sweep] [--resweep] [--presumes Q[,Q...]] [--json] [--show-text]
node --experimental-strip-types scripts/replay.ts <run-dir | id --registry FILE> [the same options]
```

A finished run's registers read again under a harness's finish rules, to
measure a rule change on recorded histories before paying for new runs
(ADR 0017, "Measuring a rule change"). No model call, no job, no VM.

- **The run is never written.** It is copied to a temporary directory, a
  clone where the file system makes one (APFS, a reflink; elsewhere the copy
  costs the store's size), with the times kept. Left out: `inputs/` (the
  evidence, whose hashes `inputs.json` keeps), the VMs' records and images,
  the seats' Pi sessions and the kickoff's options. Every link in the copy is
  removed, never followed. The run's registers are hashed before and after,
  and a change is said. One copy per checkout and stop policy: the finish
  gate writes (it reopens leads on the ledger and runs a store sweep lost with
  its process, as it does at a done), and one evaluation never sees another's.
- **What is evaluated, in the order a done reads it**, each checkout in a
  process of its own: the answers check (each `check-answers.ts` line of the
  goal's checks, read as `await-done.sh` reads them from the registry record,
  run as its own function); the finish gate over it and the finish line's
  verdict; readiness; the finish register (the coordinator, its resume
  segment and how many posts it carries, what is late against the report,
  the coordinator's prepares, the resolutions and the batches they came in,
  the last check recorded); the report's standing for
  each question (its status, and whether its chain says a best candidate);
  and every custody verdict the run holds (`custody.json`, one a resume set
  aside, the ones the anchor beside the run names), verified as a prefix of
  the registers with the checkout's own chain code. The goal's other checks
  are its own commands, which no harness version changes: they are not run,
  and the verdict reads them as passing.
- **What it prints**, per question: its declared result, the check's outcome
  and disposition, whether it is held a best candidate, the codes of its open
  and named defects, of its warnings and of the readiness items on it, the
  gate's disposition, and the report's standing. Then readiness, the gate's
  defect codes, the verdict (proceeds and how the run would end, or held and
  on what), the finish (whose, what is late, whether the done would write the
  sentinel now), the seals, and where readiness, the answers check and the
  gate disagree on a question (`readiness_holds_disposed`,
  `readiness_clear_held`, `gate_holds_check_disposed`, and a run whose
  readiness is not ready while the gate holds nothing). A route limitation
  that readiness holds under `--stop operator` only limits the done, by
  design (ADR 0015, 7 and 8), and is not counted a disagreement. An answer
  the check reads as answered while one of its own defects holds it (an
  absence negative held on its source's broad extraction), and a question
  the gate reads accepted while the check holds a defect on it, are held by
  the finish line through the check, and counted held. Where the checkout reads
  the store journal's preparation receipts, each source's broad extraction,
  capability by capability, and the questions held (`preparation_pending`)
  or warned (`preparation_missing`) on it, with their sources. Where the
  checkout has the source-first review rule (ADR 0015, "A source-first
  review"), how many established attests of answers that claim established
  the run recorded, and each the rule would cap, by question, answer, seat
  and codes (`no_discriminator`, `locator_unverified`,
  `derivation_unverified`), and each it would warn and not cap
  (`no_locator_or_derivation`, `warned`; a checkout before the Fable review
  of the limits branch capped it): the recorded
  strengths stand, this says what the rule would have done at each attest
  (a locator into an input cannot be read in the copy, which leaves the
  evidence out, and says so). Where it reads the reverse sweeps (ADR 0013,
  "Late evidence: the reverse sweep and the delta"), each evidence
  addition's, its passes read as one: its state, how many standing
  coverage records and strings it searched for, how many objects it read, and per question the hit objects
  and occurrences, never a string. Each coverage record's store sweep, by
  its latest line: the hits, the named hits and the echoes, counted. Where it has the review carry rule (ADR
  0015, "A review carries over"), the report's reviews replayed over its
  versions in `history/`: the acks, the re-reviews of a later version and
  how many the rule finds standing already (each recorded ack read as a
  review of the whole report, and as the what-if in which each seat named
  the sections of the questions it answered), the section reviews the
  re-reviews covered against those the rule asks again, per reviewed
  version how many sections changed and how many seats are asked again,
  and the resolved late posts that announced their author's ack a moment
  after it (within two minutes). Counts and seats, never a section's words.
- **Values-free by default**: codes, ids, counts and the harness's own words,
  never a record's text (no answer, finding, lead title, reason or post).
  `--show-text` adds the harness's lines whole, which quote records; it is
  off unless asked for. `--json` gives the same as data.
- **Which rules.** This checkout's, or `--checkout PATH`'s (a worktree at a
  commit: `git worktree add --detach /tmp/x <commit>`). `--compare` evaluates
  two and names every difference: with no argument, the run's own harness
  against this checkout (or `--checkout`); with one, that checkout against
  this one; with two, the first against the second. `frozen` names the run's
  own harness: the hub directory's frozen host copy while it is there, else
  the commit its registry record names (`provenance.harness_commit`),
  extracted from this repository with `git archive` into the temporary
  directory (no worktree is made). A run whose commit is not in this
  repository's history is refused, with how to give it instead.
- **`--stop-policy`** evaluates the copy as though the run's stop policy were
  each one given (`operator`, `cap-pause`, `cap-stop`; several with commas):
  the copy's `budget.json` only.
- **`--deliveries`** reads where the checkout delivers the answers check's
  warnings (ADR 0013, "Warnings where the decision is made"), act by act:
  the reply to every record of a question's answer, every review offered
  for an answer (read when it reached its seat), the reply to every attest,
  and the reply to every seat's close or confirmation of a lead. Each act's
  registers are cut to the moment of the act in a scratch directory beside
  the copy (the ledger to the answer's own seq for its record, the
  attestations to the attest's own line, the lead register to a close's or
  a confirmation's own lines, every other register to the act's time: a
  chain cut at a line is a prefix of it), and the
  checkout's own `warningsAt` says what that point carries then; finish
  status is read at the end. It prints the acts read, each act that carries
  a warning (the point, the entry, the seat, the questions and the codes)
  and finish status; `--compare` names the difference point by point. A
  checkout from before the delivery says it delivered in finish status only.
- **`--prepare-as STATE`** asks what a run from before the receipts would
  have met under the preparation hold: this checkout's census asks the run's
  packs' broad extractions (by id, as this checkout ships them) about the
  run's own evidence, read in place through a scratch sandbox whose
  `inputs/` links to the run's and never written; each copy then gets, per
  source and capability that applies, a synthetic receipt by `replay` in
  STATE (planned, attempted, produced, partial, failed, declined; one its
  pack says the images cannot run is declined), and is evaluated as usual.
  It prints what applied, and what could not be asked (a pack this checkout
  does not ship, an input with no digest, a run whose evidence is not here).
- **`--reverse-sweep`** asks what a run from before the reverse sweep would
  have been told at each evidence addition: each addition in a copy that has
  no reverse sweep line gets the one this checkout's store sweep computes
  over the copy's import, from the coverage records standing at the
  addition, marked synthetic, on the copy's chain. Only for a checkout that
  reads version 2 sweep lines (one from before would read the chain as
  broken): its copy is left as it is, and the output says so.
- **`--resweep`** reads each coverage record's recorded store sweep again
  with this checkout's rules (ADR 0013, "Echoes: authored, not derived"):
  each recorded hit whose object the record names under another name of the
  same bytes (a kept output and its sealed import), or whose makers make it
  an echo or a reading of what the record names, is moved, and the record
  gets the result as a synthetic line on the copy's chain. Nothing is
  searched again; a sweep where nothing moves gets no line. It prints how
  many sweeps moved hits, how many hits there were and are, and how many
  went to the named hits and to the echoes. Without it, a checkout that
  records the sweep's rules version on each line reads a line recorded
  under older rules again under its own at its answers check, in the copy,
  as a hub that starts does (ADR 0013, "Re-reading after a rules change"):
  the store sweeps' counts say how many (`reread`).
- **`--presumes Q[,Q...]`** asks what the premise rule (ADR 0011, "What a
  question presumes") would have said of a run from before it: each question
  named is amended in every copy, by this checkout's register as the
  operator would amend it, to presume "the event question <n> asks about
  happened" (synthetic words); a question the register does not hold is
  named. Each partial answer none of whose tests covers the premise is then
  warned (`premise_untested`), and the review rule names each recorded
  established attest it would cap for it; the recorded strengths stay the
  run's. A checkout from before the rule reads the amendment as nothing.

Exit 0 when replayed and the run's registers are unchanged; 1 when a
checkout could not be evaluated, the run changed under it, or it was
refused (the reason on stderr); 2 on a usage error. Replay measures
decisions on a recorded history; what the agents would have done under the
other rule is not in it, and a rule that changes their behaviour is measured
by paired runs.

The contract fixtures (`tests/fixtures/contract/`, written by
`generate.ts` there) are synthetic histories made through the harness's own
acts, each with an `expect.json` written by hand from the ADRs. The tests
(`tests/contract-fixtures.test.ts`) replay each and hold it to that, and to
three invariants under every fixture and stop policy: readiness, the answers
check and the gate never disagree on a disposition; a warning never holds;
every custody verdict verifies as a prefix. A fixture recorded before a
rule may keep its history and name, in `rules`, what the harness before the
rule reads in it (`evidence-stale-without-delta`, under c34c6cb), and the
test runs that harness, extracted with `git archive`, beside this one; every
history recorded before the source-first review and the delta is replayed
under both, and reads the same but where the delta applies. A fixture that names its
`deliveries` is replayed with `--deliveries` and held to each act's warnings
too, and finish status to the answers check's. A rule change that moves a
fixture's projection changes its `expect.json` in the same commit, with the
ADR that says why.

#### Kickoff goldens

`tests/kickoff-goldens.test.sh` runs `swarm.sh start --no-start` for three goals and compares what the kickoff writes with the files under `tests/fixtures/kickoff/<case>/`: `SWARM.md`, the system prompt, the budget, the team, the case policy, the inputs manifest and the questions. Before the comparison it replaces what only the machine or the moment decides with a placeholder: the run's id, the paths, the times, and the host's guard and facts. A change to the kickoff, whether to the template, a goal, the prompt or the policy, therefore fails it until the goldens are written again in the same pull request:

```
GOLDENS=update bash tests/kickoff-goldens.test.sh
```

and the diff of `tests/fixtures/kickoff/` is the change, as the agents will read it.

#### A pull request's impact line, and the rule register

`node --experimental-strip-types scripts/replay-impact.ts <base-commit>` replays every contract fixture (`tests/fixtures/contract/`) under the base commit and under this checkout, and prints each difference as a table: a fixture, a section, what differs, and each side. CI runs it on every pull request against its base and writes the table to the job's summary. A difference is what the change reaches, never a failure; the fixtures' own expectations are what the tests hold.

`node --experimental-strip-types scripts/rules.ts --write` regenerates [the rule register](rules.md): every coded rule of the ledger with the functions that raise it, the design that states it, and the tests and fixtures that exercise it. `--check` says whether the committed file is current and names any rule without a test or fixture, a design section or a place it is raised; `tests/rules-register.test.ts` holds both. A change to a rule changes that file, so it shows in the diff.

`bash scripts/merge-prep.sh` writes the register and the kickoff goldens again, and seals every pack that differs from main, when a branch is brought up to date with main; it resolves a conflict in any of them rather than leaving it to be edited, and stages what it wrote (CONTRIBUTING.md, "Bringing a branch up to date with main").


### `npm` scripts

| Script | Runs |
| --- | --- |
| `npm test` | every node suite under `tests/` (`scripts/test-node.ts` finds them by name; `tests/node-tests.skip` names the few it leaves out, the VM suites), the Pi loader suite among them, which skips where Pi is not installed. Each test has five minutes (`--test-timeout`; on Node 22 each suite file as well), so a test that waits forever fails by name; `npm test -- --test-timeout=N` sets another |
| `npm run test:bash` | every shell suite through `scripts/test-bash.sh`, one verdict per suite (`scripts/test-bash.sh reap inputs` runs a subset) |
| `npm run test:server` | web API tests only |
| `npm run typecheck` | `tsc -p tsconfig.json` (the extension against Pi's own types, the scripts, every node test) then `tsc -p ui/tsconfig.json` (the React client) |
| `npm run ui:build` / `ui:dev` / `ui:preview` | Vite build to `ui/dist` / dev server on 43174 with `/api` proxied / preview |
| `npm run ui:server` | `scripts/ui-server.ts` on 43173 without the build step — it still serves `ui/dist` if one is there |
| `npm run ui:fixture` | Seed five fixture swarms into `runs-fixture/` |
| `npm run swarm` / `watch` / `spawn` / `ui` / `dry-run` | Wrappers around the scripts above |

### The web app

The kickoff form's goal picker offers two shelves: the investigation library
([library/](../library/README.md), one goal document per kind of case, grouped
by category and read from the repo on every request, so an edit to a file is
what the picker offers next) and the operator's own goals (the files in
`prompts/goals/`, loadable, savable and deletable from the browser). Loading
replaces the editor, and edits you have not saved are asked about first; a
library entry may suggest a team size, a cap and a wall clock, which the form
applies only when asked. The model control switches between one model and a
mixed team. Each swarm has a **Goal** tab showing the goal document
and the rendered `SWARM.md` the agents read; the live contract is read-only, and
the way to change it is "edit a copy and relaunch". See
[docs/credentials-and-teams.md](credentials-and-teams.md).

Hierarchy is **swarms → threads → agents → traces**; kickoff, stop, reap and restore are our additions and labelled as such in the UI. Design language and states: `docs/ui-design.md`. Coverage against the console inventory and a live-run screenshot index: `docs/ui-coverage.md`.

| Screen | Route | What you see and can do |
| --- | --- | --- |
| Overview | `/` | Every swarm: model, N, spend/cap bar, tokens, calls, phase (running · done · stopped · prepared · failed; for a microVM run also **finishing** while its hub puts the VMs away, `finish_failed` when the hub could not, and `stop_incomplete` when a VM was still up after `stop`), elapsed; a strip totalling spend, tokens and calls across every swarm (with the running ones counted separately); status filters; card grid or table. |
| Kickoff | `/new` | Model picker (from `pi --list-models` when `pi` is on the server's `PATH`, else a static list, plus a custom field), USD cap, N slider, goal, **Playwright** and **Netguard** toggles, advanced label / wall clock / hard-kill / **Prepare only** (`--no-start`), and **Read-only inputs**: one set or several from `SWARM_INPUTS_ROOT` (a picker adds each, a chip removes it; one `--inputs` each) plus the kernel-guard choice (`--inputs`, `--inputs-enforce`). Shows the exact `swarm.sh start …` argv, then the job output, then navigates to the swarm. Also on the form: how the evidence is attached (copy with a size ceiling, bind in place, or a disk image), a clean room over earlier runs (`--no-read`), the tools of an earlier run (`--tools-from`), a required toolbox, and, with installs allowed, keeping the package index off the allowlist (`--no-pypi`). |
| Swarm detail | `/swarms/:id` | Header with live spend bar, remaining, tokens, calls, elapsed vs wall clock, badges (cap hit, violations, sentinel); **Stop** (confirm dialog → `swarm.sh stop`) and **Reap stalled** (`swarm.sh reap <id> --stall-sec N [--stop]`); full `SWARM.md`. |
| · Threads | `…/threads/:thread` | `main` plus agent-opened threads with creator; a thread is **dark** (hatched, moon mark) when idle longer than `SWARM_THREAD_DIM_MS` (default 2 min) or its last tag is `hold`/`veto`/`stop`; posts with tag, callsign, time (file mtime); a 48-bucket messaging-density timeline with violation ticks; claim violations inline. Under the list, **what the board adds up to**: posts and characters, who spoke and who never did, the span, the median gap and the longest silence; the tag mix for the team and per speaker; the matrix of who named whom; every hold / veto / stop including the harness's own; the paths the posts cited; and the three longest silences with the post that broke each. All of it counted from `threads/` — `GET …/posts` returns every post across every thread. |
| · Agents | `…/agents/:agent` | Callsign (heuristic from the first `intro` post), id, role, mark (● working · ✓ done · ? stalled · ? dead), the paths it holds (from the lock directory, so a just-expired one can linger a moment — the Claims tab filters by expiry), per-agent spend/tokens/calls and context-window occupancy, last activity text; search; agent detail = that agent's trace under ALL / MESSAGES / TOOLS / **THINKING** / FAILURES / SESSION ENDS. THINKING is set as prose — one wrapped block per turn — and when it is empty it says why: this model returned no reasoning anywhere in the run (naming the models that did), this agent alone was quiet, or nobody reasoned at all. |
| · Traces | `…/traces` | `events.jsonl` humanised, up to 1000 matching lines; filters by agent, tool, text; oldest-first by default, newest-first on request; **Show all** reveals the `inbox`/`budget`/`read`/`bash`/`wait`/`thinking` chatter; follow mode. A row opens **in place** — its arguments and result as fields underneath it, one row at a time, no dialog, with RAW and COPY for the exact record — and says so when the harness kept an opening rather than the whole argument. Long lists are paged (25 / 50 / 100 / 250). Each row carries its duration. A line written by the trace collector carries `prev`, the sha256 of the line before it; the report's custody section says whether that chain is intact. A trace that is there and cannot be read (a directory, a link, a failed read) is said so, with the reason, never shown as "No traces yet". |
| · Claims | `…/claims` | Live locks with TTL, `claim_violation` list (who, which file, whose lock), reaped agents, claim → work → release sequences per agent and path. |
| · Budget | `…/budget` | Cap vs spent, wall clock, per-agent usage table from `budget.json`. |
| · Files | `…/files/:path` | Opens with the read-only inputs when the swarm has them: source, every file, the guard measured per pane, healed writes, the final check. Then `history/` revisions per `work/` file with a viewer and **Restore** (operator claim → guarded restore → release → `file_restore` event; HTTP 409 while an agent holds the lock). |
| · Artifacts | `…/artifacts/:path` | `work/*.html` in a sandboxed iframe with scripts off (the page is served with a `Content-Security-Policy: sandbox` that does not allow them), SVG/PNG as images, text inline; `done.output_file` highlighted. An agent's page is shown, not run: with scripts it could navigate itself and carry what it holds to any host from the examiner's browser. |
| · Ledger | `…/ledger` | The ledger as a timeline, indicators, findings, searches that found nothing, hypotheses with their status and limitations with their reason; filters by kind, by text and by the question an entry answers; standing contradictions named at the top; a sensitive entry blurred until clicked; each entry's review (accept, reject, amend); the sign-off is the Release tab's. |
| · Jobs | `…/jobs` | Every tool job from the store's journal, read-only: what was asked and by whom, its state and steps, the image and profile it ran in, the files it sealed with their hashes, and its logs. |
| · Custody | `…/custody` | The verdict: every check with its status and what it covered, what it sealed, whether `custody.json` matches the verdict anchored outside the run, the signature and timestamp when they were taken, and the operator's lines. |
| · Release | `…/release` | The run's releases (v0 sealed by the machine and checked only as its seal; each adoption with its examiner, key kind and fingerprint, whether it was signed from the console or the command line and whether the consent was confirmed), what verify says without a register, every technical review in the report's wording, where the run ran when its agents could reach the signers' keys; and the adoption: an enrolled examiner, the prepared report in a frame with no scripts beside the sha256 of the bytes shown, the gate, the key, the consent box, the dialog for the secret. |
| · Technical review | `…/review` | The technical reviews with where each stands, a countersign for a record naming an enrolled reviewer, and the reviewer's form: the state the record will be over, the outcome, what was checked, the scope, the disagreements, the consent box and the secret. |
| Examiners | `/examiners` | Who is enrolled (role, key kind, whether the console signs with the key, a lockout) and the enrolment form: an ssh key made with a passphrase typed twice, a FIDO key made with a touch, or a token's certificate. |
| Jobs drawer | header **Actions** | Every start/stop/reap job with argv, exit code, captured output, link to the swarm. |

Live updates: the server watches the runs dir recursively and pushes `change` events over `GET /api/events` naming the swarms touched and, in `by_swarm`, what kind of thing moved under each (`threads`, `events`, `locks`, `budget`, `history`, `work`, `tools`, `ledger`, `names`, `inputs`, `contract`, `done`, `team`, `registry`); open views revalidate what they read. Writes the console cannot show, Pi's session files, the proxy and watchdog logs, the inbox cursors and the lock-table mutex, are dropped at the server. Header pill: `live`, `live · polling` (watcher unavailable), or `offline`.

API (JSON, same-origin — the `access-control-allow-origin: *` these routes used to carry let any page the operator had open read a run's board, trace, goal and spend): `GET /api/health`, `/api/inputs` (the sets under `SWARM_INPUTS_ROOT`), `/api/library` and `/api/library/<category>/<slug>` (the investigation library, read-only: metadata for the picker, and the document with its metadata block removed), `/api/goals` and `/api/goals/<name>` (the operator's own goals; `PUT` and `DELETE` need the token), `/api/models` (`pi --list-models` plus every local provider in Pi's `models.json`, keyless or not, under `local`), `/api/models/readiness` (one `pi auth check` per provider, cached 60 s; the kickoff form defaults to a model whose provider is ready and, under microVM, one the VM kickoff takes when there is one; a local server Pi will not list until it has a placeholder `apiKey` is reported as `status: "local"` with the fix, and a ready one carries `local: true`), `/api/jobs`, `/api/jobs/:id`, `/api/swarms`, `/api/swarms/:id?traces=N`, `/api/swarms/:id/threads/:thread`, `/api/swarms/:id/traces?agent&tool&q&limit&order=asc|desc`, `/api/swarms/:id/work`, `/api/swarms/:id/work/<path>` (raw bytes), `/api/swarms/:id/tool-output/<path>` (the whole output of a tool call whose result reached the model as a prefix, as a trace row's `full_output` names it; plain text, same symlink checks as an artifact), `/api/swarms/:id/history`, `/api/swarms/:id/history/rev?path&rev`; `POST /api/swarms` (`{model, models?, cap_usd, n, goal?, label?, wall_clock?, playwright?, net?, allow_hosts?, provider_hosts?, netguard?, hard_kill?, tool_forging?, self_compact?, compact_notice_at?, compact_warn_at?, compact_at?, compact_model?, inbox_page_chars?, inputs?, inputs_attach?, inputs_image?, inputs_max_mb?, inputs_enforce?, no_start?, cap_tokens?, cap_per_agent?, catalog?, toolbox?, toolbox_required?, quarantine?, case_id?, examiner?, allow_install?, no_pypi?, tools_from?, no_read?, packs?, isolation?, image?, vm_cpus?, vm_memory?, vm_disk?, vm_snapshot?, allow_oauth_in_vm?}` → 202 job; `self_compact` is on unless `false`, the three lines are token counts or percentages of the ceiling with optional per-model overrides (`60%,openai/gpt-5.4-mini=55%`), sent only when set, `compact_model` is a `provider/id` for every summary call (refused with the feature off) and `inbox_page_chars` a whole number of characters of post text per `inbox`/`wait` delivery (0 for no bound); `net` is `guarded`, `hosts`, `open` or `local` (`--local-only`); `cap_usd` may be 0 only with `cap_tokens`, which is how a team that bills nothing is started; `inputs` is a set name, resolved under `SWARM_INPUTS_ROOT` on the server; the case settings map to `--cap-per-agent`, `--catalog`, `--toolbox`, `--quarantine`, `--case-id`, `--examiner` and `--allow-install`, `catalog` needs `inputs`, `toolbox` is `dfir`, `crypto`, `linux` comma-separated or `auto` or `off`, and a `cap_per_agent` above `cap_usd` is refused; `models` is a mixed team (`provider/id=count,…`) in place of `model`; `provider_hosts` are `provider=host` entries, one `--provider-host` each; `inputs_attach` is `copy` (the default, sent as `--inputs-copy` in a microVM run) or `bind`, `inputs_image` a `<set>/<file>` disk image in a set (macOS), `inputs_max_mb` a ceiling for the copy; `toolbox_required` and `no_pypi` map to their flags; `tools_from` is a run id and `no_read` up to ten run ids, both turned into directories on the server; `packs` are installed pack ids; `isolation` is `microvm` (the default, as the command line's) or `host`, always passed on as `--isolation`, and `image`, `vm_cpus` (1–99), `vm_memory` (MiB, at least 512), `vm_disk` (MiB, at least 2048), `vm_snapshot: false` (`--no-vm-snapshot`) and `allow_oauth_in_vm` are refused with `isolation: "host"`, `inputs_enforce` other than `auto` without it), `POST /api/swarms/:id/stop`, `POST /api/swarms/:id/reap` (`{stall_sec?, stop?}`), `POST /api/swarms/:id/history/restore` (`{path, rev}`); SSE `GET /api/events` (`hello`, `change`, `job`). Signing (scripts/ui/signing.ts): `GET /api/examiners`, `GET /api/runs/:id/release`, `GET /api/runs/:id/release/pending/<nonce>/report.html` (the prepared bytes, served with no scripts), and `POST /api/examiners/enroll` (`{kind: ssh|fido|pkcs11, role, name, organisation, competence, id?, passphrase, passphrase_again}` for ssh, `{fido_verify_required?, fido_resident?, pin?}` for FIDO, `{pkcs11_module, pkcs11_id | pkcs11_uri, pkcs11_chain?}` for a certificate), `POST /api/runs/:id/release/prepare` (`{examiner, pdf?, amend_reason?}`), `/release/seal` (`{nonce, shown_sha256, examiner, secret, consent: true}`), `/release/discard` (`{nonce}`), `/review/technical` (`{reviewer, outcome, checked, entries? | all_answers?, disagreements?, reviewed_at?, secret, consent: true}`) and `/review/countersign` (`{reviewer, seq, secret, consent: true}`); each POST needs the token even when `SWARM_UI_TOKEN` is empty, a loopback Host, the console's own Origin and a JSON body, is refused while a host-mode run is live, runs its script directly (never as a job) and answers 423 while the person is locked out.

### Writing a goal

The goal is a markdown document. It says what to build, how the team should
split it, when the work is finished, and how to check that. `swarm.sh start`
frames it as `SWARM.md` — adding only the team, the caps and the bail-out — and
refuses to start without a `## Definition of done`. For an investigation, start
from the library: [library/README.md](../library/README.md) is the contract the
published cases converged on (the questions, the seven ground rules, the
division of work, the definition of done, the standard checks) and every entry
there keeps it.

```markdown
## Goal

Draw a pelican riding a bicycle as `work/pelican.svg`: one self-contained SVG,
no external assets.

## Definition of done

`work/pelican.svg` is valid XML, renders with no console errors, and two
different agents have signed it off on the board by its content hash.

## Checks

- `test -s work/pelican.svg`
- `python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('work/pelican.svg')"`
- `grep -c '^approved ' threads/main/*.md | awk -F: '{n+=$2} END {exit !(n>=2)}'`

## How to divide the work

Slices that divide cleanly: bicycle geometry, pelican anatomy, palette and
scene, render-and-measure tooling, adversarial verification. Check `claims`
and take an unclaimed one.
```

Rules that make goals work with this harness:

1. **Name the artifact and make the checks runnable.** Each backticked span
   under `## Checks` is run in the sandbox by `await-done.sh`; every one has to
   exit 0 before a run counts as finished. Prose bullets are for the agents and
   are skipped. Write the checks so they fail closed, and test them by hand
   before you trust them: `ids=$(jq -e …) && …` rather than
   `for id in $(jq …)`, which passes when `jq` fails, and
   `grep -l … *.md | wc -l` rather than `grep -rlc …`, which on BSD grep
   prints both a count line and a filename line for the same file and so
   counts one sign-off as two.
2. **Say how to split the work.** Peers coordinate on the board, not through a
   planner. A list of slices that divide cleanly gives them a first move and
   avoids the pile-up on one file at boot.
3. **Ask for review explicitly if you want it.** The harness assigns no roles.
   "One of you verifies and signs off by content hash before anyone calls done"
   is a sentence in the goal, not a flag.
4. **Keep the bail-out.** It is in the frame for a reason: the agents in the
   Hugging Face incident write-up had no safe exit from impossible tasks and
   "rarely gave up". If your goal contradicts it, the frame still wins.
5. **Keep the cap tight.** Start at `--cap-usd 1` for N ≤ 3. The 10- and
   30-agent runs in [verified-runs.md](verified-runs.md) spent $0.19 and $0.73
   under a $3 cap; spend scales with N, so raise the cap with the team, not
   before.
6. **Use the verification tools you enable.** With `--playwright`: "render
   `work/index.html` and post `console_errors` before calling done."
7. Under 256 KiB (`SWARM_GOAL_MAX_BYTES`); label `[A-Za-z0-9_-]{1,40}`.
