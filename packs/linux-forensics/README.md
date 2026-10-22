# Linux Forensics Pack

What a Linux examination needs: where each artefact lives, what it shows and does not show, what parses it,
and the traps that make an answer wrong.

Depends on the Computer Forensics Base Pack, which carries the method that is true of any platform.

## What it carries

**Ten skills, fifteen second-level leaves and the router `linux/router`** (at most 400 tokens; the prompt shows this one line for the pack when the run's index is over its budget, and it names every leaf), in eight families. Each skill opens with a decision-rule note; a
second-level leaf (listed after it, opened only when its question arises) holds the reference material the first points to.

| Family | Skills |
| --- | --- |
| Triage | `triage/system-profile`; then `triage/identity-files`, `triage/clocks-boots` |
| Logs | `logs/auth`, `logs/journal`; then `logs/auth-lines`, `logs/auth-time`, `logs/journal-clocks-verify` |
| Accounts | `accounts/users`; then `accounts/sessions-histories` |
| Persistence | `persistence/mechanisms`; then `persistence/cron-timers`, `persistence/quieter-routes` |
| File system | `filesystem/ext`, `filesystem/storage`; then `filesystem/ext-deleted`, `filesystem/storage-lvm-luks`, `filesystem/storage-xfs-btrfs-virtual` |
| Containers | `containers/docker`; then `containers/layers-times`, `containers/removed-logs` |
| Packages | `packages/integrity`; then `packages/baseline` |
| Timeline | `timeline/linux`; then `timeline/linux-normalise` |

**Six tools.** Each answers with fields and locators (file, line or record, byte offset), says what it did not
read, and keeps the whole result in a file when the answer is a page of it.

- `auth_log` reads `auth.log` and `secure`, rotated and gzipped, record by record: ssh acceptances with the key type
  and fingerprint, failures, disconnects, sudo and su, PAM failures and sessions with their service. It says which
  year it applied to a stamp that has none, and on what basis.
- `utmp_parse` reads classic `wtmp`, `btmp`, `utmp` and `lastlog` in the layouts it names, says how it chose the layout
  and byte order, and refuses what it cannot tell apart. It does not read `wtmpdb` or `lastlog2` (SQLite).
- `shell_history` reads shell and client history files (bash, zsh, fish and plain client files) record by record,
  with how each record's boundaries were found, and does not call a directory name an account.
- `cron_dump` inventories cron tables and systemd timers as candidates, with what it looked in and what it did not.
- `journal_export` reads a journal from the evidence path and keeps every field: the complete native export, and a
  projection with the cursor and both clocks.
- `linux_triage` runs dissect.target one function at a time over a Linux image (including a root inside LVM) or an
  extracted root, and gives each function the status it earned.

**Sensitive output.** Command lines, sudo lines, cron environments and journal messages can hold secrets. These
tools answer without that text; it is written to a private file under `$OUT` only when `write_commands` or
`write_text` is asked, in a job, which is run with `secret_output: true`. What is withheld is chosen by its position in
a line the tool recognises (the name on an `Invalid user` line, a PAM `user=` or `ruser=`, a cron command, a journal message),
never by what it looks like; text in a place a tool does not mark as sensitive is not recognised by its shape.

**One recipe.** `linux-target` recognises a Linux disk and builds the `linux_triage` artefact files and a coverage
receipt that follows what each function produced; the base pack's `disk-volumes` recipe still supplies partition
tables, file lists and MAC timelines. It is the pack's broad extraction of a Linux disk (`purpose: broad_extraction`),
and its `exclusions` say what it does not hold: application data no selected plugin parses, deleted and
unallocated data, and encrypted volumes without their key. An empty plugin result never shows the artefact was
absent, and a detect step that could not read the OS does not close the route.

**Two goal templates**: `server-compromise.md`, `what-was-scheduled.md`.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/linux-forensics
    scripts/swarm.sh start --pack computer-forensics-base,linux-forensics ...

Host binaries are declared in `requires/host.json` and all of them are optional: the pack's own tools use the
standard library only (`journal_export` and `linux_triage` call `journalctl` and `target-query`), and each host
tool widens what can be read rather than being needed for the pack to work.
