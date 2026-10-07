# Linux Forensics Pack

What a Linux examination needs: where each artefact lives, what it shows and does not show, what parses it,
and the traps that make an answer wrong.

Depends on the Computer Forensics Base Pack, which carries the method that is true of any platform.

## What it carries

**Ten skills**, in eight families.

| Family | Skills |
| --- | --- |
| Triage | `triage/system-profile` |
| Logs | `logs/auth`, `logs/journal` |
| Accounts | `accounts/users` |
| Persistence | `persistence/mechanisms` |
| File system | `filesystem/ext`, `filesystem/storage` |
| Containers | `containers/docker` |
| Packages | `packages/integrity` |
| Timeline | `timeline/linux` |

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
`write_text` is asked, in a job, which is run with `secret_output: true`.

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
