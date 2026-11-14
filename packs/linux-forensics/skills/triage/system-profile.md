---
id: triage/system-profile
title: Linux system profile and acquisition
when: You start on a Linux target and must say what was acquired and what covers it.
needs: []
card: linux_triage {"source": "<image>", "out_dir": "work/<your id>/<name>"}: read every function's status; execution_complete is not coverage and empty is not absence. cron_dump and the other file readers need extracted files. Does not show: who used the machine.
tools: [image_layout, linux_triage, cron_dump, shell_history, utmp_parse, auth_log, journal_export]
requires_host: [target-query, target-fs]
---

Use when you begin on a Linux target. Not for the identity files and install date (`triage/identity-files`, only if you need them) or for zones and boot history (`triage/clocks-boots`, only if timestamps or boots matter).

Record first whether the evidence is a disk image, an extracted root, a logical collection or a memory capture, what was collected when, and whether volatile paths (`/proc`, `/run`, mount and process state) were captured; a disk image holds none. A collected tree is a selection, not a disk, and a memory capture needs symbols matching its kernel (the triage-collection and memory-forensics packs, when loaded). Read the release, architecture and filesystem features from the evidence, the release name only a start: whether `auth.log`, `secure`, the journal, auditd, classic wtmp or a SQLite accounting database exist is read from its files and configuration.

For a disk image read the catalogue first: its linux-target files (`catalog/README.md` says where) are `linux_triage`'s families over the whole image. Otherwise start with `image_layout`, then `linux_triage` as a job. It runs dissect.target's `target-query` one function at a time, reads a root inside LVM without mounting the evidence, and keeps each family's output and each function's stderr. Read each function's `status` and `coverage`: `execution_complete` says the processes exited 0, which is not coverage, and `parsed` says records came, not that the artefacts were all there. Treat an `empty` result as a parser's result, not as an absence. `cron_dump`, `shell_history`, `utmp_parse`, `auth_log` and `journal_export` read files, never the image: extract first in a job, `target-fs -q <image> cp <dir> -o "$OUT/root<dir>"` for each of /etc, /var/log, /var/spool/cron, /home, /root, then give them `store/jobs/<id>/out/root/...` (copies carry the extraction time, so `auth_log` needs `year` there).

Then: `triage/identity-files`, `triage/clocks-boots`, `accounts/users` and `persistence/mechanisms` (what was configured to run, apart from what ran in the incident window).

Shows: what was acquired and what its own files configure. Does not show: that a file was used (its presence or date shows configuration or last change); a hostname or machine id does not identify a host once images are cloned; nothing here shows who operated the machine. Record: the acquisition kind and time, the volatile paths captured or not, the function list, the dissect.target version and each status.

Sensitive output: `linux_triage`'s family files are bulk extracts (whole histories, authentication and journal lines, container logs) that can hold secrets, sealed as sensitive only if the job ran with `secret_output: true`. Read them by path and record; quote only what a question needs, never a secret, a fragment or a hash of one.
