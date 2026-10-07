---
id: triage/system-profile
title: Linux identity, deployment and acquisition profile
when: Establishing the target, storage, clock assumptions and evidence coverage before detailed analysis.
needs: [evidence/imaging]
tools: [timestamp_decode, image_layout, linux_triage, utmp_parse]
requires_host: [fls, icat, fsstat, dumpe2fs, target-query]
---

Everything later depends on what was acquired and on which clocks apply. Record, before anything else,
whether the evidence is a disk image, an extracted root, a logical collection or a memory capture, what was
collected when, and whether volatile paths (`/proc`, `/run`, mount and process state) were actually
captured; a disk image holds none of them. If the evidence is the output of a collection tool or a memory
capture, the triage-collection and memory-forensics packs hold the method for those when they are loaded
(check the run's tool inventory): a collected tree is a selection and not a disk, and a memory capture needs
symbols that match its kernel. Read the distribution release, architecture and filesystem features from the
evidence and treat the release name as a starting point: whether `auth.log`, `secure`, the journal, auditd,
classic wtmp or a SQLite accounting database exist on this system is read from its files and configuration,
not assumed from its name.

For a disk image start with `image_layout`, then `linux_triage`. It runs `target-query` (dissect.target) one
function at a time, reads a Linux root inside LVM without activating or mounting the evidence, and keeps
each family's complete output and each function's stderr. Read `groups[].functions[].status` and
`coverage`: `execution_complete` says the processes exited 0, which is not coverage, and `parsed` says a
function produced records, not that the artefacts were all there. Record the function list, the installed
dissect.target version and the statuses. Treat an `empty` result as a parser's result, not as an absence.

    /etc/os-release              distribution and version; fall back to the vendor's own files; note missing fields
    /etc/hostname                a configured name; correlate with logs and with cloud or VM identifiers
    /etc/localtime               a symlink into zoneinfo or a TZif file; /etc/timezone is optional and can be stale
    /etc/machine-id              set at first boot or by provisioning; a clone or a re-provisioned host duplicates or changes it
    /proc/version (if captured)  the kernel running at collection; installed kernels are another list
    /etc/fstab                   intended mounts, not mount state; captured mount information is separate evidence
    /var/log/installer/          installer logs where the distribution writes them
    /etc/network/, /etc/netplan/, /etc/NetworkManager/   configured addresses and DNS, not what was leased

Read these out of an image with `fls` and `icat`, or from an extracted tree, and keep each file's path and inode.

**Install date.** Do not pick the oldest timestamp among `/etc/machine-id`, `/var/log/installer/` and the
root filesystem's creation time (`dumpe2fs -h` on ext, `fsstat` elsewhere). They are different events:
filesystem creation, installer activity, machine-id provisioning and the first observed boot. Golden images,
cloned disks, restored backups and later provisioning separate them by months. Correlate installer and package
records with any cloud-init data, image or deployment metadata and first-boot logs; where those cannot tell
installation from deployment, say the installation date is not determinable.

**Clocks and zones.** Read the timestamp format and logging template of each source. Traditional syslog
omits the year and the offset; an RFC 3339 stamp may carry both; journal realtime is epoch-based wall time
from a clock that may have been wrong or adjusted. For a record with no zone, take the zone in force on that
date from the configuration and from corroborating records, not from `/etc/timezone` alone: it is today's
setting and says nothing of daylight-saving history. Decode a raw numeric stamp with `timestamp_decode`, choosing the epoch from the source's format. Apply one correction
per source, state which, and do not convert every artefact with one offset. Say in the report which zone and year you applied and to which sources.

**Boot history.** Build it from every source that has one: journal boot ids (`logs/journal`), the
`BOOT_TIME` records `utmp_parse` reads from classic wtmp, a SQLite accounting database (see
`accounts/users`), boot and shutdown logs, captured uptime, and hypervisor or cloud records. State each
source's retention and what was collected: wtmp is neither guaranteed nor exhaustive, and a reboot that left
no record in one source is not shown not to have happened.

**Sensitive output.** `linux_triage`'s family files are bulk extracts: whole histories, authentication and journal lines and container
logs, which can hold secrets, and they are not sealed as sensitive unless the job ran with `secret_output: true`. Read them by path and
record, quote only what a question needs, and never a secret, a fragment of one or a hash of one.

**Does not show.** A file's presence or date shows what is configured or last changed, not that it was used.
A hostname or machine id does not identify a host once images are cloned. Nothing here shows who operated
the machine.

Then the two lists everything else refers to: the accounts and their authorization, from `accounts/users`,
and what was configured to run, from `persistence/mechanisms`, keeping what was configured apart from what
the evidence shows ran in the incident window.
