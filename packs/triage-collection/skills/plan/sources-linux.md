---
id: plan/sources-linux
title: Linux sources to request, by question
when: You request more evidence from a Linux source.
needs: []
tools: [collection_index]
requires_host: []
---

Use when the delivery is Linux or Unix-like and a request needs concrete sources. Not for the request itself (`plan/what-to-collect`). macOS needs go to the macOS pack when it is loaded.

Compare each source with `collection_index`'s census of what you hold. Choose by the question and by how fast the source is lost. Identify mount points, namespaces, users and retention boundaries first. Paths are where each usually sits.

- Logs: persistent and rotated logs under `/var/log`, persistent journals under `/var/log/journal`, any preserved runtime journal (`/run/log/journal` is lost at reboot), audit records and the logging configuration that decides what exists.
- Accounts and privilege: `/etc/passwd`, `group`, `sudoers` and `sudoers.d/`, and each relevant user's shell histories and SSH metadata under `/home/*` (root's home is `/root`, outside `/home`).
- Persistence: system and user service definitions under `/etc/systemd`, timers, and cron configuration (`/etc/cron*`, `/var/spool/cron`).
- Software: package databases and their transaction logs.
- Containers and applications: the records of the runtime and logging backend actually in use. A list of Docker paths is not coverage of every container runtime.
- Secret-bearing files (private keys, password-verifier stores): only where the question and the authority justify them.

Shows: which sources could bear on a question. Does not show: that they exist, were retained or would contain a trace; an absent log is not an absent event.
Record: each source, the question, and the retention boundary you know of.
Sensitive output: `/etc/shadow` and key files hold verifiers and keys; read them in jobs with `secret_output: true`, report location, kind and what they grant, and never write a value or a hash of one.
