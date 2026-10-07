---
id: plan/sources-linux
title: Linux sources to request, by question
when: You request more evidence from a Linux source.
needs: []
tools: [collection_index]
requires_host: []
---

Use when the delivery is Linux or Unix-like and a request needs concrete sources. Not for the request itself (`plan/what-to-collect`). macOS needs go to the macOS pack when it is loaded.

Compare each source with `collection_index`'s census of what you hold. Choose by the question and by how fast the source is lost. Identify mount points, namespaces, users and retention boundaries first.

- Logs: persistent and rotated logs, any preserved runtime journal (`/run/log/journal` is lost at reboot), audit records and the logging configuration that decides what exists.
- Accounts and privilege: account and privilege configuration, and each relevant user's shell histories and SSH metadata.
- Persistence: system and user service definitions, timers and cron configuration.
- Software: package databases and their transaction logs.
- Containers and applications: the records of the runtime and logging backend actually in use. A list of Docker paths is not coverage of every container runtime.
- Secret-bearing files (private keys, password-verifier stores): only where the question and the authority justify them, read in jobs with `secret_output: true`.

Shows: which sources could bear on a question. Does not show: that they exist, were retained or would contain a trace; an absent log is not an absent event.
Record: each source, the question, and the retention boundary you know of.
