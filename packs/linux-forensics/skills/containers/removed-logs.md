---
id: containers/removed-logs
title: Removed containers and the daemon log
when: A container is gone and you ask what else records it, including the daemon's journal.
needs: []
card: journal_export {"path": "<the evidence's journal>", "unit": "docker.service"} reads the daemon's log from the evidence, never this machine's journal; keep it in a secret_output job (command lines) and cite file and entry. Removing a container removes its metadata and writable layer; volumes, bind mounts, rotated or remote logs, snapshots, orchestration records and deleted remnants can survive. Check the logging driver: json-file paths do not cover other drivers or CRI logs. A missing Docker directory clears no other runtime; name retention and the missing sources before a bounded negative. Does not show: that a container never existed, or what ran in it.
tools: [journal_export]
requires_host: []
---

Use only if the container or its metadata is gone, or you need the daemon's log. Not for locating live evidence (`containers/docker`) or for correlating containerd, Podman and Kubernetes records (`containers/runtime-orchestration`).

**What is not there.** A disk image holds no process memory and no live `/proc`; those need an acquisition of their own. Removing a container (a `--rm` run, for one) removes its active metadata and writable layer, but other evidence can survive: volumes, bind mounts, rotated or remote logs, snapshots, orchestration records, deleted filesystem remnants and the daemon's own log. Read the daemon's log from the evidence with `journal_export` and `unit: "docker.service"` (never the analysis host's own journal), and check which logging driver was in use: a `json-file` path does not cover the other drivers or the CRI log formats. Name the retention and the missing sources before stating a bounded negative, and do not let a missing Docker directory clear the other runtimes.

Shows: which other sources may still record a removed container. Does not show: that a container never existed because its directory is absent, or what ran in it. Record: the logging driver, the retention, each source searched and the ones missing.

Sensitive output: the daemon's journal can hold command lines; keep `journal_export` in a `secret_output` job and cite the file and entry.
