---
id: containers/layers-times
title: Container layers, runtime metadata and times
when: Reading overlay layers, whiteouts, config timestamps, commands and environments.
needs: []
card: container_layers {"overlay2_root": "<overlay2 directory>", "start": "<layer directory>"}: map the container to its real upper layer and lower chain first. A missing lower layer cuts the chain (partial); opaque_directories_not_told_in_layers names layers whose lost xattrs hide an opaque directory, so lower contents may show as visible. A copy-up moves host inode metadata without showing when anything ran. Created, StartedAt, FinishedAt, Path and Args are runtime metadata: keep each original string with its offset; timestamp_decode is for a raw number. Config.Env: names and that values exist, never values. Does not show: an execution history, or when anything ran inside.
tools: [container_layers, timestamp_decode]
requires_host: []
---

Use only if you read a container's layers or its runtime metadata. Not for locating the evidence (`containers/docker`), for what a removed container leaves (`containers/removed-logs`) or for correlating runtimes and nodes (`containers/runtime-orchestration`).

**Layers.** An OCI or Docker image-layer archive represents a deletion as a `.wh.<name>` entry and an opaque directory as `.wh..wh..opq`. A native OverlayFS upper directory uses filesystem objects and extended attributes instead (as the kernel documents them, a character device 0/0 and an opaque attribute on the directory), with details depending on the implementation. Preserve xattrs, device metadata and layer order, and map the container to its actual upper layer and lower chain before reconstructing a view; `container_layers` builds it from an explicit chain or overlay2's `lower` files, naming the layer that supplies each path and what each layer did to it, and says when an extraction lost the opaque attribute. A copy-up changes the host inode's metadata without showing when anything ran in the container.

**Timestamps and commands.** `Created`, `StartedAt` and `FinishedAt` and the `Path` and `Args` are runtime metadata whose meaning depends on the stored schema and the restart history: they are not a complete execution history and not evidence that a command achieved its purpose. Keep each original timestamp string with its offset and any missing or zero value (`timestamp_decode` is for a raw number; an RFC 3339 string needs no decoding). `Config.Env` often carries credentials: inspect it, the mounts and the credential configuration in a sealed job run with `secret_output: true`, and report the variable names and that values exist, not the values.

Shows: the layer chain and the runtime's own recorded metadata. Does not show: a complete execution history, that a command achieved its purpose, or when anything ran inside the container (a copy-up moves host metadata). Record: layer order, xattrs, each original timestamp string with its offset, the variable names.

Sensitive output: environments, mounts and credential configuration; names and the fact that values exist, never the values.
