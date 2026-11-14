---
id: containers/docker
title: Docker evidence locations and scope
when: Mapping supplied Docker metadata, logs, layers, volumes and host relationships.
needs: []
card: container_inventory {"root": "<extracted root>"} lists an extracted tree's containers, mounts, layers, logs and images; linux_triage reads container.logs only. Volumes and binds hold files the layer does not. A risky setting is not evidence of use. Does not show: that a command ran.
tools: [container_inventory, journal_export, linux_triage]
requires_host: [fls, icat, target-fs]
---

Use when a container is in the acquisition. Not for layer and timestamp reading (`containers/layers-times`, only if you read layers or runtime metadata) or for removed containers and the daemon log (`containers/removed-logs`, only if the container is gone).

From the daemon's configuration and the evidence, establish first the runtime, its version, rootful or rootless mode, the data root, the storage driver or snapshotter and the logging driver. Below is an example `overlay2` layout, not a universal one:

    /var/lib/docker/containers/<id>/
        config.v2.json       image, command, environment, mounts, created and started times
        hostconfig.json      privileged, capabilities, the host paths mounted in
        <id>-json.log        stdout and stderr with timestamps, for the json-file logging driver only
    /var/lib/docker/overlay2/<layer>/diff/      a layer's own files
    /var/lib/docker/image/overlay2/repositories.json     which image each id names
    /var/lib/containerd/, /var/lib/containers/, a user's home for a rootless runtime     other runtimes, other layouts

Read a file out of an image with `fls`/`icat` or `target-fs`, or from an extracted tree. Inventory the writable layers, image content, named volumes, bind-mounted host paths, runtime metadata and every configured log destination; a volume or a bind mount holds files the layer does not. For containerd and Podman take the storage locations and the metadata schema from their configuration, not from Docker's layout. For Kubernetes correlate pod, namespace, container and node identities (`containers/runtime-orchestration`), and record what lies outside the acquired host as a gap. `linux_triage`'s `containers` family reads `container.logs` only. For an extracted tree `container_inventory` lists containers, mounts, layers, logs and images; do the rest by hand.

**Host exposure.** Assess privilege from user namespaces, capabilities, device access, mounted sockets, the security module's policy and host bindings together. `Privileged: true`, a `Binds` entry for `/` or the daemon's socket, and `CapAdd` of `SYS_ADMIN` are settings that can give a container access to the host; whether one did depends on the rest of that list. Calling the host compromised needs evidence the access was used.

Shows: how the container was configured and where its data sits. Does not show: that a container ran a command because a start time is recorded, that a risky configuration was exploited, or that the writable layer is the whole story. Record: runtime, data root, drivers, the locations inventoried and the gaps outside the host.

Sensitive output: container environments and mounts can hold credentials; `journal_export` and `linux_triage` outputs can hold command lines. Keep them in `secret_output` jobs and cite the file and key.
