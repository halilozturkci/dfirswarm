---
id: containers/docker
title: Docker evidence locations, layers and scope limits
when: Mapping supplied Docker metadata, logs, writable layers, volumes and host relationships.
needs: [triage/system-profile]
tools: [timestamp_decode, linux_triage, journal_export]
requires_host: [fls, icat]
---

A container is not a machine and its evidence is not in one place. Before choosing paths, establish the
runtime, its version, rootful or rootless mode, the configured data root, the storage driver or snapshotter and
the logging driver, from the daemon's configuration and the evidence. The layout below is an example for a
classic `overlay2` installation, not a universal one:

    /var/lib/docker/containers/<id>/
        config.v2.json       image, command, environment, mounts, created and started times
        hostconfig.json      privileged, capabilities, the host paths mounted in
        <id>-json.log        stdout and stderr with timestamps, for the json-file logging driver only
    /var/lib/docker/overlay2/<layer>/diff/      a layer's own files
    /var/lib/docker/image/overlay2/repositories.json     which image each id names
    /var/lib/containerd/, /var/lib/containers/, a user's home for a rootless runtime     other runtimes, other layouts

Read a file out of an image with `fls` and `icat`, or from an extracted tree. Inventory the writable layers,
image content, named volumes, bind-mounted host paths, runtime metadata and every configured log destination;
a volume or a bind mount holds files the layer does not. For containerd and Podman take the storage locations
and the metadata schema from their configuration, not from Docker's layout. For Kubernetes correlate the pod
UID, namespace, container id, node identity, kubelet records and any retained control-plane audit records,
and record what lies outside the acquired host as a gap; if the cloud pack is loaded, its Kubernetes audit skill
holds the API-server side. `linux_triage`'s `containers` family reads `container.logs` and nothing else: it
gives no configuration, layers, volumes or runtime state, so read its function status and do the rest by hand.

**Layers.** An OCI or Docker image-layer archive represents a deletion as a `.wh.<name>` entry and an opaque
directory as `.wh..wh..opq`. A native OverlayFS upper directory uses filesystem objects and extended
attributes instead (as the kernel documents them, a character device 0/0 and an opaque attribute on the
directory), with details depending on the implementation. Preserve xattrs, device metadata and layer order,
and map the container to its actual upper layer and lower chain before reconstructing a view. A copy-up
changes the host inode's metadata without showing when anything ran in the container.

**Timestamps and commands.** `Created`, `StartedAt` and `FinishedAt` and the `Path` and `Args` are runtime
metadata whose meaning depends on the stored schema and the restart history: they are not a complete execution
history and not evidence that a command achieved its purpose. Keep each original timestamp string with its
offset and any missing or zero value, and decode with `timestamp_decode` only a number. `Config.Env` often
carries credentials: inspect it, the mounts and the credential configuration in a sealed job run with
`secret_output: true`, and report the variable names and that values exist, not the values.

**Host exposure.** Assess privilege from user namespaces, capabilities, device access, mounted sockets, the
security module's policy and host bindings together. `Privileged: true`, a `Binds` entry for `/` or the
daemon's socket, or `CapAdd` of `SYS_ADMIN` each establish potential access from the container. Actual
compromise of the host needs evidence the access was used, so look for it before calling the host
compromised.

**What is not there.** A disk image holds no process memory and no live `/proc`; those need an acquisition of
their own. Removing a container (a `--rm` run, for one) removes its active metadata and writable layer, but
other evidence can survive: volumes, bind mounts, rotated or remote logs, snapshots, orchestration records,
deleted filesystem remnants and the daemon's own log. Read the daemon's log from the evidence with
`journal_export` and `unit: "docker.service"` (never the analysis host's own journal), and check which logging
driver was in use: a `json-file` path does not cover the other drivers or the CRI log formats. Name the
retention and the missing sources before stating a bounded negative, and do not let a missing Docker
directory clear the other runtimes.

**Does not show.** That a container ran a command because a start time is recorded, that a risky
configuration was exploited, or that the writable layer is the whole story.

**Sensitive output.** Container environments and mounts can hold credentials; `journal_export` and
`linux_triage` outputs can hold command lines. Keep them in `secret_output` jobs and cite the file and key.
