---
id: containers/docker
title: Containers, and where the evidence actually lives
when: The host ran Docker, containerd or Podman and the incident touched one.
needs: [triage/system-profile]
tools: [timestamp_decode]
requires_host: [fls, icat]
---

A container is not a machine and its evidence is not in one place. On a dead
host, everything you need is under the runtime's own directory.

    /var/lib/docker/containers/<id>/
        config.v2.json       image, command, env, mounts, created and started times
        hostconfig.json      privileged, capabilities, the host paths mounted in
        <id>-json.log        stdout and stderr, with timestamps: the container's own log
    /var/lib/docker/overlay2/<layer>/diff/
        the writable layer: every file the container changed, as files
    /var/lib/docker/image/overlay2/repositories.json     which image each id is
    /var/lib/containerd/, /var/lib/containers/           the same idea, other runtimes

**The writable layer is the crime scene, but not a flat truth.**
`overlay2/<layer>/diff/` holds what that layer added or changed against its
lower chain. Whiteouts (`.wh.<name>`) and opaque-directory markers represent
deletions; reconstructing the final view needs `lowerdir`, `upperdir` and their
order from the mount metadata. Preserve inode times from the host file system,
but do not describe them as container execution times without corroboration.

**`config.v2.json` gives you the times and the command line.** `Created`,
`StartedAt` and `FinishedAt` are RFC 3339 UTC. The `Path` and `Args` are the
process that ran. `Config.Env` often carries credentials, and a reviewer will
ask whether you looked.

**`hostconfig.json` answers the question that decides scope.** `Privileged:
true`, a `Binds` entry mounting `/` or `/var/run/docker.sock`, or
`CapAdd: ["SYS_ADMIN"]` all mean the container could reach the host — so a
    compromise inside it gave a route to the host; prove whether it was used
    before calling the host compromised.

Two things that are not there. The container's own `/proc` and its memory are
gone unless the host was imaged live. And a container started with `--rm` leaves
no directory at all: its only trace is the daemon's log
(`journalctl -u docker`), the image pull, and whatever it wrote into a mount.
Also check rootless storage under each user's home, containerd snapshots under
`/var/lib/containerd`, Podman under `/var/lib/containers`, Kubernetes pod logs,
and rotated `*-json.log.*` files. A missing Docker directory does not clear the
other runtimes.
