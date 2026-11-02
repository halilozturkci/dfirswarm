---
id: containers/runtime-orchestration
title: containerd, Podman and Kubernetes nodes
when: Correlating a container across runtime stores, node logs and a control plane.
needs: []
tools: [container_inventory, container_layers]
requires_host: []
---

Use when containers ran under containerd, Podman or Kubernetes, or under several runtimes on one host. Not for Docker's own file layout (`containers/docker`) or for a container that is gone (`containers/removed-logs`).

Find the stores from configuration, not by habit: the rootful stores (`var/lib/docker`, `var/lib/containers/storage`, `var/lib/containerd`), rootless Podman under each home's `.local/share/containers/storage`, and a Kubernetes node's `var/log/pods/<namespace>_<pod>_<uid>/<container>/<n>.log` (CRI log format) with the kubelet's records. `container_inventory` reads Docker, Podman and CRI logs and says what it did not read: containerd's bolt metadata database is listed under `unsupported` and not read, and that is no statement that nothing ran under containerd. Check `storage_roots` when a data root was moved.

Correlate by identifiers, not names: the container id (the 64-digit id Docker and Podman use, the id in a CRI log's directory name), the pod uid and namespace, the image id and its layers. A pod directory gives the node-side view only; which workload asked for it, from which manifest and by whom is in the control plane's records (the API server's audit log), which are on this node only if someone collected them. Record what lies outside the acquired node as a gap. If the cloud pack is loaded, its notes hold the API-server side.

Keep volumes apart from the writable layer. A volume or a bind mount holds files the layer does not, and a layer holds what the container changed in its image. `container_layers` builds the view of an image's layers from an explicit chain or overlay2's `lower` files: the layer that supplies each path and what each layer did to it, with OCI whiteouts told from overlayfs native ones. A missing layer is named and makes the answer partial, and a copy that lost extended attributes cannot show a native opaque directory (the answer says so). CRI logs rotate by number under the kubelet's retention: say which rotation numbers exist before you call a log complete.

Shows: what the runtime and node files say was created, mounted and logged, and how the stores link. Does not show: that a container ran what its configuration says, which workload requested it, or anything held only by the control plane. Record: each store and its runtime, ids with their locators, the layers missing, the log rotations present, the gaps outside the node.

Sensitive output: environments, commands, mounts and log text can hold secrets and are lengths in the answers. Keep `container_inventory` and `container_layers` in `secret_output` jobs when you ask for text or copies. Cite file and key, never the value or a hash of it.
