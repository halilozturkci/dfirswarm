---
id: antiforensics/controls
title: Security-control changes and deleted VMs
when: An exclusion, disabled protection or deleted VM disk suggests a changed control.
needs: [antiforensics/traces]
tools: [regkv, evtx_query, evtx_carve]
requires_host: []
---

Use when an antivirus exclusion, a disabled protection or a deleted virtual machine disk points to a changed control. Not for the PowerShell logs themselves (`logs/powershell`).

- Observation: an exclusion added or protection turned off. Examine the product's operational events, its policy and configuration (exclusion and policy keys in the SOFTWARE hive, read with `regkv`), service events, process telemetry and PowerShell records (`logs/security`, `logs/powershell`). Separate a requested change from an effective one and from a blocked attempt.
- A console history file is optional, configurable and not an event log; its limits are in `logs/powershell-history`.
- Compare with approved administration (group policy, management software, installers) before attributing a change to an intruder.
- A deleted virtual machine: a recovered disk header names a candidate container; it does not show the logical sectors can be rebuilt. Inventory configuration files, hypervisor logs, snapshot and backing-disk chains and the extents that survive (`filesystem/carving`). Keep the mapping from recovered bytes to their source offsets, validate the container and the guest file system, and report missing extents and backing files.
- Attribute recovered guest events to the guest only when their structure and provenance support it; `evtx_carve` reads carved chunks, and a record still belongs to the channel it names (`logs/carving`).

Shows: a recorded change to a control, or a candidate guest disk with the extents that survive. Does not show: who made the change, that it took effect, or that the guest can be rebuilt. Record: the policy and event records with their times, the requested, effective or blocked state, the extent map of a recovered guest.

Sensitive output: `regkv`, `evtx_query` and `evtx_carve` can return command lines and script text; run them as jobs (`secret_output: true`); `regkv` withholds by name or place only.
