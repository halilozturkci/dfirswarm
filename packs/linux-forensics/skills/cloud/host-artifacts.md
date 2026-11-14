---
id: cloud/host-artifacts
title: Cloud-host identity, provisioning and remote administration
when: A Linux host is a cloud instance: which instance, image or agent it was.
needs: []
card: journal_export {"path": "<the evidence's var/log/journal>", "unit": "<cloud-init or agent unit>"} dates cloud-init's stages from the evidence; never contact a metadata endpoint, the provider's API or an agent. Keep instance, image and disk identities apart: an instance id unlike the paperwork says imaged, cloned or restored, not tampered. Never run user data. Use a secret_output job; cite file and line. Does not show: who held the provider account, or what the provider logged.
tools: [journal_export]
requires_host: []
mentions: [cloudtrail_parse]
---

Use when the Linux evidence came from a cloud instance and its identity, how it was provisioned or how it was administered remotely matters. Not for the provider's own audit trail (the cloud pack, when it is loaded) or for the host's logins (`logs/auth`).

Never contact a metadata endpoint, the provider's API or a guest agent: every claim here comes from files the acquisition holds. Identify three things apart. The instance (its id, name and region or zone), the image it started from (an image id, a machine image name or a marketplace product), and the disk or snapshot the evidence was taken from. A copy of the disk of one instance, an image made from it and a new instance started from that image carry the same files and different identities, so find where the identity was written and when: `var/lib/cloud/` (the cloud-init instance id and the `instance` link), `var/lib/cloud/data`, `var/lib/cloud/instances/<id>/` and `var/log/cloud-init*.log`. An instance id in the files that differs from the one in the acquisition's paperwork says the disk was imaged, cloned or restored, not that anyone tampered with it.

Read cloud-init's data, logs and state as evidence and never run its user data or scripts: the user data of a first boot is a command source, so read it, list what it would fetch or install, and do not execute it. The datasource that cloud-init recorded names the platform; the vendor data and user data it kept say what the provisioning asked for, and its boot stages' times (in the cloud-init log, and `journal_export` for its units) say when the instance first booted and when it ran its later stages.

Remote administration has host-side records: the AWS Systems Manager agent, the Azure and Google guest agents and their logs under `var/log/` write what commands they were told to run. Read them as a second source of execution beside `logs/auditd` and the shell histories (`execution/history`); the command a person sent is in the provider's trail, which is not on this host. If the cloud pack is loaded, `cloudtrail_parse` reads the AWS side; its rows and the host's are two sources to put on one timeline.

Shows: which identity the disk recorded and what provisioning data and agents wrote on it. Does not show: who held the provider account, that a command reached the host from the console, or what the provider logged. Record: each identity value with its file, the cloud-init stages and times, the agents found and the logs read.

Sensitive output: user data and agent logs can hold keys and tokens. Keep `journal_export` in a `secret_output` job and cite the file and line, never the value or a hash of it.
