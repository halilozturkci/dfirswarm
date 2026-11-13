---
id: encryptor/traces
title: Encryptor execution, deployment and affected files
when: Establishing what executed, under which security context and on which assets.
core: 1
needs: []
tools: []
requires_host: []
---

Use when you reconstruct how the encryptor reached and ran on each asset. Not for the artefact-level Windows records (`encryptor/windows-evidence`) or for samples and notes (`encryptor/samples-and-notes`).

Build an evidence chain from deployment to execution to file modification, and say
which links the evidence supports. A surviving binary helps; its absence does not
show that it was deleted, and does not rule out a reconstruction from what else
remains.

**Execution evidence.** Prefer records that describe the event being claimed:
process creation and parentage, the command line where it was collected, the
security token or account, the executable's identity and the file activity that
follows. Correlate a local record with central EDR or other telemetry kept
elsewhere. Prefetch can support execution where its format and collection are
understood, and its absence does not exclude one; the paths it lists are not proof
that each listed file was encrypted. Amcache and the compatibility cache support
presence or an inventory observation without proving execution; check what an
Amcache hash covers, in the build and parser in use, before comparing it with a
whole-file digest. UserAssist and BAM have limits of mechanism, account and
version, and neither names the person responsible.

**Changes before or around the run.** Correlate endpoint-protection changes, service
stops, task changes and recovery impairment with the account and process behind
them. A configuration change that was observed is not thereby malicious, successful
or the encryptor's; keep the earlier state where it exists and separate an attempt
from its effect.

**Deployment and spread.** Look at both ends: remote administration, service or task
deployment, policy changes and management-platform activity. PsExec, WMI and
legitimate remote-management products are possible mechanisms; a file name is no
conclusion. Include management, identity and central telemetry sources: imaging one
apparent source machine is not a spread investigation. These Windows artefacts do
not cover Linux, hypervisor or storage-appliance execution; ask for the matching
platform evidence and record the limit where its parser or collection is missing.

Only if the chain rests on NTFS records or Windows events (MFT, USN, 7045, 4698, 4688, 1102): `encryptor/windows-evidence`. Only for a recovered binary, a ruleset, tails or note placement: `encryptor/samples-and-notes`.

**Does not show.** Service installation does not show execution; Prefetch absence
does not show no execution; a rule match does not show who ran what.

**Deliver** an asset-by-asset chain of deployment, execution and effect, with source
references, clock uncertainty, confidence and the competing explanations.
