---
id: encryptor/traces
title: Reconstructing encryptor execution, deployment and affected files
when: Establishing what executed, under which security context and on which assets.
needs: [scope/first-hour]
tools: [encrypted_survey, ransom_note_scan]
requires_host: [yara]
mentions: [mft_records, usn_journal, prefetch_mam, amcache_apps, regkv, evtx_query]
---

Build an evidence chain from deployment to execution to file modification, and say
which links the evidence supports. A surviving binary helps; its absence does not
show that it was deleted, and does not rule out a reconstruction from what else
remains.

**Filesystem evidence.** Preserve the suspected binary or script, its original
path and source-object identity, its configuration, staging files and deployment
lists. On NTFS look at the relevant MFT records and any change-journal records.
An MFT timestamp is not a general deletion time. A retained USN record can support
a deletion event; rollover, record reuse and an incomplete collection limit what
survives. If the windows-forensics pack is loaded (check the run's tool
inventory), `mft_records` and `usn_journal` read them, `prefetch_mam` and
`amcache_apps` read the execution artefacts below, and its skills
(`execution/overview`, `logs/remote-access`, `logs/powershell`) carry the
per-artefact limits: read those rather than a summary of them here. Where it is
not loaded, say that these artefacts were not examined.

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

**Windows event evidence.** A System 7045 record shows a service installed, not
that it ran. Security 4698 and TaskScheduler 106 show a task created or
registered; look separately for records of its action running. Security 4688
depends on the audit policy, and a command line in it on a further setting. Record
the provider, channel, event id, record id and source host. Security 1102 records
the clearing of the Security log: do not expect it in every incident, do not read
its absence as evidence against cleanup, and look at other clearing records,
interrupted collection, retention and central copies. Clearing can also be
authorised administration. `evtx_query` and `regkv`, where that pack is loaded,
read these; otherwise say they were not read.

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

**Samples and file effects.** Read and hash recovered code; never run it. No rules
ship with this pack: if `yara` is installed and the case supplies a ruleset, record
the engine version, the ruleset's source, revision and hash, the rule names and the
match locations. A match is a classification lead, not proof of execution or
attribution.

`encrypted_survey` names candidates and samples a few tails; its answer says what it
read and did not (`coverage`, `complete`). `ransom_note_scan` says where note files
sit, by name and content. Where a note sits shows where something wrote a note, not
which directories were encrypted. Check a repeated tail against the file's own
format, against independent files and against supported family research before it
means more than a coincidence. Note placement, renaming and encryption can each
occur without the others.

**Sensitive output.** `ransom_note_scan` reaches values that can carry access: run
it as a job with `secret_output: true`, cite a value by note id and offset, and never
write one, or a hash of one, into the ledger or the report.

**Does not show.** Service installation does not show execution; Prefetch absence
does not show no execution; a note's place does not show an encrypted directory;
a rule match does not show who ran what.

**Deliver** an asset-by-asset chain of deployment, execution and effect, with source
references, clock uncertainty, confidence and the competing explanations.
