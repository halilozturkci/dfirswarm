---
id: logs/powershell
title: PowerShell logs
when: Event records and script blocks.
needs: []
tools: [evtx_query, powershell_blocks, regkv]
requires_host: []
mentions: [pwsh]
card: powershell_blocks {"path": "<Operational .evtx>"} groups 4104 parts by ScriptBlockId: report missing parts; text only with write_text (secret_output job). A 4104 shows compiled text, not that it ran. Does not show: who typed it, intent or effect.
---

Use when the evidence holds PowerShell event-log records. Not for the interactive history file, encoded commands or an older engine (`logs/powershell-history`, only if you meet one of them).

Several kinds of record exist, each enabled separately: inventory them first. Keep Windows PowerShell 5.x apart from PowerShell 7 (`pwsh`), which has its own configuration and channel (`PowerShellCore/Operational`).

    Microsoft-Windows-PowerShell/Operational
        4104  a script block as the engine compiled it (ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal)
        4103  module and pipeline logging: a command with its bound parameters
        4105/4106  a block's invocation started and stopped, where enabled
    Windows PowerShell (the classic log)
        400/403  engine state changed (HostApplication, EngineVersion, HostVersion)
        600  provider started; 800  pipeline details, where module logging was on
    Transcripts, in the place the session or policy named

Script block logging, module logging and transcription are policy: read it with `regkv` from the SOFTWARE hive and each NTUSER.DAT (`Policies\Microsoft\Windows\PowerShell`: `ScriptBlockLogging`, `ModuleLogging`, `Transcription`). Without it an absent 4104 is a coverage question (`logs/coverage`). Read the Operational channel for 4104 even when logging was not established: the engine may log content it finds suspicious anyway (not on every build, nor after tampering).

- **Reassembling.** `powershell_blocks` takes the `.evtx` file or the `result_file` of `evtx_query` and groups the 4104 records by source, computer and ScriptBlockId, in MessageNumber order: expected against observed fragments, missing numbers, duplicates, disagreeing totals, Path, Level, each part's record id and `record_offset`. No script text unless `write_text` in a `secret_output` job.
- **A 4104 shows** that the engine compiled this text, in this host, under this account (the Security `UserID` is in the XML). It does not show that every statement ran or succeeded: a function definition or a script failing at line one produces one too. Its Level is the engine's classing, not a verdict. Establish an action from the launch (4688 where audited, 400's HostApplication, `execution/prefetch`), the process's other records and the effect.
- **Qualifiers of a negative:** script block logging shown on, off or not established; the profiles, transcripts and logs supplied.

Shows: engine-logged text and its host and account. Does not show: who typed it, intent, completion or effect. Record: file, channel, record id, `record_offset`, the policy evidence, the parts you hold.
Sensitive output: command lines and script text can hold a credential; run `evtx_query` here, and `powershell_blocks` with `write_text`, as a job with `secret_output: true`. Describe a found secret by where it sits, its kind, length and what it grants, never its value, a fragment or a digest.
