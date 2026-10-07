---
id: logs/powershell
title: PowerShell logs and script blocks
when: You are about to read PowerShell event-log records or quote a script block.
needs: []
tools: [evtx_query, regkv]
requires_host: []
mentions: [pwsh]
---

Use when the evidence holds PowerShell event-log records. Not for the interactive history file, encoded commands or an older engine (`logs/powershell-history`, only if you meet one of them).

Several kinds of record exist, enabled separately, none guaranteed: inventory what the image holds first. Keep Windows PowerShell 5.x apart from PowerShell 7 (`pwsh`): separate products with their own configuration and, in the event log, their own channel (look for `PowerShellCore/Operational`).

    Microsoft-Windows-PowerShell/Operational
        4104  a script block as the engine compiled it (ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal)
        4103  module and pipeline logging: a command with its bound parameters
        4105/4106  a block's invocation started and stopped, where that setting was on
    Windows PowerShell (the classic log)
        400/403  engine state changed (HostApplication, EngineVersion, HostVersion)
        600  provider started; 800  pipeline details, where module logging was on
    Transcripts, in the place the session or policy named

Script block logging, module logging and transcription are policy: read it with `regkv` from the SOFTWARE hive and each NTUSER.DAT (for example `Policies\Microsoft\Windows\PowerShell`, keys `ScriptBlockLogging`, `ModuleLogging`, `Transcription`). Without it an absent 4104 is a coverage question (`logs/coverage`). Read the Operational channel for 4104 even when logging was not established: the engine may log content it considers suspicious regardless of policy, which is not to be assumed for every build or after tampering.

- **Reassembling.** A long script arrives as several 4104 records. The pack has no assembler: group the rows of `result_file` by computer, ScriptBlockId, then MessageNumber, and compare with MessageTotal. Keep the record id and `record_offset` of every part, with duplicates and missing parts visible. A reconstruction with a part missing is partial and names the missing numbers. Do this per source log: ids from two machines or two log generations are not one sequence.
- **A 4104 shows** that the engine compiled this text, in this host, under this account (the Security `UserID` is in the XML). It does not show that every statement ran or succeeded: a function definition, a commented block and a script that failed at line one each produce one. Its Level is the engine's classing, not a verdict. Establish an action from the launch (4688 with a command line where audited, 400's HostApplication, `execution/prefetch`), the process's other records and the effect on the system.
- **Qualifiers of a negative:** script block logging shown on, off or not established; which profiles, transcripts and logs the case supplied.

Shows: engine-logged text and its host and account. Does not show: who typed it, intent, completion or effect. Record: file, channel, record id, `record_offset`, the policy evidence, the parts you hold.
Sensitive output: command lines and script text can hold a credential; run `evtx_query` here as a job with `secret_output: true`.
