# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `acquire/images` Memory acquisition methods and their limits: The operator is deciding how to capture memory, or you must judge how a capture was made, what it covers and whether it can be trusted.
- `credentials/material` Credential material in memory, and how to handle and report it: An examination may expose credentials, keys, tokens or cookies in memory, or you must say whether credentials were exposed or taken.
- `network/state` Network objects, ownership and timestamp limits: You need connections, listeners or an address from memory, or an address to tie to a host artefact.
- `patterns/yara` YARA over files and reconstructed memory regions: You have case rules or a precise byte pattern to test against a memory image or a dumped process region.
- `processes/injection` Process anomalies and candidate code modification: You need what was running, or you are asked whether code was injected into a process.
- `strings/discipline` A string in memory is an observation, with its provenance: Any claim built on text found in a memory image.
- `triage/no-framework` What a memory image gives you when no framework can read it: The selected job image lacks a usable framework, its symbols or dependencies, or does not support the capture; or you want an answer before you configure one.
- `triage/volatility` Volatility with the right symbols, offline: You are selecting Volatility plugins, validating Windows, Linux or macOS symbols, or diagnosing an unsatisfied symbol or translation requirement.
- `triage/what-you-have` Verify and classify a memory capture before anything else: The evidence includes a memory image, a process dump, a crash dump, a VM's saved state, a paging file or a hibernation file.
