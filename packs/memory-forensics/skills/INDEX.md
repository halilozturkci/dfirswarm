# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `acquire/images` Acquiring memory, and what the method costs you: The operator is deciding how to capture memory, or you must judge how a capture was made.
- `credentials/material` Credential material, and how to talk about it: You must say whether credentials were exposed or taken.
- `network/state` Network state, and what it proves about when: You need connections, listeners, or an address to tie to a host artefact.
- `patterns/yara` YARA over memory without turning a match into a verdict: You have case rules or a precise byte pattern to test against memory or a dumped process region.
- `processes/injection` Processes, and code that is not where it should be: You need what was running, or whether something was injected into it.
- `strings/discipline` A string in memory is not an action: Any claim built on text found in a memory image.
- `triage/no-framework` What a memory image gives you with no framework at all: The host has no Volatility and no MemProcFS, or you want an answer before you configure one.
- `triage/volatility` Volatility with the right symbols, offline: You are about to run Volatility on Windows or Linux memory, or a plugin reports an unsatisfied symbol requirement.
- `triage/what-you-have` What the container is, before anything else: The evidence includes a memory image, a crash dump or a hibernation file.
