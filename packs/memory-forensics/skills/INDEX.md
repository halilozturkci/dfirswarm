# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

Router: `memory/router`

- `acquire/avml-and-preserve` AVML, capture order and what to preserve: AVML is proposed, sources are being ordered, or you list what an acquisition keeps.
- `acquire/images` Memory acquisition methods and their limits: The operator is choosing how to capture memory, or you must judge how a capture was made and trusted.
- `artifacts/reconstruction` From a signature hit to a record you can cite: A carved hit must be readied for a parser, or its integrity judged.
- `credentials/key-schedules` AES key schedules in a memory image: Searching an image for AES-128 or AES-256 key schedules with aeskeyfind.
- `credentials/material` Credential material in memory, and reporting it: Memory may expose credentials, keys or tokens; say whether any were exposed or taken.
- `memory/router` Memory notes by question: Pick one when none is listed, or you cannot choose.
- `network/state` Network objects and their owners in memory: You need connections, listeners or an address from memory, or one to tie to a host artefact.
- `network/timestamps-dns` Timestamps and DNS cache entries from memory: A network object carries a time, or you read a DNS cache entry from an image.
- `patterns/yara` YARA over an image or a dumped region: You have case rules or a precise byte pattern to test against an image or a dumped process region.
- `processes/injection` Process anomalies and candidate code modification: You need what was running, or are asked whether code was injected into a process.
- `processes/kernel-integrity` Comparing module, driver and kernel views: Kernel views disagree, or someone asks whether the kernel was tampered with.
- `processes/preserve-regions` Preserving a process region before you rely on it: You will argue from a process's memory, or read a MemProcFS tree with mem_fs.
- `strings/discipline` A string in memory is an observation: Any claim built on text found in a memory image.
- `symbols/linux` A Linux kernel's symbol table, matched exactly: A Linux capture needs an ISF, or someone offers a nearby kernel's table.
- `symbols/macos` macOS memory, the kernel and its symbols, with no support claim: The capture is from a Mac, or you are asked whether a macOS image can be read.
- `timeline/memory` Times in a memory capture and what each one dates: A time from a memory image goes on a timeline, or memory events are ordered against disk or logs.
- `triage/address-spaces` Which address space a number is in: A number from memory needs a place, or a raw region is compared with a rebuilt executable.
- `triage/carve-signatures` Carving structures from an image by signature: Using mem_carve or sig_carve to find hives, event logs, Prefetch or PE headers in a raw image.
- `triage/container-details` Locators, saved states and VMware memory: A crash dump, LiME file, hiberfil.sys or .vmem, or an offset to translate.
- `triage/coverage` What a memory search covered: Before writing "not in memory", or when a plugin or scan returned nothing, stopped early or gave a count.
- `triage/memprocfs` MemProcFS and its FUSE prerequisite: You will read an image as a MemProcFS file tree, or a mount failed or its readiness is in question.
- `triage/no-framework` A memory image no framework can read: The job image lacks a usable framework, symbols or dependencies; or you want an answer first.
- `triage/paging-files` The page file and the hibernation file: pagefile.sys, swap or hiberfil.sys is in the evidence next to, or instead of, a RAM capture.
- `triage/volatility` Volatility, offline, with the right symbols: Selecting Volatility plugins, or diagnosing an unsatisfied symbol or translation requirement.
- `triage/volatility-catalogue` The kickoff's plugin catalogue and its limits: The memory-windows recipe has run at the kickoff and you read its receipts.
- `triage/volatility-plugins` Volatility plugins by operating system: Choosing Windows, Linux or macOS plugins, or the option that writes a region to disk.
- `triage/volatility-symbols` Which symbol tables the image holds, and a missing one: The error names a PDB, GUID and age, or you say which kernels the image reads.
- `triage/what-you-have` Classify a memory capture first: A memory image, crash dump, saved VM state, paging or hibernation file is in the evidence.
