---
id: memory/router
title: Memory notes by question
when: Pick one when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a memory note. Not for rules: each note holds its own.

First
`triage/what-you-have` classify the capture
`triage/container-details` crash dump, LiME, VMware vmem, offsets
`triage/paging-files` pagefile, swap, hibernation file
`acquire/images` how a capture was made, trusted
`acquire/avml-and-preserve` Linux live capture, order, what to keep

Reading the image
`triage/volatility` offline use, symbols, plugin choice
`triage/volatility-plugins` plugins by operating system
`triage/volatility-symbols` missing symbol table
`triage/volatility-catalogue` kickoff catalogue receipts
`triage/no-framework` no usable framework
`triage/carve-signatures` hives, logs, PE by signature
`triage/address-spaces` offset, physical or virtual address
`triage/coverage` what a search covered
`symbols/macos` macOS kernel and symbols

Processes and text
`processes/injection` what ran, injected code
`processes/preserve-regions` preserving a region before relying on it
`processes/kernel-integrity` module and driver views that differ
`strings/discipline` a string is an observation
`patterns/yara` rules or byte patterns over an image

Network and secrets
`network/state` connections, listeners, owners
`network/timestamps-dns` network times, DNS cache
`credentials/material` credentials, keys, tokens exposed
`credentials/key-schedules` AES key schedules

Time
`timeline/memory` which clock a memory time belongs to
