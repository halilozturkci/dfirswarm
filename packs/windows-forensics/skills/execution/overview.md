---
id: execution/overview
title: Assessing evidence of program execution
when: You are about to cite an execution artefact or must choose among them.
needs: []
tools: []
requires_host: []
---

Use when you state that a program ran, or weigh execution sources against each other. Not for reading one source (the leaf each line below names) or for who was at the keyboard (`accounts/sessions`).

A method leaf: it names no tool; the readers are in the leaves it points to.

- **Name the claim first.** "The file was on the machine", "a process started", "it ran to completion", "it did something", "an account's session started it", "a person chose to" are six claims, and each source supports some of them: write the claim, the source and the step between.
- **What each source records.** Prefetch: a launch record for one executable path (`execution/prefetch`). UserAssist: shell-associated activity in one profile's hive; BAM and DAM: a per-SID last-execution value where the build keeps it (`execution/userassist`). Amcache: an inventory of applications and files, which is presence (`execution/amcache`). ShimCache: the compatibility cache's observation (`execution/shimcache`). SRUM: aggregated resource accounting (`execution/srum`). Process-creation events and Sysmon 1: only where configured before the event (`logs/events`). PowerShell 4104: script text that was logged (`logs/powershell`). A snapshot: an earlier state of any of these, not another mechanism (`filesystem/shadowcopies`).
- **Weigh by what a source can support**, not by a ranking or a count. A cleanly parsed process-creation record establishes that a process started, not that its action completed; one well-supported record can stand. Records that share an origin (one hive, a snapshot copy, parsers with one decoder) are one source; for a material conclusion find one that does not depend on it.
- **Their clocks differ.** A prefetcher launch, a shell launch, a per-SID last-run value and an inventory write are different events with their own epoch, zone and resolution: do not reconcile them to the second without saying what each is (`registry/clock`).
- **A renamed or moved executable.** Identify a binary by content hash where the bytes exist; correlate file references, rename history, cached paths and process records. A name or path in an artefact is a label it carries; without the bytes the identification is an inference. Say the mechanism (shell, service, task, another process) and the account.
- **An absence is qualified by its detection opportunity:** was the source enabled and configured, does its retained interval cover the time, was it acquired whole and parsed without `status: partial`, could it be altered or cleared. A missing Prefetch file is no execution negative until the build, the prefetcher's configuration, its service state and the collection are established; do not infer them from a Server edition or an SSD.

Shows: which claim each source can support and how to combine them. Does not show: who operated the machine, that a program finished or had an effect, that it was the only run, or that a program with no entry did not run. Record: the claim, each source with its clock and state (for an event source, its provider and configuration), what the sources share, the alternatives left open.
