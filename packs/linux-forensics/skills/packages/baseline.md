---
id: packages/baseline
title: Package comparison coverage and independent baseline
when: Stating what a package check covered and obtaining a baseline the machine did not write.
needs: []
card: package_verify {"root": "<extracted root>"} compares with the acquired database only: a file and its recorded hash can have been changed together, so it is triage, not distribution authenticity. Coverage follows package manifests: files no package owns (in /opt, /usr/local, homes, container layers) and Debian packages with no md5sums were never compared, so a clean report is not a clean machine. An independent baseline is an authorised offline copy of the exact package and architecture with its provenance, extracted without running its scripts. Without one, report only differences from the acquired database and say so. Does not show: anything about unowned files, or a clean machine.
tools: [package_verify]
requires_host: []
---

Use only if you report a package result beyond a list of differences, or need a trusted baseline. Not for running the verification (`packages/integrity`).

**What the comparison covers.** Coverage follows package manifests, not directory names: a package can own files outside `/usr` and files nobody owns can sit inside it. Identify separately the unowned files, files with no recorded checksum (`package_verify` counts the Debian packages with no md5sums file), diversions and alternatives, configuration changes, permissions, capabilities, ACLs and security labels. Anything in `/opt`, `/usr/local`, a home directory or a container layer that no package claims was never compared, so a clean report is not a clean machine. A package database written during the incident window is a stronger lead than one modified binary, and the database's and a binary's timestamps are leads whose meaning you check against package-manager logs, snapshots and deployment records.

**An independent baseline.** Run trusted tools against explicitly scoped evidence or a documented working copy, and confirm no path resolves into the analysis host. To compare against something the examined machine did not write, obtain an authorised offline copy of the exact package for the exact architecture, with its repository's or its signer's provenance, extract it without running its scripts, and compare payload and metadata. Record the package version, its source, the signature or repository verification result, the scope and the legitimate configuration exceptions. Where no trusted baseline is available, report only differences from the acquired database and say that is all this is.

Shows: what the check covered and what an independent copy says. Does not show: anything about files no package owns, or a clean machine from a clean report. Record: package versions and sources, signature results, scope, the exceptions, the unowned paths.

Sensitive output: none beyond paths.
