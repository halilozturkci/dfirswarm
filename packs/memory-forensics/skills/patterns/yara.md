---
id: patterns/yara
title: YARA over files and reconstructed memory regions
when: You have case rules or a precise byte pattern to test against a memory image or a dumped process region.
needs: [strings/discipline, triage/volatility, credentials/material]
tools: []
requires_host: [yara, vol]
---

Run scans as jobs, with their outputs under `$OUT`, and keep the whole result and
stderr in the job. Record the rule file's source, version, licence and sha256 (a rule
file is not a secret), the external variables you set, and the scanner's version.

    yara -r -s RULES.yar IMAGE

`-s` prints the matching strings with their offsets, so a match line carries the
bytes: for a memory scan that prints matching bytes, surrounding context or a
dumped region, run the job with `secret_output: true` (**Sensitive output**) and
share rule names, counts and references to the sealed output, not the bytes. A rule
need not have a string to print; do not assume every match has a locator.

**Offsets.** A standalone scan reports offsets in the file it read. They are not
guest physical addresses or process virtual addresses, particularly for a framed or
compressed capture. Whole-image YARA finds candidates; it does not give process
ownership. To scan the virtual regions of processes, with matching symbols:

    vol --offline -f IMAGE windows.vadyarascan.VadYaraScan --yara-file RULES.yar
    vol --offline -f IMAGE linux.vmayarascan.VmaYaraScan --yara-file RULES.yar

In Volatility 3 2.28.2 (as of October 2026) both plugins and `--yara-file` exist, and
they need a YARA Python binding (`yara-python` 3.8 or newer, or `yara_x`) in the
same Python environment as `vol`. The `yara` executable does not provide it, and no
requirement of this pack installs one: check that the plugin is available in the job
image you have and what its import error says. If it is not, ask the operator for an
image correction, or use the standalone scanner and conclude from file offsets only.
Verify the options of the plugin you run (`vol windows.vadyarascan.VadYaraScan
--help`), since they change between versions.

**Coverage.** In 2.28.2 (as of October 2026) these scanners skip a region larger
than 1 GiB, read the regions they scan with padding (an unavailable page reads as
padding), and see only the processes and mappings their enumeration finds. Record
the processes and regions excluded, pages unavailable or padded, and failures; a
successful exit is not a complete scan. A rule that matched over one region need
not behave the same over a whole file.

**Region and attribution.** Keep a matched region as a sealed derivative with its
process, virtual range, protection, extraction method and unreadable or padded
ranges, and corroborate it with the process path, modules, handles or disk artefacts
(`processes/injection`).

**Does not show.** A rule match is not a malware verdict. Name the rule source and
version, check whether the bytes are an antivirus signature, a browser cache, a log
buffer or the examiner's own acquisition tool, and report the false-positive
testing you did.

**Sensitive output.** Match bytes, context and dumped regions can be credentials or
secret-bearing; see `credentials/material`. Never paste them into the board, the
ledger or the report.
