---
id: patterns/yara
title: YARA over memory without turning a match into a verdict
when: You have case rules or a precise byte pattern to test against memory or a dumped process region.
needs: [strings/discipline, triage/volatility]
tools: []
requires_host: [yara, vol]
---

Hash the rule file and keep the whole result. `-s` is essential: it records the
matching string and byte offset instead of returning only a rule name.

    sha256sum RULES.yar >work/<your id>/yara-rules.sha256
    yara -r -s RULES.yar IMAGE >work/<your id>/yara-image.txt \
      2>work/<your id>/yara-image.stderr

Whole-image YARA gives physical-file offsets, not process ownership. Use it to
find candidates, then attribute the bytes to a process and region. With matching
symbols, scan virtual regions directly:

    vol --offline -f IMAGE windows.vadyarascan.VadYaraScan --yara-file RULES.yar
    vol --offline -f IMAGE linux.vmayarascan.VmaYaraScan --yara-file RULES.yar

Confirm the plugin's current help before relying on an option name. Dump and
hash the matched region, record its process, virtual range and protection, and
corroborate it with the process path, modules, handles or disk artefacts.

A rule match is not a malware verdict. Name the rule source and version, check
whether the bytes are an antivirus signature, browser cache, log buffer or the
examiner's own acquisition tool, and report false-positive testing. Never paste
recovered credentials or other secrets into the board or report.
