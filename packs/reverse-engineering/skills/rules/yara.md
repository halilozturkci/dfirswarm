---
id: rules/yara
title: YARA matches and what they mean
when: You search evidence with rules or must interpret a rule hit.
needs: [triage/quarantine]
tools: [pe_info]
requires_host: [yara]
---

Use when you scan evidence with rules or must say what a hit means. Not for naming a family, and not for shipping a rule: a hit is a lead.

1. Record the YARA version (`yara --version`), where the rules came from, hashes of the rule files and includes, namespaces, external variables, scan options and the target manifest. This pack ships no rules; a public set is third-party input with its own licence.
2. Keep the whole output and the diagnostics, and whether the scan completed. Failures and skipped files are part of the result.
3. `yara -s` prints each matched string with its offset and its bytes, and the bytes can be a credential: when the target can hold secrets run it as a job with `secret_output: true`, write the output to a file (`yara -s RULES SAMPLE > "$OUT/yara-s.txt"`), read the rule, identifier and offset columns, and cite those, not the bytes. A condition-only or module match has no string offset. A file offset is not a memory address.
4. A hit is a lead: public sets match packers and common libraries, so a match says little of purpose. A completed no-hit scan holds only for those rules, this target and this scope.
5. Use `pe_info` to confirm the format facts a structural condition leans on (section names, imports) before trusting it.

Only if you are writing or validating a rule, read `rules/authoring`.

Sensitive output: see item 3.

Shows: that these rules matched these bytes. Does not show: family, intent, or that unmatched files are clean. Record: version, rule hashes and source, command, target manifest, the complete output, completion status.
